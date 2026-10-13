import argparse
import csv
import hashlib
import json
import math
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import numpy as np
from rapidfuzz.distance import Levenshtein
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import _tree

ROOT = Path(__file__).resolve().parents[1]
COMMON_DOMAINS_PATH = ROOT / "tool/domain_lists/tranco_top_1000_20261012.txt"
TRANCO_TOP_1000 = tuple(
    COMMON_DOMAINS_PATH.read_text(encoding="ascii").splitlines()
)
if len(TRANCO_TOP_1000) != 1000 or len(set(TRANCO_TOP_1000)) != 1000:
    raise ValueError(f"{COMMON_DOMAINS_PATH} must contain 1000 unique domains")
COMMON_DOMAINS = TRANCO_TOP_1000
MODEL_VERSION = "4.0.0"
FEATURE_ORDER = [
    "length",
    "shannon_entropy",
    "digit_ratio",
    "vowel_ratio",
    "consonant_sequence_ratio",
    "suspicious_tld",
    "min_normalized_levenshtein",
    "bigram_repeat_ratio",
    "trigram_repeat_ratio",
    "subdomain_depth",
    "tld_length_ratio",
    "idn_homograph_indicator",
    "non_ascii_ratio",
    "consecutive_digits_indicator",
    "conditional_entropy",
    "rare_character_ratio",
    "longest_label_length_ratio",
    "suspicious_keyword_indicator",
]
LEGACY_FEATURE_ORDER = FEATURE_ORDER[:6]
SUSPICIOUS_TLDS = {
    "cam",
    "cc",
    "click",
    "country",
    "date",
    "download",
    "fit",
    "gq",
    "info",
    "loan",
    "mov",
    "party",
    "review",
    "rest",
    "stream",
    "support",
    "tk",
    "top",
    "wang",
    "work",
    "xyz",
    "zip",
}
DATASET_DIR = ROOT / "data"
REPORTS_DIR = ROOT / "tool/reports"
MODEL_OUTPUT = REPORTS_DIR / "aura_brain_model.json"
METRICS_JSON = REPORTS_DIR / "metrics.json"
METRICS_MARKDOWN = REPORTS_DIR / "metrics.md"
MOBILE_MODEL_OUTPUT = REPORTS_DIR / "aura_brain_model_mobile.json"
MOBILE_METRICS_JSON = REPORTS_DIR / "metrics_mobile.json"
MOBILE_METRICS_MARKDOWN = REPORTS_DIR / "metrics_mobile.md"
MOBILE_SIZE_TRIALS = REPORTS_DIR / "mobile_size_trials.json"
MAX_MOBILE_MODEL_BYTES = 4 * 1024 * 1024
EXPECTED_CLASSES = {0, 1}
MIN_TEST_ROWS_PER_CLASS = 500


def build_model_metadata():
    return {
        "version": MODEL_VERSION,
        "feature_count": len(FEATURE_ORDER),
        "feature_names": FEATURE_ORDER,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }


def normalize_domain(value):
    return value.strip().lower().rstrip(".")
SEED_DATASET = [
    ("google.com", 0), ("github.com", 0), ("whatsapp.com", 0),
    ("amazon.com", 0), ("bancodevenezuela.com", 0), ("codemagic.io", 0),
    ("flutter.dev", 0), ("wikipedia.org", 0), ("microsoft.com", 0),
    ("netflix.com", 0), ("binance.com", 0), ("youtube.com", 0),
    ("stackoverflow.com", 0), ("apple.com", 0), ("linkedin.com", 0),
    ("zoom.us", 0), ("cloudflare.com", 0), ("android.com", 0),
    ("x7z9q1wplmnb.xyz", 1), ("aqwzsxedcrfv12.top", 1),
    ("free-crypto-rewards.click", 1), ("update-system-android.live", 1),
    ("cxj9812kmzsloq.cc", 1), ("malicious-payload-server.info", 1),
    ("shw28190axmzq.xyz", 1), ("get-root-bypass.top", 1),
    ("91kazmslqo1029az.biz", 1), ("free-cleaner-android.gq", 1),
    ("p0wz9172mlxozq.tk", 1), ("get-unlocked-premium.fit", 1),
]


def calculate_shannon_entropy(domain_string):
    if not domain_string:
        return 0.0
    frequencies = {}
    for character in domain_string.lower():
        frequencies[character] = frequencies.get(character, 0) + 1
    length = len(domain_string)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )


CYRILLIC_CONFUSABLES = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
}
SUSPICIOUS_KEYWORDS = {
    "free",
    "reward",
    "update",
    "system",
    "unlock",
    "premium",
    "crack",
}
_RARE_CHARACTERS = frozenset("qxzk")


@lru_cache(maxsize=65536)
def _minimum_top_domain_distance(host):
    closest_distance = math.inf
    for common_domain in TRANCO_TOP_1000:
        length_difference = abs(len(host) - len(common_domain))
        if length_difference >= closest_distance:
            continue
        distance = Levenshtein.distance(host, common_domain)
        if distance < closest_distance:
            closest_distance = distance
        if closest_distance == 0:
            break
    normalized_distance = min(closest_distance / max(len(host), 1), 1.0)
    return closest_distance, normalized_distance


def levenshtein_distance_to_top_domains(domain):
    """Return minimum edit distance / host length, capped to [0, 1]."""
    host = normalize_domain(domain)
    if not host:
        return 1.0
    _, normalized_distance = _minimum_top_domain_distance(host)
    return normalized_distance


def is_probable_typosquatting(domain):
    """Return whether the nearest popular domain is one or two edits away."""
    host = normalize_domain(domain)
    if not host:
        return False
    distance, _ = _minimum_top_domain_distance(host)
    return 0 < distance <= 2


def _minimum_normalized_levenshtein(host):
    return levenshtein_distance_to_top_domains(host)


def _repeated_ngram_ratio(value, size):
    grams = [
        value[index:index + size]
        for index in range(max(0, len(value) - size + 1))
    ]
    if not grams:
        return 0.0
    return (len(grams) - len(set(grams))) / len(grams)


def calculate_bigram_repeat_ratio(host):
    return _repeated_ngram_ratio(normalize_domain(host), 2)


def calculate_trigram_repeat_ratio(host):
    return _repeated_ngram_ratio(normalize_domain(host), 3)


def calculate_conditional_entropy(host):
    character_count = 0
    weighted_entropy = 0.0
    for label in normalize_domain(host).split("."):
        if not label:
            continue
        character_count += len(label)
        entropy = calculate_shannon_entropy(label)
        weighted_entropy += entropy * len(label)
    if not character_count:
        return 0.0
    return min((weighted_entropy / character_count) / math.log2(36), 1.0)


def detect_idn_homoglyphs(domain):
    """Return a capped indicator score for Cyrillic Latin-lookalikes."""
    candidate = normalize_domain(domain)
    if not candidate:
        return 0.0
    confusable_count = sum(character in CYRILLIC_CONFUSABLES for character in candidate)
    return min(confusable_count / 2.0, 1.0)


def extract_enhanced_features(domain):
    return extract_maximum_features(domain)


def extract_maximum_features(domain):
    host = normalize_domain(domain)
    length = len(host)
    if length == 0:
        return [0.0] * 18

    labels = host.split(".")
    tld = labels[-1]
    ascii_letters = [character for character in host if character.isascii() and character.isalpha()]
    digits = sum(character.isascii() and character.isdigit() for character in host)
    vowels = sum(character in "aeiou" for character in ascii_letters)
    consonant_sequence_characters = 0
    run_length = 0
    for character in host:
        if character.isascii() and character.isalpha() and character not in "aeiou":
            run_length += 1
        else:
            if run_length >= 3:
                consonant_sequence_characters += run_length
            run_length = 0
    if run_length >= 3:
        consonant_sequence_characters += run_length
    consecutive_digits = any(
        host[index].isascii()
        and host[index].isdigit()
        and host[index + 1].isascii()
        and host[index + 1].isdigit()
        for index in range(length - 1)
    )
    rare_characters = sum(character in _RARE_CHARACTERS for character in host)

    return [
        float(length),
        calculate_shannon_entropy(host),
        digits / length,
        vowels / len(ascii_letters) if ascii_letters else 0.0,
        (
            consonant_sequence_characters / len(ascii_letters)
            if ascii_letters
            else 0.0
        ),
        float(tld in SUSPICIOUS_TLDS),
        min(levenshtein_distance_to_top_domains(host), 1.0),
        calculate_bigram_repeat_ratio(host),
        calculate_trigram_repeat_ratio(host),
        min(host.count(".") / 126.0, 1.0),
        min(len(tld) / 63.0, 1.0),
        detect_idn_homoglyphs(host),
        sum(not character.isascii() for character in host) / length,
        float(consecutive_digits),
        calculate_conditional_entropy(host),
        rare_characters / len(ascii_letters) if ascii_letters else 0.0,
        min(max(map(len, labels), default=0) / 63.0, 1.0),
        float(any(keyword in host for keyword in SUSPICIOUS_KEYWORDS)),
    ]


def extract_legacy_features(domain):
    host = normalize_domain(domain)
    length = len(host)
    if not length:
        return [0.0] * len(LEGACY_FEATURE_ORDER)

    letters = [
        character
        for character in host
        if character.isascii() and character.isalpha()
    ]
    digits = sum(character.isascii() and character.isdigit() for character in host)
    vowels = sum(character in "aeiou" for character in letters)
    consonant_sequence_characters = 0
    run_length = 0
    for character in host:
        if character.isascii() and character.isalpha() and character not in "aeiou":
            run_length += 1
        else:
            if run_length >= 3:
                consonant_sequence_characters += run_length
            run_length = 0
    if run_length >= 3:
        consonant_sequence_characters += run_length
    tld = host.rsplit(".", 1)[-1]
    return [
        float(length),
        calculate_shannon_entropy(host),
        digits / length,
        vowels / len(letters) if letters else 0.0,
        consonant_sequence_characters / len(letters) if letters else 0.0,
        float(tld in SUSPICIOUS_TLDS),
    ]


def read_split(path):
    if not path.is_file():
        raise FileNotFoundError(f"Dataset split is missing: {path}")
    rows = []
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        expected_header = ["domain", "label", "source", "license", "retrieved_at"]
        if reader.fieldnames != expected_header:
            raise ValueError(f"Unexpected dataset CSV schema in {path}: {reader.fieldnames}")
        for row in reader:
            domain = row["domain"].strip().lower()
            if not domain or "." not in domain or row["label"] not in {"0", "1"}:
                raise ValueError(f"Invalid dataset row in {path}: {row}")
            rows.append((domain, int(row["label"])))
    return rows


def evaluate_metrics(labels, predictions):
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = matrix.ravel()
    specificity_denominator = true_negative + false_positive
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "false_positive_rate": (
            float(false_positive / specificity_denominator)
            if specificity_denominator
            else 0.0
        ),
        "confusion_matrix": {
            "labels": ["safe", "threat"],
            "rows_actual_columns_predicted": matrix.tolist(),
            "true_negative": int(true_negative),
            "false_positive": int(false_positive),
            "false_negative": int(false_negative),
            "true_positive": int(true_positive),
        },
    }


def evaluate_serialized_node(node, features, depth=0):
    if not isinstance(node, dict) or depth > 32:
        raise ValueError("Invalid or too-deep serialized model node")
    if node.get("type") == "leaf":
        value = node.get("value")
        if value not in (0, 1):
            raise ValueError("Serialized leaf value must be binary")
        return int(value)
    feature_index = node.get("feature_index")
    threshold = node.get("threshold")
    if (
        node.get("type") != "split"
        or not isinstance(feature_index, int)
        or feature_index < 0
        or feature_index >= len(features)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
    ):
        raise ValueError("Invalid serialized split node")
    branch = "left" if features[feature_index] <= threshold else "right"
    return evaluate_serialized_node(node.get(branch), features, depth + 1)


def predict_serialized_model(model, domain):
    trees = model.get("trees")
    if not isinstance(trees, list) or not trees:
        raise ValueError("Serialized model has no trees")
    model_feature_order = model.get("feature_order")
    if model_feature_order == LEGACY_FEATURE_ORDER:
        features = extract_legacy_features(domain)
    elif model_feature_order == FEATURE_ORDER:
        features = extract_enhanced_features(domain)
    else:
        raise ValueError("Serialized model uses an unsupported feature order")
    votes = sum(evaluate_serialized_node(tree.get("root"), features) for tree in trees)
    return votes / len(trees)


def write_metrics(metrics, json_path=METRICS_JSON, markdown_path=METRICS_MARKDOWN):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write(json_path, json.dumps(metrics, indent=2, sort_keys=True) + "\n")
    scores = metrics["test_metrics"]
    matrix = scores["confusion_matrix"]
    markdown = "\n".join(
        [
            "# Aura Random Forest Test Metrics",
            "",
            f"- Test rows: {metrics['test_rows']}",
            f"- Test class counts: safe={metrics['test_class_counts']['safe']}, threat={metrics['test_class_counts']['threat']}",
            f"- Accuracy: {scores['accuracy']:.6f}",
            f"- Precision: {scores['precision']:.6f}",
            f"- Recall: {scores['recall']:.6f}",
            f"- F1: {scores['f1']:.6f}",
            f"- False-positive rate: {scores['false_positive_rate']:.6f}",
            "",
            "## Confusion matrix",
            "",
            "| Actual \\ Predicted | Safe | Threat |",
            "|---|---:|---:|",
            f"| Safe | {matrix['true_negative']} | {matrix['false_positive']} |",
            f"| Threat | {matrix['false_negative']} | {matrix['true_positive']} |",
            "",
            "## Training run",
            "",
            f"- Samples: {metrics['training_rows']}",
            f"- Trees: {metrics['hyperparameters']['n_estimators']}",
            f"- Maximum depth: {metrics['hyperparameters']['max_depth']}",
            f"- Training time: {metrics['training_seconds']:.3f} s",
            f"- Dataset manifest SHA-256: {metrics['dataset_manifest_sha256']}",
            f"- Validation accuracy: {metrics['validation_metrics']['accuracy']:.6f}",
            "",
        ]
    )
    atomic_write(markdown_path, markdown)


def serialize_tree(estimator, threshold_decimals=None):
    tree = estimator.tree_

    def serialize_node(node_index):
        if tree.feature[node_index] == _tree.TREE_UNDEFINED:
            class_index = int(np.argmax(tree.value[node_index][0]))
            return {"type": "leaf", "value": int(estimator.classes_[class_index])}
        threshold = float(tree.threshold[node_index])
        if threshold_decimals is not None:
            threshold = round(threshold, threshold_decimals)
        return {
            "type": "split",
            "feature_index": int(tree.feature[node_index]),
            "threshold": threshold,
            "left": serialize_node(tree.children_left[node_index]),
            "right": serialize_node(tree.children_right[node_index]),
        }

    return {"root": serialize_node(0)}


def atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as temporary:
        temporary.write(content)
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, path)


def train_mobile_preset():
    train_rows = read_split(DATASET_DIR / "splits/train.csv")
    val_rows = read_split(DATASET_DIR / "splits/val.csv")
    test_rows = read_split(DATASET_DIR / "splits/test.csv")
    for split_name, rows in (("train", train_rows), ("val", val_rows), ("test", test_rows)):
        counts = {label: sum(row_label == label for _, row_label in rows) for label in EXPECTED_CLASSES}
        if any(counts[label] < MIN_TEST_ROWS_PER_CLASS for label in EXPECTED_CLASSES):
            raise SystemExit(
                f"{split_name} split must contain at least 500 rows per class "
                f"(safe={counts[0]}, threat={counts[1]}). Restore the stash or regenerate the real dataset."
            )

    training_features = np.asarray(
        [extract_maximum_features(domain) for domain, _ in train_rows]
    )
    training_labels = np.asarray([label for _, label in train_rows], dtype=np.int64)
    configurations = [
        (10, 8), (10, 32), (10, 128), (10, 512), (10, 2048),
        (9, 4096), (9, 8192), (9, 16384),
        (8, 32768), (8, 65536), (8, 131072),
    ]
    trials = []
    selected = None
    for max_depth, min_samples_leaf in configurations:
        print(
            f"Training Aura mobile forest: 500 trees, max_depth={max_depth}, "
            f"min_samples_leaf={min_samples_leaf}, train={len(train_rows)}, "
            f"val={len(val_rows)}, test={len(test_rows)}."
        )
        forest = RandomForestClassifier(
            n_estimators=500,
            max_depth=max_depth,
            min_samples_leaf=min_samples_leaf,
            n_jobs=-1,
            random_state=42,
            class_weight="balanced_subsample",
        )
        training_started = time.perf_counter()
        forest.fit(training_features, training_labels)
        training_seconds = time.perf_counter() - training_started
        model = {
            "model_name": "Aura Lexical Threat Forest",
            "model_version": MODEL_VERSION,
            "metadata": build_model_metadata(),
            "model_type": "random_forest",
            "training_status": "heuristic_seed_with_csv",
            "training_samples": len(train_rows),
            "csv_files": [str((DATASET_DIR / "splits/train.csv").relative_to(ROOT))],
            "training_config": {
                "n_estimators": 500,
                "max_depth": max_depth,
                "min_samples_leaf": min_samples_leaf,
                "n_jobs": -1,
                "random_state": 42,
            },
            "feature_order": FEATURE_ORDER,
            "classes": {"0": "safe", "1": "threat"},
            "trees": [
                serialize_tree(estimator, threshold_decimals=4)
                for estimator in forest.estimators_
            ],
        }
        if len(model["trees"]) != 500:
            raise RuntimeError("El preset móvil debe conservar exactamente 500 árboles.")
        model_bytes = (
            json.dumps(model, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        trees = model["trees"]

        def node_stats(node):
            if node["type"] == "leaf":
                return 1, 0
            left_leaves, left_depth = node_stats(node["left"])
            right_leaves, right_depth = node_stats(node["right"])
            return left_leaves + right_leaves, 1 + max(left_depth, right_depth)

        tree_stats = [node_stats(tree["root"]) for tree in trees]
        leaves = sum(item[0] for item in tree_stats)
        observed_depth = max(item[1] for item in tree_stats)
        trial = {
            "trees": len(trees),
            "max_depth": max_depth,
            "observed_depth": observed_depth,
            "min_samples_leaf": min_samples_leaf,
            "leaves": leaves,
            "bytes": len(model_bytes),
        }
        trials.append(trial)
        print(
            f"MOBILE_TRIAL trees={len(trees)} max_depth={max_depth} "
            f"observed_depth={observed_depth} min_samples_leaf={min_samples_leaf} "
            f"leaves={leaves} bytes={len(model_bytes)}"
        )
        if len(model_bytes) < MAX_MOBILE_MODEL_BYTES:
            selected = (model, model_bytes, trial, training_seconds)
            break
        del forest, model, model_bytes

    atomic_write(MOBILE_SIZE_TRIALS, json.dumps(trials, indent=2) + "\n")
    if selected is None:
        raise SystemExit(
            "Mobile preset still exceeds 4194304 bytes at max_depth=8 with aggressive pruning; "
            f"see {MOBILE_SIZE_TRIALS.relative_to(ROOT)}. No base asset was changed."
        )

    model, model_bytes, trial, training_seconds = selected
    atomic_write(MOBILE_MODEL_OUTPUT, model_bytes.decode("utf-8"))
    evaluation_domains = [domain for domain, _ in test_rows]
    evaluation_labels = [label for _, label in test_rows]
    validation_domains = [domain for domain, _ in val_rows]
    validation_labels = [label for _, label in val_rows]
    test_predictions = [
        int(predict_serialized_model(model, domain) >= 0.5)
        for domain in evaluation_domains
    ]
    validation_predictions = [
        int(predict_serialized_model(model, domain) >= 0.5)
        for domain in validation_domains
    ]
    manifest_path = DATASET_DIR / "dataset_manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Dataset manifest is missing: {manifest_path}")
    metrics = {
        "metrics_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "evaluation_mode": "stratified-test-split-serialized-mobile-model",
        "training_rows": len(train_rows),
        "validation_rows": len(val_rows),
        "test_rows": len(test_rows),
        "test_class_counts": {
            "safe": sum(label == 0 for label in evaluation_labels),
            "threat": sum(label == 1 for label in evaluation_labels),
        },
        "tree_count": 500,
        "maximum_observed_depth": trial["observed_depth"],
        "leaf_count": trial["leaves"],
        "model_bytes": len(model_bytes),
        "size_trials": trials,
        "hyperparameters": {
            "n_estimators": 500,
            "max_depth": trial["max_depth"],
            "min_samples_leaf": trial["min_samples_leaf"],
            "n_jobs": -1,
            "random_state": 42,
            "class_weight": "balanced_subsample",
            "feature_order": FEATURE_ORDER,
            "threshold_precision_decimals": 4,
        },
        "training_seconds": training_seconds,
        "dataset_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "metrics_model_file": str(MOBILE_MODEL_OUTPUT.relative_to(ROOT)),
        "validation_metrics": evaluate_metrics(validation_labels, validation_predictions),
        "test_metrics": evaluate_metrics(evaluation_labels, test_predictions),
    }
    write_metrics(metrics, MOBILE_METRICS_JSON, MOBILE_METRICS_MARKDOWN)
    print(f"MODEL_PRESET={MOBILE_MODEL_OUTPUT.relative_to(ROOT)}")
    print(f"MODEL_BYTES={len(model_bytes)}")
    print(f"METRICS_JSON={MOBILE_METRICS_JSON.relative_to(ROOT)}")
    print(f"METRICS_MARKDOWN={MOBILE_METRICS_MARKDOWN.relative_to(ROOT)}")
    print("Mobile candidate and metrics generated; tracked assets/model files were not modified.")


def main():
    parser = argparse.ArgumentParser(description="Entrena el bosque local de Aura.")
    parser.add_argument(
        "--preset",
        choices=("full", "mobile"),
        default="full",
        help="Select the full 500-tree candidate or the size-constrained 500-tree mobile preset.",
    )
    parser.add_argument(
        "--allow-seed-only",
        action="store_true",
        help="Allow the documented 30-domain seed fallback when a qualified test split is unavailable.",
    )
    args = parser.parse_args()
    if args.preset == "mobile":
        if args.allow_seed_only:
            parser.error("--preset mobile never permits --allow-seed-only")
        train_mobile_preset()
        return
    try:
        train_rows = read_split(DATASET_DIR / "splits/train.csv")
        val_rows = read_split(DATASET_DIR / "splits/val.csv")
        test_rows = read_split(DATASET_DIR / "splits/test.csv")
    except FileNotFoundError as error:
        if not args.allow_seed_only:
            raise SystemExit(
                f"{error}. Pass --allow-seed-only only for the documented seed fallback."
            ) from error
        train_rows, val_rows, test_rows = [], [], []
    test_counts = {label: sum(row_label == label for _, row_label in test_rows) for label in EXPECTED_CLASSES}
    inadequate_test = any(test_counts[label] < MIN_TEST_ROWS_PER_CLASS for label in EXPECTED_CLASSES)
    if inadequate_test and not args.allow_seed_only:
        raise SystemExit(
            "Test split must contain at least 500 rows per class "
            f"(safe={test_counts[0]}, threat={test_counts[1]}). "
            "Rebuild from more licensed real data or pass --allow-seed-only for the documented seed fallback."
        )

    using_seed_fallback = inadequate_test
    if using_seed_fallback:
        samples = list(SEED_DATASET)
        training_rows = samples
        evaluation_rows = samples
        validation_rows = samples
        print("WARNING: using the documented 30-domain seed-only fallback; metrics are not a real holdout evaluation.")
    else:
        training_rows = train_rows
        evaluation_rows = test_rows
        validation_rows = val_rows

    features = np.asarray([extract_maximum_features(domain) for domain, _ in training_rows])
    labels = np.asarray([label for _, label in training_rows], dtype=np.int64)
    evaluation_domains = [domain for domain, _ in evaluation_rows]
    evaluation_labels = [label for _, label in evaluation_rows]
    validation_domains = [domain for domain, _ in validation_rows]
    validation_labels = [label for _, label in validation_rows]
    print(
        f"Training Aura forest: 500 trees, max_depth=12, "
        f"train={len(training_rows)}, val={len(val_rows)}, test={len(test_rows)}."
    )
    forest = RandomForestClassifier(
        n_estimators=500,
        max_depth=12,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced_subsample",
    )
    training_started = time.perf_counter()
    forest.fit(features, labels)
    training_seconds = time.perf_counter() - training_started

    evaluation_features = np.asarray(
        [extract_maximum_features(domain) for domain in evaluation_domains]
    )
    predictions = forest.predict(evaluation_features).astype(int).tolist()
    test_metrics = evaluate_metrics(evaluation_labels, predictions)
    validation_features = np.asarray(
        [extract_maximum_features(domain) for domain in validation_domains]
    )
    validation_predictions = forest.predict(validation_features).astype(int).tolist()
    validation_metrics = evaluate_metrics(validation_labels, validation_predictions)

    model = {
        "model_name": "Aura Lexical Threat Forest",
        "model_version": MODEL_VERSION,
        "metadata": build_model_metadata(),
        "model_type": "random_forest",
        "training_status": "heuristic_seed" if using_seed_fallback else "heuristic_seed_with_csv",
        "training_samples": len(training_rows),
        "csv_files": [str((DATASET_DIR / "splits/train.csv").relative_to(ROOT))],
        "training_config": {
            "n_estimators": 500,
            "max_depth": 12,
            "n_jobs": -1,
            "random_state": 42,
        },
        "feature_order": FEATURE_ORDER,
        "classes": {"0": "safe", "1": "threat"},
        "trees": [
            serialize_tree(estimator, threshold_decimals=4)
            for estimator in forest.estimators_
        ],
    }
    if len(model["trees"]) != 500:
        raise RuntimeError("El bosque serializado no contiene exactamente 500 árboles.")

    json_bytes = (json.dumps(model, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    atomic_write(MODEL_OUTPUT, json_bytes.decode("utf-8"))
    manifest_path = DATASET_DIR / "dataset_manifest.json"
    if not manifest_path.is_file() and not using_seed_fallback:
        raise FileNotFoundError(f"Dataset manifest is missing: {manifest_path}")
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest() if manifest_path.is_file() else "seed-only-no-manifest"
    metrics = {
        "metrics_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "evaluation_mode": "seed-only-not-a-holdout" if using_seed_fallback else "stratified-test-split",
        "training_rows": len(training_rows),
        "validation_rows": len(validation_rows),
        "test_rows": len(evaluation_rows),
        "test_class_counts": {
            "safe": sum(label == 0 for label in evaluation_labels),
            "threat": sum(label == 1 for label in evaluation_labels),
        },
        "hyperparameters": {
            "n_estimators": 500,
            "max_depth": 12,
            "n_jobs": -1,
            "random_state": 42,
            "class_weight": "balanced_subsample",
            "feature_order": FEATURE_ORDER,
        },
        "training_seconds": training_seconds,
        "dataset_manifest_sha256": manifest_digest,
        "metrics_model_file": str(MODEL_OUTPUT.relative_to(ROOT)),
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
    }
    write_metrics(metrics)
    print(f"MODEL_CANDIDATE={MODEL_OUTPUT.relative_to(ROOT)}")
    print(f"METRICS_JSON={METRICS_JSON.relative_to(ROOT)}")
    print(f"METRICS_MARKDOWN={METRICS_MARKDOWN.relative_to(ROOT)}")
    print("Model candidate and metrics generated; tracked assets/model files were not modified.")


if __name__ == "__main__":
    main()
