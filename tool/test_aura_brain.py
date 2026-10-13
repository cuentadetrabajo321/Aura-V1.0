"""Golden contract tests for Aura's serialized random-forest model."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import re
import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tool"))
sys.path.insert(0, str(ROOT / "tool/dataset"))

from dataset.build_dataset import is_allowlisted, normalize_domain  # noqa: E402
from train_max_aura_brain import (  # noqa: E402
    COMMON_DOMAINS,
    FEATURE_ORDER,
    MODEL_VERSION,
    build_model_metadata,
    calculate_bigram_repeat_ratio,
    calculate_conditional_entropy,
    calculate_trigram_repeat_ratio,
    detect_idn_homoglyphs,
    extract_enhanced_features,
    extract_maximum_features,
    is_probable_typosquatting,
    levenshtein_distance_to_top_domains,
    predict_serialized_model,
)

ASSET_MODEL_PATH = ROOT / "assets/model/aura_brain_model.json"
ASSET_DIGEST_PATH = ROOT / "assets/model/aura_brain_model.json.sha256"
MODEL_PATH = ASSET_MODEL_PATH


@pytest.fixture(scope="module")
def model():
    if not MODEL_PATH.is_file():
        pytest.fail("The versioned Aura model asset is missing")
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def is_threat(model_data: dict, domain: str) -> bool:
    if is_allowlisted(domain):
        return False
    return predict_serialized_model(model_data, domain) >= 0.5


def test_known_dga_is_classified_as_threat(model):
    assert is_threat(model, "x7z9q1wplmnb.xyz")


def test_known_legitimate_domain_is_classified_as_safe(model):
    assert not is_threat(model, "netflix.com")


def test_static_allowlist_domain_is_safe(model):
    assert is_allowlisted("google.com")
    assert is_allowlisted("api.google.com")
    assert not is_allowlisted("google.com.attacker.invalid")
    assert normalize_domain("google.com") == "google.com"
    assert not is_threat(model, "google.com")


def test_malformed_host_is_rejected_without_exception():
    assert normalize_domain("http://[::1") is None
    assert normalize_domain("127.0.0.1") is None
    assert normalize_domain("-invalid.example") is None


def test_model_schema_and_original_asset_digest(model):
    assert set(model) == {
        "model_name",
        "model_version",
        "model_type",
        "training_status",
        "training_samples",
        "csv_files",
        "training_config",
        "feature_order",
        "classes",
        "trees",
    }
    assert model["feature_order"] in (FEATURE_ORDER[:6], FEATURE_ORDER)
    assert len(model["trees"]) == 500
    assert model["classes"] == {"0": "safe", "1": "threat"}

    def validate_node(node: object, depth: int = 0) -> None:
        assert isinstance(node, dict)
        assert depth <= 10
        if node.get("type") == "leaf":
            assert node.get("value") in {0, 1}
            return
        assert node.get("type") == "split"
        assert node.get("feature_index") in range(len(model["feature_order"]))
        assert isinstance(node.get("threshold"), (int, float))
        assert round(float(node["threshold"]), 4) == node["threshold"]
        validate_node(node.get("left"), depth + 1)
        validate_node(node.get("right"), depth + 1)

    for tree in model["trees"]:
        assert set(tree) == {"root"}
        validate_node(tree["root"])

    expected_digest = ASSET_DIGEST_PATH.read_text(encoding="ascii").strip().split()[0]
    actual_digest = hashlib.sha256(ASSET_MODEL_PATH.read_bytes()).hexdigest()
    assert actual_digest == expected_digest


def test_offline_fixture_is_within_the_row_limit():
    fixture = ROOT / "tool/dataset/fixtures/sample.csv"
    with fixture.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert 0 < len(rows) <= 200
    assert set(rows[0]) == {"domain", "label", "source", "license", "retrieved_at"}


def test_enhanced_features_preserve_legacy_values_and_normalize_new_values():
    features = extract_enhanced_features("ABBB3.XYZ")
    maximum_features = extract_maximum_features("ABBB3.XYZ")

    assert len(features) == 18
    assert maximum_features == features
    assert features[:6] == [
        9.0,
        -(
            (3 / 9) * math.log2(3 / 9)
            + 6 * (1 / 9) * math.log2(1 / 9)
        ),
        1 / 9,
        1 / 7,
        6 / 7,
        1.0,
    ]
    assert all(0.0 <= value <= 1.0 for value in features[6:])
    assert features[11] == 0.0
    assert features[13] == 0.0
    assert features[15] == 2 / 7
    assert features[9] == 1 / 126
    assert features[10] == 3 / 63
    assert features[16] == 5 / 63


def test_python_and_dart_share_the_feature_order_and_common_domains():
    assert FEATURE_ORDER == [
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
    readme_source = (ROOT / "README.md").read_text(encoding="utf-8")
    readme_order = re.findall(
        r"^\|\s*\d+\s*\|\s*`([^`]+)`",
        readme_source,
        flags=re.MULTILINE,
    )
    assert readme_order == FEATURE_ORDER
    dart_source = (ROOT / "lib/inference/aura_common_domains.dart").read_text(
        encoding="utf-8"
    )
    dart_domains = re.findall(r"^  '([^']+)',$", dart_source, flags=re.MULTILINE)
    assert tuple(dart_domains) == COMMON_DOMAINS
    inference_source = (ROOT / "lib/inference/aura_ai_inference.dart").read_text(
        encoding="utf-8"
    )
    feature_order_match = re.search(
        r"enhancedFeatureOrder\s*=\s*<String>\[(.*?)\];",
        inference_source,
        flags=re.DOTALL,
    )
    assert feature_order_match is not None
    assert re.findall(r"'([^']+)'", feature_order_match.group(1)) == FEATURE_ORDER


def test_enhanced_features_combine_repeated_bigrams_and_trigrams():
    features = extract_enhanced_features("ababab.example")

    assert features[7] > 0.0
    assert features[7] <= 1.0
    assert features[8] > 0.0
    assert features[8] <= 1.0


def test_feature_helpers_and_model_metadata_follow_the_v4_contract():
    assert 0.0 < calculate_bigram_repeat_ratio("ABABAB.example") <= 1.0
    assert 0.0 < calculate_trigram_repeat_ratio("ABABAB.example") <= 1.0
    assert 0.0 <= calculate_conditional_entropy("ABABAB.example") <= 1.0

    metadata = build_model_metadata()
    assert set(metadata) == {
        "version",
        "feature_count",
        "feature_names",
        "trained_at",
    }
    assert metadata["version"] == MODEL_VERSION == "4.0.0"
    assert metadata["feature_count"] == 18
    assert metadata["feature_names"] == FEATURE_ORDER
    assert datetime.fromisoformat(metadata["trained_at"]).tzinfo is not None


def test_common_domain_has_zero_normalized_levenshtein_distance():
    assert levenshtein_distance_to_top_domains("google.com") == 0.0
    assert extract_enhanced_features("google.com")[6] == 0.0


def test_levenshtein_distance_scores_typosquatting_against_top_domains():
    assert levenshtein_distance_to_top_domains("goggle.com") == 0.1
    assert 0.0 <= levenshtein_distance_to_top_domains(
        "totally-unrelated-domain.example"
    ) <= 1.0
    assert is_probable_typosquatting("google.com") is False
    assert is_probable_typosquatting("goggle.com") is True
    assert is_probable_typosquatting("totally-unrelated-domain.example") is False
    assert levenshtein_distance_to_top_domains("") == 1.0


def test_enhanced_features_detect_idn_homographs_and_suspicious_keywords():
    features = extract_enhanced_features("раypal-free123.com")

    assert len(features) == 18
    assert features[11] == 1.0
    assert features[12] > 0.0
    assert features[13] == 1.0
    assert features[17] == 1.0


def test_enhanced_features_do_not_mistake_punycode_ascii_for_cyrillic():
    homograph = extract_enhanced_features("xn--80ak6aa92e.com")
    non_homograph_idn = extract_enhanced_features("xn--fsqu00a.com")

    assert homograph[11] == 0.0
    assert non_homograph_idn[11] == 0.0


def test_idn_homoglyph_indicator_is_capped_at_one():
    assert detect_idn_homoglyphs("apple.com") == 0.0
    assert detect_idn_homoglyphs("\u0430pple.com") == 0.5
    assert detect_idn_homoglyphs("\u0430\u0440ple.com") == 1.0
    assert detect_idn_homoglyphs("xn--pypal-4ve.com") == 0.0
    assert detect_idn_homoglyphs("\u0430\u0440\u0441\u0435\u0430.com") == 1.0
    assert detect_idn_homoglyphs("") == 0.0


def test_enhanced_features_return_zeros_for_empty_domains():
    assert extract_enhanced_features("") == [0.0] * 18