import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:aura_mobile_defens/inference/aura_ai_inference.dart';
import 'package:aura_mobile_defens/inference/aura_common_domains.dart';
import 'package:aura_mobile_defens/models/aura_ai_brain.dart' as model_inference;
import 'package:test/test.dart';

void main() {
  final mockModelJson = <String, dynamic>{
    'trees': <Map<String, Object>>[
      <String, Object>{
        'root': <String, Object>{
          'type': 'split',
          'feature_index': 1,
          'threshold': 3.5,
          'left': <String, Object>{'type': 'leaf', 'value': 0},
          'right': <String, Object>{'type': 'leaf', 'value': 1},
        },
      },
      <String, Object>{
        'root': <String, Object>{
          'type': 'split',
          'feature_index': 5,
          'threshold': 0.5,
          'left': <String, Object>{'type': 'leaf', 'value': 0},
          'right': <String, Object>{'type': 'leaf', 'value': 1},
        },
      },
    ],
  };

  group('Active model inference input validation', () {
    test('ignores invalid DNS labels, ports, and URL credentials', () async {
      final results = await model_inference.AuraAIInference.analyzeThreatPayload(
        rawData: jsonEncode(<String, Object>{
          'hosts': <Map<String, String>>[
            <String, String>{'host': 'bad.-label.example'},
            <String, String>{'host': 'bad..example'},
            <String, String>{'host': 'good.example:443'},
            <String, String>{'host': 'https://user@good.example/path'},
          ],
        }),
        modelStructure: <String, dynamic>{},
        suspiciousTlds: <String>[],
      );

      expect(results, isEmpty);
    });

    test('normalizes a valid HTTPS URL to its DNS host', () async {
      final results = await model_inference.AuraAIInference.analyzeThreatPayload(
        rawData: '{"host":"https://good.example/path"}',
        modelStructure: _safeForest(),
        suspiciousTlds: <String>[],
      );

      expect(results.single.host, 'good.example');
    });

    test('accepts IPv6 literals as addresses but does not score them as domains',
        () async {
      final results = await model_inference.AuraAIInference.analyzeThreatPayload(
        rawData: '{"hosts":[{"host":"https://[2001:0db8::1]/"}]}',
        modelStructure: _safeForest(),
        suspiciousTlds: <String>[],
      );

      expect(results, isEmpty);
    });

  });

  group('AuraAIInference feature calculations', () {
    test('preserves the six legacy feature values and exposes the full vector', () {
      final features = AuraAIInference.extractFeatures('ABBB3.XYZ');
      final enhanced =
          AuraAIInference.extractEnhancedFeatures('ABBB3.XYZ');
      const length = 9;
      final expectedEntropy =
          -((3 / length) * (math.log(3 / length) / math.ln2) +
              6 * (1 / length) * (math.log(1 / length) / math.ln2));

      expect(enhanced, hasLength(18));
      expect(AuraAIInference.enhancedFeatureOrder, <String>[
        'length',
        'shannon_entropy',
        'digit_ratio',
        'vowel_ratio',
        'consonant_sequence_ratio',
        'suspicious_tld',
        'min_normalized_levenshtein',
        'bigram_repeat_ratio',
        'trigram_repeat_ratio',
        'subdomain_depth',
        'tld_length_ratio',
        'idn_homograph_indicator',
        'non_ascii_ratio',
        'consecutive_digits_indicator',
        'conditional_entropy',
        'rare_character_ratio',
        'longest_label_length_ratio',
        'suspicious_keyword_indicator',
      ]);
      expect(features['length'], 9);
      expect(features['shannon_entropy'], closeTo(expectedEntropy, 1e-12));
      expect(features['digit_ratio'], closeTo(1 / 9, 1e-12));
      expect(features['vowel_ratio'], closeTo(1 / 7, 1e-12));
      expect(features['consonant_sequence_ratio'], closeTo(6 / 7, 1e-12));
      expect(features['suspicious_tld'], 1);
      expect(enhanced.take(6).toList(), <double>[
        9,
        expectedEntropy,
        1 / 9,
        1 / 7,
        6 / 7,
        1,
      ]);
      expect(enhanced.skip(6).every((value) => value >= 0 && value <= 1), isTrue);
      expect(enhanced[13], 0);
      expect(enhanced[15], closeTo(2 / 7, 1e-12));
    });

    test('detects IDN homographs and suspicious keyword patterns', () {
      final features =
          AuraAIInference.extractEnhancedFeatures('раypal-free123.com');

      expect(features, hasLength(18));
      expect(features[11], 1);
      expect(features[12], greaterThan(0));
      expect(features[13], 1);
      expect(features[17], 1);
    });

    test('decodes punycode without flagging every IDN', () {
      expect(
        AuraAIInference.extractEnhancedFeatures('xn--80ak6aa92e.com')[11],
        1,
      );
      expect(
        AuraAIInference.extractEnhancedFeatures('xn--fsqu00a.com')[11],
        0,
      );
    });

    test('scores mapped Cyrillic homoglyphs and flags two or more', () {
      expect(AuraAIInference.detectIdnHomoglyphs('apple.com'), 0);
      expect(AuraAIInference.detectIdnHomoglyphs('\u0430pple.com'), 0.5);
      expect(
        AuraAIInference.detectIdnHomoglyphs('\u0430\u0440ple.com'),
        1,
      );
      expect(
        AuraAIInference.detectIdnHomoglyphs('xn--pypal-4ve.com'),
        0.5,
      );
      expect(
        AuraAIInference.detectIdnHomoglyphs('xn--80ak6aa92e.com'),
        1,
      );
      expect(AuraAIInference.detectIdnHomoglyphs(''), 0);
    });

    test('uses the pinned 1000-domain corpus shared with Python training', () {
      final source = File(
        'tool/domain_lists/tranco_top_1000_20261012.txt',
      ).readAsLinesSync();

      expect(auraCommonDomains, hasLength(1000));
      expect(auraCommonDomains, source);
      expect(
        AuraAIInference.extractEnhancedFeatures('google.com')[6],
        0,
      );
      expect(
        AuraAIInference.levenshteinDistanceToTopDomains('goggle.com'),
        closeTo(0.1, 1e-12),
      );
      expect(
        AuraAIInference.levenshteinDistanceToTopDomains(
          'totally-unrelated-domain.example',
        ),
        inInclusiveRange(0, 1),
      );
      expect(AuraAIInference.isProbableTyposquatting('google.com'), isFalse);
      expect(AuraAIInference.isProbableTyposquatting('goggle.com'), isTrue);
      expect(
        AuraAIInference.isProbableTyposquatting(
          'totally-unrelated-domain.example',
        ),
        isFalse,
      );
      expect(AuraAIInference.levenshteinDistanceToTopDomains(''), 1);
    });

    test('does not treat a suspicious-looking substring as the TLD', () {
      final features = AuraAIInference.extractFeatures('notxyz.example');

      expect(features['suspicious_tld'], 0);
    });
  });

  group('Operational robustness', () {
    test('allows clean official domains without allowing suffix bypasses', () {
      expect(
        AuraAIInference.analyzeHostSecure('google.com', mockModelJson),
        isTrue,
      );
      expect(
        AuraAIInference.analyzeHostSecure('whatsapp.net', mockModelJson),
        isTrue,
      );
      expect(
        AuraAIInference.analyzeHostSecure(
          'google.com.maliciousdomain.xyz',
          mockModelJson,
        ),
        isFalse,
      );
    });

    test('classifies high-entropy hosts with suspicious TLDs as threats', () {
      expect(
        AuraAIInference.analyzeHostSecure(
          'x921llmzaqp0182ncnw.xyz',
          mockModelJson,
        ),
        isFalse,
      );
    });

    test('rejects empty and malformed hosts', () {
      expect(AuraAIInference.analyzeHostSecure('', mockModelJson), isFalse);
      expect(
        AuraAIInference.analyzeHostSecure('://google.com', mockModelJson),
        isFalse,
      );
    });

    test('rejects user-info tricks whose actual host is not allowlisted', () {
      expect(
        AuraAIInference.analyzeHostSecure(
          'https://google.com@attacker.xyz',
          mockModelJson,
        ),
        isFalse,
      );
    });
  });

  group('Allowlist boundary and ensemble decisions', () {
    test('checks all official suffixes and their subdomains', () {
      final threateningModel = _forest(<int>[1, 1, 1]);

      for (final suffix in AuraAIInference.auraStaticWhitelist) {
        expect(
          AuraAIInference.analyzeHostSecure(suffix, threateningModel),
          isTrue,
          reason: 'official suffix: $suffix',
        );
        expect(
          AuraAIInference.analyzeHostSecure('cdn.$suffix', threateningModel),
          isTrue,
          reason: 'official subdomain: cdn.$suffix',
        );
      }
      expect(
        AuraAIInference.analyzeHostSecure(
          'google.com.attacker.xyz',
          threateningModel,
        ),
        isFalse,
      );
    });

    test('uses a strict majority of tree votes', () {
      final tiedModel = _forest(<int>[1, 1, 0, 0]);
      final safeMajorityModel = _forest(<int>[1, 0, 0]);

      expect(
        AuraAIInference.analyzeHostSecure('ordinary.example', tiedModel),
        isFalse,
      );
      expect(
        AuraAIInference.analyzeHostSecure(
            'ordinary.example', safeMajorityModel),
        isTrue,
      );
    });

    test('rejects unverified hosts when no model is loaded', () {
      expect(
          AuraAIInference.analyzeHostSecure('ordinary.example', {}), isFalse);
    });
  });

  group('Binary AURA forest', () {
    test('walks nested nodes and applies little-endian thresholds', () {
      final model = _binaryForest(<_BinaryTree>[
        _BinaryTree(
          rootIndex: 0,
          nodes: <_BinaryNode>[
            _BinaryNode.split(
              featureIndex: 5,
              threshold: 0.5,
              leftChild: 1,
              rightChild: 2,
            ),
            const _BinaryNode.leaf(0),
            _BinaryNode.split(
              featureIndex: 0,
              threshold: 10.0,
              leftChild: 3,
              rightChild: 4,
            ),
            const _BinaryNode.leaf(0),
            const _BinaryNode.leaf(1),
          ],
        ),
      ]);

      expect(
        AuraAIInference.evaluateHostFromBinary('normal.example', model),
        isTrue,
      );
      expect(
        AuraAIInference.evaluateHostFromBinary('abcdefghijkl.xyz', model),
        isFalse,
      );
    });

    test('distinguishes little-endian float thresholds from byte-swapped data',
        () {
      final model = _binaryForest(<_BinaryTree>[
        _BinaryTree(
          rootIndex: 0,
          nodes: <_BinaryNode>[
            _BinaryNode.split(
              featureIndex: 2,
              threshold: 0.5,
              leftChild: 1,
              rightChild: 2,
            ),
            const _BinaryNode.leaf(0),
            const _BinaryNode.leaf(1),
          ],
        ),
      ]);

      expect(
        AuraAIInference.evaluateHostFromBinary('abc1.example', model),
        isTrue,
      );
    });

    test('loads and evaluates a .bin file', () async {
      final directory = await Directory.systemTemp.createTemp('aura-model-');
      try {
        final modelFile = File('${directory.path}/forest.bin');
        await modelFile.writeAsBytes(
          _binaryForest(<_BinaryTree>[_leafTree(0)]),
        );

        expect(
          await AuraAIInference.evaluateHostFromBinaryFile(
            'normal.example',
            modelFile,
          ),
          isTrue,
        );
      } finally {
        await directory.delete(recursive: true);
      }
    });

    test('uses threat votes and classifies a tie as threat', () {
      final tiedForest = _binaryForest(<_BinaryTree>[
        _leafTree(1),
        _leafTree(0),
      ]);
      final safeMajority = _binaryForest(<_BinaryTree>[
        _leafTree(1),
        _leafTree(0),
        _leafTree(0),
      ]);

      expect(
        AuraAIInference.evaluateHostFromBinary('normal.example', tiedForest),
        isFalse,
      );
      expect(
        AuraAIInference.evaluateHostFromBinary('normal.example', safeMajority),
        isTrue,
      );
    });

    test('accepts a threat leaf as the root of a tree', () {
      final model = _binaryForest(<_BinaryTree>[_leafTree(1)]);

      expect(
        AuraAIInference.evaluateHostFromBinary('normal.example', model),
        isFalse,
      );
    });

    test('rejects invalid magic, truncated records, and trailing bytes', () {
      final validModel = _binaryForest(<_BinaryTree>[_leafTree(0)]);
      final invalidMagic = Uint8List.fromList(validModel)..[0] = 0;
      final truncated = Uint8List.sublistView(
        validModel,
        0,
        validModel.length - 1,
      );
      final trailingByte = Uint8List(validModel.length + 1)
        ..setRange(0, validModel.length, validModel);

      expect(
        () => AuraAIInference.evaluateHostFromBinary(
          'normal.example',
          invalidMagic,
        ),
        throwsFormatException,
      );
      expect(
        () =>
            AuraAIInference.evaluateHostFromBinary('normal.example', truncated),
        throwsFormatException,
      );
      expect(
        () => AuraAIInference.evaluateHostFromBinary(
          'normal.example',
          trailingByte,
        ),
        throwsFormatException,
      );
    });

    test('rejects cyclic trees and invalid feature indexes', () {
      final cyclicForest = _binaryForest(<_BinaryTree>[
        _BinaryTree(
          rootIndex: 0,
          nodes: <_BinaryNode>[
            _BinaryNode.split(
              featureIndex: 5,
              threshold: 0.5,
              leftChild: 0,
              rightChild: 1,
            ),
            const _BinaryNode.leaf(0),
          ],
        ),
      ]);
      final invalidFeatureForest = _binaryForest(<_BinaryTree>[
        _BinaryTree(
          rootIndex: 0,
          nodes: <_BinaryNode>[
            _BinaryNode.split(
              featureIndex: 6,
              threshold: 0.5,
              leftChild: 1,
              rightChild: 1,
            ),
            const _BinaryNode.leaf(0),
          ],
        ),
      ]);

      expect(
        () => AuraAIInference.evaluateHostFromBinary(
          'normal.example',
          cyclicForest,
        ),
        throwsFormatException,
      );
      expect(
        () => AuraAIInference.evaluateHostFromBinary(
          'normal.example',
          invalidFeatureForest,
        ),
        throwsFormatException,
      );
    });
  });
}

Map<String, dynamic> _safeForest() => <String, dynamic>{
      'trees': List<Map<String, Object>>.generate(
        500,
        (_) => <String, Object>{
          'root': <String, Object>{'type': 'leaf', 'value': 0},
        },
      ),
    };

Map<String, dynamic> _forest(List<int> leafVotes) => <String, dynamic>{
      'trees': <Map<String, Object>>[
        for (final vote in leafVotes)
          <String, Object>{
            'root': <String, Object>{'type': 'leaf', 'value': vote},
          },
      ],
    };

Uint8List _binaryForest(List<_BinaryTree> trees) {
  final byteLength = 8 +
      trees.fold<int>(
        0,
        (total, tree) => total + 8 + tree.nodes.length * 20,
      );
  final bytes = Uint8List(byteLength);
  final data = ByteData.sublistView(bytes);
  data
    ..setUint8(0, 0x41)
    ..setUint8(1, 0x55)
    ..setUint8(2, 0x52)
    ..setUint8(3, 0x41)
    ..setUint32(4, trees.length, Endian.little);

  var offset = 8;
  for (final tree in trees) {
    data
      ..setUint32(offset, tree.rootIndex, Endian.little)
      ..setUint32(offset + 4, tree.nodes.length, Endian.little);
    offset += 8;
    for (final node in tree.nodes) {
      data
        ..setInt32(offset, node.type, Endian.little)
        ..setInt32(offset + 4, node.featureIndex, Endian.little)
        ..setInt32(offset + 8, node.leftChild, Endian.little)
        ..setInt32(offset + 12, node.rightChild, Endian.little)
        ..setFloat32(offset + 16, node.threshold, Endian.little);
      offset += 20;
    }
  }
  return bytes;
}

_BinaryTree _leafTree(int classification) => _BinaryTree(
      rootIndex: 0,
      nodes: <_BinaryNode>[_BinaryNode.leaf(classification)],
    );

class _BinaryTree {
  const _BinaryTree({required this.rootIndex, required this.nodes});

  final int rootIndex;
  final List<_BinaryNode> nodes;
}

class _BinaryNode {
  const _BinaryNode.leaf(int classification)
      : type = 1,
        featureIndex = classification,
        leftChild = -1,
        rightChild = -1,
        threshold = 0;

  const _BinaryNode.split({
    required this.featureIndex,
    required this.threshold,
    required this.leftChild,
    required this.rightChild,
  }) : type = 2;

  final int type;
  final int featureIndex;
  final int leftChild;
  final int rightChild;
  final double threshold;
}
