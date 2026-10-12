import 'dart:convert';
import 'dart:isolate';
import 'dart:math' as math;
import 'dart:io';

class AuraInferenceResult {
  const AuraInferenceResult({
    required this.host,
    required this.threatScore,
    required this.isThreat,
    required this.computedFeatures,
  });

  final String host;
  final double threatScore;
  final bool isThreat;
  final Map<String, double> computedFeatures;
}

abstract final class AuraAIInference {
  static const int _expectedTreeCount = 500;
  static const int _maximumTreeDepth = 32;
  static final RegExp _hostnamePattern = RegExp(
    r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
    r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$',
  );
  static final RegExp _domainPattern = RegExp(
    r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]{1,63})+',
  );
  static const Set<String> _domainFields = <String>{
    'domain',
    'host',
    'hostname',
    'qname',
    'requested_domain',
  };

  static Future<List<AuraInferenceResult>> analyzeThreatPayload({
    required String rawData,
    required Map<String, dynamic> modelStructure,
    required List<String> suspiciousTlds,
  }) async {
    final serializedResult = await Isolate.run<Map<String, Object?>>(
      () => _processInBackground(
        rawData,
        modelStructure,
        suspiciousTlds,
      ),
    );
    final rawResults = serializedResult['results'];
    if (rawResults is! List) {
      throw const FormatException('El resultado del isolate no es válido.');
    }
    return rawResults.map((rawResult) {
      if (rawResult is! Map) {
        throw const FormatException('Resultado de inferencia inválido.');
      }
      final result = Map<String, Object?>.from(rawResult);
      final host = result['host'];
      final score = result['threat_score'];
      final threat = result['is_threat'];
      final rawFeatures = result['features'];
      if (host is! String ||
          score is! num ||
          threat is! bool ||
          rawFeatures is! Map) {
        throw const FormatException('Campos de inferencia incompletos.');
      }
      final features = <String, double>{};
      for (final entry in rawFeatures.entries) {
        if (entry.key is! String || entry.value is! num) {
          throw const FormatException(
            'Las características devueltas por el isolate no son válidas.',
          );
        }
        features[entry.key as String] = (entry.value as num).toDouble();
      }
      return AuraInferenceResult(
        host: host,
        threatScore: score.toDouble(),
        isThreat: threat,
        computedFeatures: Map<String, double>.unmodifiable(features),
      );
    }).toList(growable: false);
  }

  static Map<String, Object?> _processInBackground(
    String rawData,
    Map<String, dynamic> modelStructure,
    List<String> suspiciousTlds,
  ) {
    final hosts = _extractHosts(rawData);
    if (hosts.isEmpty) return <String, Object?>{'results': <Object?>[]};

    final trees = modelStructure['trees'];
    if (trees is! List || trees.length != _expectedTreeCount) {
      throw const FormatException(
        'El modelo local no contiene exactamente 500 árboles.',
      );
    }
    final suspicious = suspiciousTlds.map((tld) => tld.toLowerCase()).toSet();
    final results = <Map<String, Object?>>[];
    for (final host in hosts) {
      final features = _extractFeatures(host, suspicious);
      var threatVotes = 0;
      for (final tree in trees) {
        if (tree is! Map || !tree.containsKey('root')) {
          throw const FormatException('Raíz de árbol inválida en el bosque.');
        }
        threatVotes += _evaluateNode(tree['root'], features);
      }
      final threatScore = threatVotes / trees.length;
      final maximumConsonantStreak = _maximumConsonantStreak(host);
      results.add(<String, Object?>{
        'host': host,
        'threat_score': threatScore,
        'is_threat': threatScore >= 0.5,
        'features': <String, double>{
          'length': features[0],
          'entropy': features[1],
          'digit_ratio': features[2],
          'vowel_ratio': features[3],
          'consonant_sequence_ratio': features[4],
          'suspicious_tld': features[5],
          'maximum_consonant_streak': maximumConsonantStreak.toDouble(),
          'maximum_consonant_streak_ratio':
              host.isEmpty
                  ? 0.0
                  : maximumConsonantStreak / host.runes.length,
        },
      });
    }
    return <String, Object?>{'results': results};
  }

  static List<String> _extractHosts(String rawData) {
    final hosts = <String>{};
    try {
      _collectHosts(jsonDecode(rawData), hosts);
    } on FormatException {
      for (final match in _domainPattern.allMatches(rawData)) {
        final value = match.group(0);
        if (value != null) {
          final host = _normalizeHost(value);
          if (host != null) hosts.add(host);
        }
      }
    }
    return hosts.toList(growable: false);
  }

  static void _collectHosts(Object? value, Set<String> hosts, [int depth = 0]) {
    if (depth > _maximumTreeDepth) {
      throw const FormatException('El payload JSON supera la profundidad permitida.');
    }
    if (value is Map) {
      for (final entry in value.entries) {
        final key = entry.key.toString().toLowerCase();
        if (_domainFields.contains(key) && entry.value is String) {
          final host = _normalizeHost(entry.value as String);
          if (host != null) hosts.add(host);
        } else {
          _collectHosts(entry.value, hosts, depth + 1);
        }
      }
    } else if (value is List) {
      for (final entry in value) {
        _collectHosts(entry, hosts, depth + 1);
      }
    }
  }

  static String? _normalizeHost(String input) {
    var candidate = input.trim().toLowerCase();
    if (candidate.isEmpty) return null;
    if (candidate.contains('://')) {
      final uri = Uri.tryParse(candidate);
      if (uri == null ||
          (uri.scheme != 'http' && uri.scheme != 'https') ||
          uri.userInfo.isNotEmpty ||
          uri.host.isEmpty) {
        return null;
      }
      candidate = uri.host.toLowerCase();
    } else {
          if (candidate.contains('/') ||
            candidate.contains('\\') ||
            candidate.contains('?') ||
            candidate.contains('#') ||
            candidate.contains('@') ||
            candidate.contains(':') ||
            candidate.contains('%')) {
        return null;
      }
    }
    if (candidate.endsWith('.')) {
      candidate = candidate.substring(0, candidate.length - 1);
    }
    if (!_hostnamePattern.hasMatch(candidate) ||
        InternetAddress.tryParse(candidate) != null) {
      return null;
    }
    return candidate;
  }

  static List<double> _extractFeatures(
    String host,
    Set<String> suspiciousTlds,
  ) {
    final characters = host.runes.toList(growable: false);
    final length = characters.length;
    if (length == 0) return List<double>.filled(6, 0);

    var digits = 0;
    var vowels = 0;
    var letterCount = 0;
    var currentConsonantRun = 0;
    var maximumConsonantRun = 0;
    var consonantSequenceCharacters = 0;
    for (final character in characters) {
      if (_isAsciiDigit(character)) digits++;
      if (_isAsciiLetter(character)) {
        letterCount++;
        final lower = character | 0x20;
        if (_isVowel(lower)) {
          vowels++;
          if (currentConsonantRun >= 3) {
            consonantSequenceCharacters += currentConsonantRun;
          }
          currentConsonantRun = 0;
        } else {
          currentConsonantRun++;
          if (currentConsonantRun > maximumConsonantRun) {
            maximumConsonantRun = currentConsonantRun;
          }
        }
      } else {
        if (currentConsonantRun >= 3) {
          consonantSequenceCharacters += currentConsonantRun;
        }
        currentConsonantRun = 0;
      }
    }
    if (currentConsonantRun >= 3) {
      consonantSequenceCharacters += currentConsonantRun;
    }

    final lettersDenominator = letterCount == 0 ? 1 : letterCount;
    final tld = host.substring(host.lastIndexOf('.') + 1);
    return <double>[
      length.toDouble(),
      _shannonEntropy(host),
      digits / length,
      letterCount == 0 ? 0 : vowels / lettersDenominator,
      letterCount == 0
          ? 0
          : consonantSequenceCharacters / lettersDenominator,
      suspiciousTlds.contains(tld) ? 1 : 0,
    ];
  }

  static double _shannonEntropy(String host) {
    if (host.isEmpty) return 0;
    final frequencies = <int, int>{};
    final characters = host.toLowerCase().runes.toList(growable: false);
    for (final character in characters) {
      frequencies.update(character, (count) => count + 1, ifAbsent: () => 1);
    }
    final length = characters.length;
    var entropy = 0.0;
    for (final count in frequencies.values) {
      final probability = count / length;
      entropy -= probability * (math.log(probability) / math.ln2);
    }
    return entropy;
  }

  static int _maximumConsonantStreak(String host) {
    var current = 0;
    var maximum = 0;
    for (final character in host.runes) {
      if (_isAsciiLetter(character) && !_isVowel(character | 0x20)) {
        current++;
        if (current > maximum) maximum = current;
      } else {
        current = 0;
      }
    }
    return maximum;
  }

  static int _evaluateNode(
    Object? rawNode,
    List<double> features, [
    int depth = 0,
  ]) {
    if (rawNode is! Map || depth > _maximumTreeDepth) {
      throw const FormatException('Nodo inválido en el modelo local.');
    }
    if (rawNode['type'] == 'leaf') {
      final value = rawNode['value'];
      if (value is! int || (value != 0 && value != 1)) {
        throw const FormatException('La hoja debe contener un voto binario.');
      }
      return value;
    }
    final featureIndex = rawNode['feature_index'];
    final threshold = rawNode['threshold'];
    if (rawNode['type'] != 'split' ||
        featureIndex is! int ||
        featureIndex < 0 ||
        featureIndex >= features.length ||
        threshold is! num ||
        !threshold.toDouble().isFinite) {
      throw const FormatException('Nodo de bifurcación inválido.');
    }
    final branch = features[featureIndex] <= threshold.toDouble()
        ? rawNode['left']
        : rawNode['right'];
    return _evaluateNode(branch, features, depth + 1);
  }

  static bool _isAsciiLetter(int character) =>
      (character >= 65 && character <= 90) ||
      (character >= 97 && character <= 122);

  static bool _isAsciiDigit(int character) =>
      character >= 48 && character <= 57;

  static bool _isVowel(int character) =>
      character == 0x61 ||
      character == 0x65 ||
      character == 0x69 ||
      character == 0x6f ||
      character == 0x75;
}
