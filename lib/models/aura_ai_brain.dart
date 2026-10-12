import 'dart:convert';
import 'dart:isolate';
import 'dart:io';

import '../inference/aura_ai_inference.dart' as shared_features;

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
    final hosts = _extractHosts(rawData)
        .where((host) => InternetAddress.tryParse(host) == null)
        .toList(growable: false);
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
      final features =
          shared_features.AuraAIInference.extractEnhancedFeatures(host);
      features[5] =
          suspicious.contains(host.substring(host.lastIndexOf('.') + 1))
              ? 1.0
              : 0.0;
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
          for (var index = 6;
              index < shared_features.AuraAIInference.enhancedFeatureOrder.length;
              index++)
            shared_features.AuraAIInference.enhancedFeatureOrder[index]:
                features[index],
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
    var rawAddressInput = rawData.trim();
    if (rawAddressInput.startsWith('[') && rawAddressInput.endsWith(']')) {
      rawAddressInput =
          rawAddressInput.substring(1, rawAddressInput.length - 1);
    }
    final rawAddress = InternetAddress.tryParse(rawAddressInput);
    if (rawAddress != null) {
      return <String>[rawAddress.address.toLowerCase()];
    }
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
          candidate.contains('%')) {
        return null;
      }
    }
    if (candidate.startsWith('[') && candidate.endsWith(']')) {
      candidate = candidate.substring(1, candidate.length - 1);
    }
    final address = InternetAddress.tryParse(candidate);
    if (address != null) return address.address.toLowerCase();
    if (candidate.contains(':')) return null;
    if (candidate.endsWith('.')) {
      candidate = candidate.substring(0, candidate.length - 1);
    }
    if (!_hostnamePattern.hasMatch(candidate)) return null;
    return candidate;
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

  static bool _isVowel(int character) =>
      character == 0x61 ||
      character == 0x65 ||
      character == 0x69 ||
      character == 0x6f ||
      character == 0x75;
}
