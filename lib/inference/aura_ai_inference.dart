import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:flutter/services.dart';

import 'aura_common_domains.dart';

class AuraAIInference {
  static const List<String> enhancedFeatureOrder = <String>[
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
  ];
  static const List<String> legacyFeatureOrder = <String>[
    'length',
    'shannon_entropy',
    'digit_ratio',
    'vowel_ratio',
    'consonant_sequence_ratio',
    'suspicious_tld',
  ];

  static const List<String> auraStaticWhitelist = <String>[
    'google.com',
    'apple.com',
    'microsoft.com',
    'amazonaws.com',
    'cloudflare.com',
    'akamaiedge.net',
    'android.com',
    'github.com',
    'whatsapp.net',
    'googleapis.com',
    'gstatic.com',
    'googleusercontent.com',
    'apple-dns.net',
    'icloud.com',
    'microsoftonline.com',
    'windows.net',
    'amazon.com',
    'awsstatic.com',
    'akamaized.net',
    'fastly.net',
  ];

  static const List<String> suspiciousTlds = <String>[
    'xyz',
    'info',
    'cc',
    'top',
    'cam',
    'click',
    'country',
    'date',
    'download',
    'fit',
    'gq',
    'loan',
    'mov',
    'party',
    'review',
    'rest',
    'stream',
    'support',
    'tk',
    'wang',
    'work',
    'zip',
  ];

  static final RegExp _hostnamePattern = RegExp(
    r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
    r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$',
  );
  static const int _maximumTreeDepth = 32;
  static const MethodChannel _blocklistChannel =
      MethodChannel('com.ciberdefensa.aura/blocklist');
  static const int _binaryHeaderLength = 8;
  static const int _binaryTreeHeaderLength = 8;
  static const int _binaryNodeLength = 20;
  static const int _maximumBinaryModelBytes = 5 * 1024 * 1024;
  static final Map<String, (int, double)> _levenshteinCache =
      <String, (int, double)>{};

  /// Returns true for allowlisted hosts or hosts classified as safe by the model.
  static bool analyzeHostSecure(
    String rawHost,
    Map<String, dynamic> trainedModelJson,
  ) {
    final host = _normalizeHost(rawHost);
    if (host == null) return false;
    if (_isAllowlisted(host)) return true;

    final features = _featuresForModel(host, trainedModelJson['feature_order']);
    return _evaluateEnsemble(Float64List.fromList(features), trainedModelJson);
  }

  /// Retains the original six unscaled values for legacy diagnostics.
  static Map<String, double> extractFeatures(String rawHost) {
    final values = extractLegacyFeatures(rawHost);
    return <String, double>{
      'length': values[0],
      'shannon_entropy': values[1],
      'digit_ratio': values[2],
      'vowel_ratio': values[3],
      'consonant_sequence_ratio': values[4],
      'suspicious_tld': values[5],
    };
  }

  /// Returns 18 features, preserving the six legacy values and adding
  /// twelve normalized features.
  static List<double> extractEnhancedFeatures(String domain) {
    final host = _normalizeFeatureDomain(domain);
    if (host == null) {
      throw const FormatException('El host no tiene un formato válido.');
    }

    return _calculateEnhancedFeatures(host);
  }

  /// Returns the original six unscaled values for models trained with v3.
  static List<double> extractLegacyFeatures(String domain) {
    final host = _normalizeFeatureDomain(domain);
    if (host == null) {
      throw const FormatException('El host no tiene un formato válido.');
    }
    return _calculateLegacyFeatures(host);
  }

  /// Uses an enhanced vector only when its exact feature schema is present.
  static List<double> extractFeaturesForModel(
    String domain,
    Object? featureOrder,
  ) {
    final host = _normalizeFeatureDomain(domain);
    if (host == null) {
      throw const FormatException('El host no tiene un formato válido.');
    }
    return _featuresForModel(host, featureOrder);
  }

  static List<String> extractDomainsForBlocklist(String rawData) {
    return _extractHosts(rawData)
        .where((host) => InternetAddress.tryParse(host) == null)
        .toList(growable: false);
  }

  static Future<Set<String>> findBlocklistedDomains(
    Iterable<String> domains,
  ) async {
    if (!Platform.isAndroid) return <String>{};
    final requestedDomains = domains.toList(growable: false);
    if (requestedDomains.isEmpty) return <String>{};
    final response = await _blocklistChannel.invokeMethod<Object?>(
      'blockedDomains',
      <String, Object>{'domains': requestedDomains},
    );
    if (response is! List || response.any((domain) => domain is! String)) {
      throw const FormatException(
        'El servicio nativo devolvió una respuesta de blocklist inválida.',
      );
    }
    final blockedDomains = response.cast<String>().toSet();
    if (!requestedDomains.toSet().containsAll(blockedDomains)) {
      throw const FormatException(
        'El servicio nativo devolvió dominios fuera de la consulta.',
      );
    }
    return blockedDomains;
  }

  static List<double> _featuresForModel(String host, Object? featureOrder) {
    if (featureOrder is List &&
        _sameFeatureOrder(featureOrder, enhancedFeatureOrder)) {
      return _calculateEnhancedFeatures(host);
    }
    if (featureOrder == null ||
        (featureOrder is List &&
            _sameFeatureOrder(featureOrder, legacyFeatureOrder))) {
      return _calculateLegacyFeatures(host);
    }
    throw const FormatException('El modelo tiene un orden de características no compatible.');
  }

  static bool _sameFeatureOrder(List<dynamic> actual, List<String> expected) {
    if (actual.length != expected.length) return false;
    for (var index = 0; index < expected.length; index++) {
      if (actual[index] != expected[index]) return false;
    }
    return true;
  }

  static List<double> _calculateLegacyFeatures(String host) {
    final characters = host.runes.toList(growable: false);
    if (characters.isEmpty) return List<double>.filled(6, 0);
    final letters = characters.where(_isAsciiLetter).toList(growable: false);
    final digits = characters.where(_isAsciiDigit).length;
    var vowels = 0;
    var consonantRun = 0;
    var consonantSequenceCharacters = 0;
    for (final character in characters) {
      if (!_isAsciiLetter(character)) {
        if (consonantRun >= 3) {
          consonantSequenceCharacters += consonantRun;
        }
        consonantRun = 0;
        continue;
      }
      final lower = character | 0x20;
      if (lower == 0x61 ||
          lower == 0x65 ||
          lower == 0x69 ||
          lower == 0x6f ||
          lower == 0x75) {
        vowels++;
        if (consonantRun >= 3) {
          consonantSequenceCharacters += consonantRun;
        }
        consonantRun = 0;
      } else {
        consonantRun++;
      }
    }
    if (consonantRun >= 3) {
      consonantSequenceCharacters += consonantRun;
    }
    final tld = host.substring(host.lastIndexOf('.') + 1);
    return <double>[
      characters.length.toDouble(),
      _calculateEntropy(characters),
      digits / characters.length,
      letters.isEmpty ? 0 : vowels / letters.length,
      letters.isEmpty
          ? 0
          : consonantSequenceCharacters / letters.length,
      suspiciousTlds.contains(tld) ? 1 : 0,
    ];
  }

  static List<double> _calculateEnhancedFeatures(String host) {
    final characters = host.runes.toList(growable: false);
    if (characters.isEmpty) {
      return List<double>.filled(enhancedFeatureOrder.length, 0);
    }

    final labels = host.split('.');
    final tld = labels.last;
    final nonAsciiCount = characters.where((character) => character > 0x7f).length;
    final legacyFeatures = _calculateLegacyFeatures(host);
    final asciiLetters = characters.where(_isAsciiLetter).toList(growable: false);
    var hasConsecutiveDigits = false;
    for (var index = 0; index < characters.length - 1; index++) {
      if (_isAsciiDigit(characters[index]) &&
          _isAsciiDigit(characters[index + 1])) {
        hasConsecutiveDigits = true;
        break;
      }
    }
    final rareCharacterCount = asciiLetters.where((character) {
      final lower = character | 0x20;
      return lower == 0x71 ||
          lower == 0x78 ||
          lower == 0x7a ||
          lower == 0x6b;
    }).length;
    final longestLabelLength = labels.fold<int>(
      0,
      (longest, label) => math.max(longest, label.runes.length).toInt(),
    );

    return legacyFeatures + <double>[
      _minimumNormalizedLevenshtein(host),
      _repeatedNgramRatio(characters, 2),
      _repeatedNgramRatio(characters, 3),
      math.min(host.split('.').length - 1, 126) / 126,
      math.min(tld.runes.length, 63) / 63,
      detectIdnHomoglyphs(host),
      nonAsciiCount / characters.length,
      hasConsecutiveDigits ? 1 : 0,
      _conditionalLabelEntropy(labels),
      asciiLetters.isEmpty ? 0 : rareCharacterCount / asciiLetters.length,
      math.min(longestLabelLength, 63) / 63,
      const <String>[
        'free',
        'reward',
        'update',
        'system',
        'unlock',
        'premium',
        'crack',
      ].any(host.contains)
          ? 1
          : 0,
    ];
  }

  static const Map<int, String> idnConfusables = <int, String>{
    0x0430: 'a',
    0x0435: 'e',
    0x043e: 'o',
    0x0440: 'p',
    0x0441: 'c',
    0x0443: 'y',
    0x0445: 'x',
  };

  /// Returns a capped score for Cyrillic characters that resemble Latin letters.
  static double detectIdnHomoglyphs(String domain) {
    final candidate = _normalizeFeatureDomain(domain);
    if (candidate == null) return 0;

    final confusableCount =
        candidate.runes.where(idnConfusables.containsKey).length;
    return math.min(confusableCount / 2, 1.0);
  }

  static double _repeatedNgramRatio(List<int> characters, int size) {
    final gramCount = characters.length - size + 1;
    if (gramCount <= 0) return 0;
    final frequencies = <String, int>{};
    for (var index = 0; index < gramCount; index++) {
      final gram = characters
          .sublist(index, index + size)
          .map((character) => character.toRadixString(16))
          .join(',');
      frequencies.update(gram, (count) => count + 1, ifAbsent: () => 1);
    }
    final repeated = frequencies.values.fold<int>(
      0,
      (total, count) => total + count - 1,
    );
    return repeated / gramCount;
  }

  static double _conditionalLabelEntropy(List<String> labels) {
    var characterCount = 0;
    var weightedEntropy = 0.0;
    for (final label in labels) {
      final labelCharacters = label.runes.toList(growable: false);
      if (labelCharacters.isEmpty) continue;
      characterCount += labelCharacters.length;
      final frequencies = <int, int>{};
      for (final character in labelCharacters) {
        frequencies.update(
          character,
          (count) => count + 1,
          ifAbsent: () => 1,
        );
      }
      var entropy = 0.0;
      for (final count in frequencies.values) {
        final probability = count / labelCharacters.length;
        entropy -= probability * (math.log(probability) / math.ln2);
      }
      weightedEntropy += labelCharacters.length * entropy;
    }
    if (characterCount == 0) return 0;
    return math.min(
      (weightedEntropy / characterCount) / (math.log(36) / math.ln2),
      1.0,
    );
  }

  /// Return minimum edit distance / host length, capped to [0, 1].
  static double levenshteinDistanceToTopDomains(String domain) {
    final host = _normalizeFeatureDomain(domain);
    if (host == null) return 1;
    return _minimumTopDomainDistances(host).$2;
  }

  /// True when the closest popular domain is no more than two edits away.
  static bool isProbableTyposquatting(String domain) {
    final host = _normalizeFeatureDomain(domain);
    if (host == null) return false;
    final distance = _minimumTopDomainDistances(host).$1;
    return distance > 0 && distance <= 2;
  }

  static double _minimumNormalizedLevenshtein(String host) =>
      _minimumTopDomainDistances(host).$2;

  static (int, double) _minimumTopDomainDistances(String host) {
    final cached = _levenshteinCache[host];
    if (cached != null) return cached;

    final hostCharacters = host.runes.toList(growable: false);
    var minimumDistance = math.max(hostCharacters.length, 253).toInt();
    for (final commonDomain in auraCommonDomains) {
      final domainCharacters = commonDomain.runes.toList(growable: false);
      final lengthDifference =
          (hostCharacters.length - domainCharacters.length).abs();
      if (lengthDifference >= minimumDistance) continue;
      final distance = _levenshteinDistance(hostCharacters, domainCharacters);
      if (distance < minimumDistance) {
        minimumDistance = distance;
      }
      if (minimumDistance == 0) {
        break;
      }
    }
    if (_levenshteinCache.length >= 512) {
      _levenshteinCache.remove(_levenshteinCache.keys.first);
    }
    final normalizedDistance = math
        .min(minimumDistance / math.max(hostCharacters.length, 1), 1.0)
        .toDouble();
    final distances = (minimumDistance, normalizedDistance);
    _levenshteinCache[host] = distances;
    return distances;
  }

  static int _levenshteinDistance(List<int> left, List<int> right) {
    if (left.isEmpty) return right.length;
    if (right.isEmpty) return left.length;
    var previous = List<int>.generate(right.length + 1, (index) => index);
    var current = List<int>.filled(right.length + 1, 0);
    for (var leftIndex = 0; leftIndex < left.length; leftIndex++) {
      current[0] = leftIndex + 1;
      for (var rightIndex = 0; rightIndex < right.length; rightIndex++) {
        final substitutionCost =
            left[leftIndex] == right[rightIndex] ? 0 : 1;
        current[rightIndex + 1] = math
            .min(
              math.min(
                current[rightIndex] + 1,
                previous[rightIndex + 1] + 1,
              ),
              previous[rightIndex] + substitutionCost,
            )
            .toInt();
      }
      final previousRow = previous;
      previous = current;
      current = previousRow;
    }
    return previous.last;
  }

  static String? _normalizeFeatureDomain(String rawDomain) {
    final asciiHost = _normalizeHost(rawDomain);
    if (asciiHost != null) return asciiHost;

    var candidate = rawDomain.trim().toLowerCase();
    if (candidate.endsWith('.')) {
      candidate = candidate.substring(0, candidate.length - 1);
    }
    if (candidate.isEmpty || !candidate.contains('.') ||
        candidate.runes.length > 253 ||
        InternetAddress.tryParse(candidate) != null) {
      return null;
    }

    final labels = candidate.split('.');
    for (final label in labels) {
      final characters = label.runes.toList(growable: false);
      if (characters.isEmpty ||
          characters.length > 63 ||
          characters.first == 0x2d ||
          characters.last == 0x2d) {
        return null;
      }
      for (final character in characters) {
        final isAsciiDnsCharacter = _isAsciiLetter(character) ||
            _isAsciiDigit(character) ||
            character == 0x2d;
        final isSupportedIdnCharacter = character > 0x7f &&
            String.fromCharCode(character).trim().isNotEmpty;
        if (!isAsciiDnsCharacter && !isSupportedIdnCharacter) return null;
      }
    }
    return candidate;
  }

  /// Populates a legacy six-feature vector for binary v3 model compatibility.
  static void _extractFeatureVector(Uint8List host, Float64List features) {
    final values = _calculateLegacyFeatures(String.fromCharCodes(host));
    for (var index = 0; index < values.length; index++) {
      features[index] = values[index];
    }
  }

  static bool _isAsciiLetter(int character) =>
      (character >= 0x41 && character <= 0x5a) ||
      (character >= 0x61 && character <= 0x7a);

  static double _calculateEntropy(
    List<int> characters, [
    Map<int, int>? existingFrequencies,
  ]) {
    if (characters.isEmpty) return 0;
    final frequencies = existingFrequencies ?? <int, int>{};
    if (existingFrequencies == null) {
      for (final character in characters) {
        frequencies.update(
          character,
          (count) => count + 1,
          ifAbsent: () => 1,
        );
      }
    }
    var entropy = 0.0;
    for (final count in frequencies.values) {
      final probability = count / characters.length;
      entropy -= probability * (math.log(probability) / math.ln2);
    }
    return entropy;
  }

  static bool _isAsciiDigit(int character) =>
      character >= 0x30 && character <= 0x39;

  /// Evaluates a little-endian AURA forest.
  ///
  /// Layout: `AURA`, uint32 tree count, then per tree uint32 root index and
  /// uint32 node count. Each node is five fields: int32 type (1 leaf, 2 split),
  /// int32 feature index (or leaf class 0/1), int32 left child, int32 right
  /// child, and float32 threshold. Child indices are local to their tree.
  static bool evaluateHostFromBinary(String rawHost, Uint8List modelBytes) {
    final host = _normalizeHost(rawHost);
    if (host == null) return false;
    if (_isAllowlisted(host)) return true;

    Uint8List? hostBuffer;
    Float64List? features;
    try {
      if (modelBytes.length < _binaryHeaderLength ||
          modelBytes.length > _maximumBinaryModelBytes) {
        throw const FormatException('Tamaño de modelo binario no válido.');
      }

      final data = ByteData.sublistView(modelBytes);
      if (data.getUint8(0) != 0x41 ||
          data.getUint8(1) != 0x55 ||
          data.getUint8(2) != 0x52 ||
          data.getUint8(3) != 0x41) {
        throw const FormatException('La cabecera mágica AURA no es válida.');
      }

      final treeCount = data.getUint32(4, Endian.little);
      if (treeCount == 0 ||
          treeCount >
              (modelBytes.length - _binaryHeaderLength) ~/
                  _binaryTreeHeaderLength) {
        throw const FormatException('El conteo de árboles no es válido.');
      }

      hostBuffer = Uint8List.fromList(host.codeUnits);
      features = Float64List(legacyFeatureOrder.length);
      _extractFeatureVector(hostBuffer, features);

      var offset = _binaryHeaderLength;
      var threatVotes = 0;
      for (var treeIndex = 0; treeIndex < treeCount; treeIndex++) {
        if (modelBytes.length - offset < _binaryTreeHeaderLength) {
          throw const FormatException('Cabecera de árbol truncada.');
        }
        final rootIndex = data.getUint32(offset, Endian.little);
        final nodeCount = data.getUint32(offset + 4, Endian.little);
        offset += _binaryTreeHeaderLength;

        if (nodeCount == 0 ||
            nodeCount > (modelBytes.length - offset) ~/ _binaryNodeLength) {
          throw const FormatException('Los nodos del árbol están truncados.');
        }
        final nodesStart = offset;
        _validateBinaryTree(data, nodesStart, nodeCount, rootIndex);
        final traversalPath = Uint8List(nodeCount);
        try {
          threatVotes += _walkBinaryTree(
            data,
            nodesStart,
            nodeCount,
            rootIndex,
            features,
            traversalPath,
          );
        } finally {
          traversalPath.fillRange(0, traversalPath.length, 0);
        }
        offset += nodeCount * _binaryNodeLength;
      }

      if (offset != modelBytes.length) {
        throw const FormatException('El modelo contiene bytes sobrantes.');
      }
      return threatVotes * 2 < treeCount;
    } finally {
      hostBuffer?.fillRange(0, hostBuffer.length, 0);
      features?.fillRange(0, features.length, 0);
    }
  }

  /// Reads an indexed `.bin` model and clears the file buffer after evaluation.
  static Future<bool> evaluateHostFromBinaryFile(
    String rawHost,
    File modelFile,
  ) async {
    if (!modelFile.path.toLowerCase().endsWith('.bin')) {
      throw const FormatException('El modelo debe ser un archivo .bin.');
    }
    final fileLength = await modelFile.length();
    if (fileLength < _binaryHeaderLength ||
        fileLength > _maximumBinaryModelBytes) {
      throw const FormatException('Tamaño de modelo binario no válido.');
    }

    final modelBytes = await modelFile.readAsBytes();
    try {
      return evaluateHostFromBinary(rawHost, modelBytes);
    } finally {
      modelBytes.fillRange(0, modelBytes.length, 0);
    }
  }

  static void _validateBinaryTree(
    ByteData data,
    int nodesStart,
    int nodeCount,
    int rootIndex,
  ) {
    if (rootIndex >= nodeCount) {
      throw const FormatException('El índice raíz está fuera del árbol.');
    }

    for (var index = 0; index < nodeCount; index++) {
      final nodeOffset = nodesStart + index * _binaryNodeLength;
      final type = data.getInt32(nodeOffset, Endian.little);
      final featureIndex = data.getInt32(nodeOffset + 4, Endian.little);
      final leftChild = data.getInt32(nodeOffset + 8, Endian.little);
      final rightChild = data.getInt32(nodeOffset + 12, Endian.little);
      final threshold = data.getFloat32(nodeOffset + 16, Endian.little);

      if (type == 1) {
        if ((featureIndex != 0 && featureIndex != 1) ||
            leftChild != -1 ||
            rightChild != -1) {
          throw const FormatException('El nodo hoja binario no es válido.');
        }
      } else if (type == 2) {
        if (featureIndex < 0 ||
            featureIndex >= 6 ||
            leftChild < 0 ||
            leftChild >= nodeCount ||
            rightChild < 0 ||
            rightChild >= nodeCount ||
            !threshold.isFinite) {
          throw const FormatException(
              'El nodo de decisión binario no es válido.');
        }
      } else {
        throw const FormatException('Tipo de nodo binario desconocido.');
      }
    }
  }

  static int _walkBinaryTree(
    ByteData data,
    int nodesStart,
    int nodeCount,
    int nodeIndex,
    Float64List features,
    Uint8List traversalPath, [
    int depth = 0,
  ]) {
    if (depth > _maximumTreeDepth || nodeIndex < 0 || nodeIndex >= nodeCount) {
      throw const FormatException('Recorrido binario fuera de límites.');
    }
    if (traversalPath[nodeIndex] != 0) {
      throw const FormatException('El árbol binario contiene un ciclo.');
    }

    traversalPath[nodeIndex] = 1;
    try {
      final nodeOffset = nodesStart + nodeIndex * _binaryNodeLength;
      final type = data.getInt32(nodeOffset, Endian.little);
      final featureIndex = data.getInt32(nodeOffset + 4, Endian.little);
      if (type == 1) return featureIndex;

      final leftChild = data.getInt32(nodeOffset + 8, Endian.little);
      final rightChild = data.getInt32(nodeOffset + 12, Endian.little);
      final threshold = data.getFloat32(nodeOffset + 16, Endian.little);
      final childIndex =
          features[featureIndex] <= threshold ? leftChild : rightChild;
      return _walkBinaryTree(
        data,
        nodesStart,
        nodeCount,
        childIndex,
        features,
        traversalPath,
        depth + 1,
      );
    } finally {
      traversalPath[nodeIndex] = 0;
    }
  }

  static String? _normalizeHost(String rawInput) {
    var candidate = rawInput.trim().toLowerCase();
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
    } else if (candidate.contains(RegExp(r'[/\\?#@:%]'))) {
      return null;
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

  static bool _isAllowlisted(String host) => auraStaticWhitelist.any(
        (suffix) => host == suffix || host.endsWith('.$suffix'),
      );

  static bool _evaluateEnsemble(
    Float64List features,
    Map<String, dynamic> model,
  ) {
    final trees = model['trees'];
    if (trees == null || (trees is List && trees.isEmpty)) return false;
    if (trees is! List) {
      throw const FormatException('El bosque de inferencia no es válido.');
    }

    var threatVotes = 0;
    for (final tree in trees) {
      if (tree is! Map || !tree.containsKey('root')) {
        throw const FormatException('La raíz de un árbol no es válida.');
      }
      threatVotes += _evaluateNode(tree['root'], features);
    }
    return threatVotes / trees.length < 0.5;
  }

  static int _evaluateNode(
    Object? rawNode,
    Float64List features, [
    int depth = 0,
  ]) {
    if (rawNode is! Map || depth > _maximumTreeDepth) {
      throw const FormatException('Nodo inválido en el modelo.');
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
}
