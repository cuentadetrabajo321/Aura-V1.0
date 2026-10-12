import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

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

    Uint8List? hostBuffer;
    Float64List? features;
    try {
      hostBuffer = Uint8List.fromList(host.codeUnits);
      features = Float64List(enhancedFeatureOrder.length);
      _extractFeatureVector(hostBuffer, features);
      return _evaluateEnsemble(features, trainedModelJson);
    } finally {
      hostBuffer?.fillRange(0, hostBuffer.length, 0);
      features?.fillRange(0, features.length, 0);
    }
  }

  /// Retains the original six named values for existing diagnostics callers.
  static Map<String, double> extractFeatures(String rawHost) {
    final values = extractEnhancedFeatures(rawHost);
    return <String, double>{
      'length': values[0],
      'shannon_entropy': values[1],
      'digit_ratio': values[2],
      'vowel_ratio': values[3],
      'consonant_sequence_ratio': values[4],
      'suspicious_tld': values[5],
    };
  }

  /// Returns the six legacy features followed by twelve normalized features.
  static List<double> extractEnhancedFeatures(String domain) {
    final host = _normalizeFeatureDomain(domain);
    if (host == null) {
      throw const FormatException('El host no tiene un formato válido.');
    }

    return _calculateEnhancedFeatures(host);
  }

  static List<double> _calculateEnhancedFeatures(String host) {
    final characters = host.runes.toList(growable: false);
    if (characters.isEmpty) {
      return List<double>.filled(enhancedFeatureOrder.length, 0);
    }

    var digits = 0;
    var vowels = 0;
    var letters = 0;
    var consonantRun = 0;
    var consonantSequenceCharacters = 0;
    final asciiLetters = <int>[];
    final labels = host.split('.');
    for (final character in characters) {
      if (_isAsciiDigit(character)) digits++;
      if (!_isAsciiLetter(character)) {
        if (consonantRun >= 3) {
          consonantSequenceCharacters += consonantRun;
        }
        consonantRun = 0;
        continue;
      }

      letters++;
      asciiLetters.add(character);
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

    final frequencies = <int, int>{};
    for (final character in characters) {
      frequencies.update(character, (count) => count + 1, ifAbsent: () => 1);
    }
    var entropy = 0.0;
    for (final count in frequencies.values) {
      final probability = count / characters.length;
      entropy -= probability * (math.log(probability) / math.ln2);
    }

    final tld = labels.last;
    final bigramRatio = _repeatedNgramRatio(characters, 2);
    final trigramRatio = _repeatedNgramRatio(characters, 3);
    final nonAsciiCount = characters.where((character) => character > 0x7f).length;
    final rareCharacterCount = asciiLetters.where((character) {
      final lower = character | 0x20;
      return lower == 0x71 ||
          lower == 0x78 ||
          lower == 0x7a ||
          lower == 0x6b;
    }).length;
    final idnHomograph = detectIdnHomoglyphs(host) >= 1.0;
    var longestLabelLength = 0;
    for (final label in labels) {
      longestLabelLength =
          math.max(longestLabelLength, label.runes.length).toInt();
    }

    return <double>[
      characters.length.toDouble(),
      entropy,
      digits / characters.length,
      letters == 0 ? 0 : vowels / letters,
      letters == 0 ? 0 : consonantSequenceCharacters / letters,
      suspiciousTlds.contains(tld) ? 1 : 0,
      _minimumNormalizedLevenshtein(host),
      bigramRatio,
      trigramRatio,
      (host.split('.').length - 1).clamp(0, 126) / 126,
      tld.runes.length.clamp(0, 63) / 63,
      idnHomograph ? 1 : 0,
      nonAsciiCount / characters.length,
      RegExp(r'[0-9]{2,}').hasMatch(host) ? 1 : 0,
      _conditionalLabelEntropy(labels),
      asciiLetters.isEmpty ? 0 : rareCharacterCount / asciiLetters.length,
      longestLabelLength.clamp(0, 63) / 63,
      const <String>['free', 'reward', 'update', 'system']
              .any(host.contains)
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

  /// Scores mapped Cyrillic homoglyphs: one yields 0.5, two or more yield 1.
  static double detectIdnHomoglyphs(String domain) {
    final candidate = _normalizeFeatureDomain(domain);
    if (candidate == null) return 0;

    var confusableCount = 0;
    for (var label in candidate.split('.')) {
      if (label.startsWith('xn--')) {
        final decoded = _decodePunycode(label.substring(4));
        if (decoded == null) continue;
        label = decoded;
      }
      confusableCount +=
          label.runes.where(idnConfusables.containsKey).length;
    }
    return math.min(confusableCount / 2, 1.0);
  }

  static String? _decodePunycode(String encoded) {
    const base = 36;
    const tmin = 1;
    const tmax = 26;
    const initialBias = 72;
    const initialCodePoint = 128;

    final output = <int>[];
    var inputIndex = 0;
    final delimiter = encoded.lastIndexOf('-');
    if (delimiter >= 0) {
      for (var index = 0; index < delimiter; index++) {
        final character = encoded.codeUnitAt(index);
        if (character > 0x7f) return null;
        output.add(character);
      }
      inputIndex = delimiter + 1;
    }

    var bias = initialBias;
    var codePoint = initialCodePoint;
    var insertionIndex = 0;
    while (inputIndex < encoded.length) {
      final oldInsertionIndex = insertionIndex;
      var weight = 1;
      for (var k = base;; k += base) {
        if (inputIndex >= encoded.length) return null;
        final digit = _punycodeDigit(encoded.codeUnitAt(inputIndex++));
        if (digit == null) return null;
        insertionIndex += digit * weight;

        final threshold = k <= bias
            ? tmin
            : k >= bias + tmax
                ? tmax
                : k - bias;
        if (digit < threshold) break;
        weight *= base - threshold;
      }

      final outputLength = output.length + 1;
      bias = _adaptPunycodeBias(
        insertionIndex - oldInsertionIndex,
        outputLength,
        oldInsertionIndex == 0,
      );
      codePoint += insertionIndex ~/ outputLength;
      insertionIndex %= outputLength;
      if (codePoint > 0x10ffff ||
          (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
        return null;
      }
      output.insert(insertionIndex, codePoint);
      insertionIndex++;
    }
    return String.fromCharCodes(output);
  }

  static int? _punycodeDigit(int character) {
    if (character >= 0x61 && character <= 0x7a) return character - 0x61;
    if (character >= 0x30 && character <= 0x39) return character - 0x30 + 26;
    return null;
  }

  static int _adaptPunycodeBias(int delta, int pointCount, bool firstTime) {
    const base = 36;
    const tmin = 1;
    const tmax = 26;
    const skew = 38;
    const damp = 700;

    delta = firstTime ? delta ~/ damp : delta ~/ 2;
    delta += delta ~/ pointCount;
    var k = 0;
    while (delta > ((base - tmin) * tmax) ~/ 2) {
      delta ~/= base - tmin;
      k += base;
    }
    return k + ((base - tmin + 1) * delta) ~/ (delta + skew);
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
      if (labelCharacters.length > 1) {
        weightedEntropy += labelCharacters.length *
            entropy /
            (math.log(labelCharacters.length) / math.ln2);
      }
    }
    return characterCount == 0 ? 0 : weightedEntropy / characterCount;
  }

  /// Return minimum edit distance / longer domain length, in [0, 1].
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
    var minimumNormalized = 1.0;
    for (final commonDomain in auraCommonDomains) {
      final domainCharacters = commonDomain.runes.toList(growable: false);
      final denominator =
          math.max(hostCharacters.length, domainCharacters.length).toInt();
      if (denominator == 0) continue;
      final lengthDifference =
          (hostCharacters.length - domainCharacters.length).abs();
      if (lengthDifference >= minimumDistance &&
          lengthDifference / denominator >= minimumNormalized) {
        continue;
      }
      final distance = _levenshteinDistance(hostCharacters, domainCharacters);
      final normalized = distance / denominator;
      if (normalized < minimumNormalized) {
        minimumNormalized = normalized;
      }
      if (distance < minimumDistance) {
        minimumDistance = distance;
      }
      if (minimumNormalized == 0 && minimumDistance == 0) {
        break;
      }
    }
    if (_levenshteinCache.length >= 512) {
      _levenshteinCache.remove(_levenshteinCache.keys.first);
    }
    final distances = (minimumDistance, minimumNormalized);
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
      var rowMinimum = current[0];
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
        rowMinimum = math.min(rowMinimum, current[rightIndex + 1]).toInt();
      }
      final previousRow = previous;
      previous = current;
      current = previousRow;
      if (rowMinimum >= left.length && rowMinimum >= right.length) {
        return rowMinimum;
      }
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

  /// Populates the legacy fields first, then appends the synchronized features.
  static void _extractFeatureVector(Uint8List host, Float64List features) {
    final values = _calculateEnhancedFeatures(String.fromCharCodes(host));
    for (var index = 0; index < values.length; index++) {
      features[index] = values[index];
    }
  }

  static bool _isAsciiLetter(int character) =>
      (character >= 0x41 && character <= 0x5a) ||
      (character >= 0x61 && character <= 0x7a);

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
      features = Float64List(enhancedFeatureOrder.length);
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
