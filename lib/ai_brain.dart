import 'dart:convert';
import 'dart:developer' as developer;
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

import 'agent/aura_crypto_layer.dart';
import 'agent/aura_whitelist.dart';
import 'inference/aura_ai_inference.dart' as shared_features;
import 'infrastructure/security/aura_dynamic_whitelist.dart';
import 'models/aura_ai_brain.dart';
import 'secure_vault.dart';
import 'providers/aura_state_provider.dart';
import 'security/shannon_entropy.dart';

export 'security/shannon_entropy.dart';

typedef AuraToolStartedCallback = void Function(
  String toolName,
  Map<String, Object?> arguments,
);
typedef AuraToolCompletedCallback = void Function(
  String toolName,
  Map<String, Object?> arguments,
  Map<String, Object?> result,
);
typedef AuraDnsBlockRuleHandler = Future<bool> Function(String domain);
typedef AuraModelIntegrityFailureHandler = void Function(String message);

const Set<String> _suspiciousTlds = {
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
  'top',
  'wang',
  'work',
  'xyz',
  'zip',
};

List<double> extractFeatures(String domain) {
  final host = _normalizeDomain(domain);
  final characters = host.runes.toList(growable: false);
  final letters = characters
      .where(_isAsciiLetter)
      .toList(growable: false);
  final digits = characters.where(_isAsciiDigit).length;
  final vowels = letters.where(_isVowel).length;
  final consonantSequenceCharacters = _consonantSequenceLength(characters);
  final tld = host.split('.').last;
  final letterCount = letters.length;

  return <double>[
    host.length.toDouble(),
    calculateShannonEntropy(host),
    characters.isEmpty ? 0 : digits / characters.length,
    letterCount == 0 ? 0 : vowels / letterCount,
    letterCount == 0 ? 0 : consonantSequenceCharacters / letterCount,
    _suspiciousTlds.contains(tld) ? 1 : 0,
  ];
}

class AuraAIBrain {
  static const String _modelAssetPath =
      'assets/model/aura_brain_model.json';
  static const String _modelDigestAssetPath =
      'assets/model/aura_brain_model.json.sha256';
  static const String _installedModelFileName = 'aura_brain_model.enc';
  static const int _maxModelBytes = 5 * 1024 * 1024;
  static const int _maxEncryptedModelHexBytes =
      2 * (_maxModelBytes + 2 * 16);
  static const MethodChannel _engineChannel =
      MethodChannel('com.aura.cyberdefense/engine');
  static const MethodChannel _shieldChannel =
      MethodChannel('com.ciberdefensa.aura/shield');
  static const MethodChannel _telemetryChannel =
      MethodChannel('com.ciberdefensa.aura/telemetry');
  static final List<WeakReference<AuraAIBrain>> _instances = [];
  static AuraModelIntegrityFailureHandler? onModelIntegrityFailure;
  static bool _forceRuleFallback = false;

  final AuraStateProvider? _stateProvider;
  final AuraSecureVault _secureVault;
  final AuraToolStartedCallback? _onToolStarted;
  final AuraToolCompletedCallback? _onToolCompleted;
  AuraDnsBlockRuleHandler? _onDnsBlockRule;
  Future<Map<String, dynamic>>? _modelLoad;
  Map<String, dynamic>? _modelCache;

  AuraAIBrain({
    AuraStateProvider? stateProvider,
    AuraSecureVault? secureVault,
    AuraToolStartedCallback? onToolStarted,
    AuraToolCompletedCallback? onToolCompleted,
    AuraDnsBlockRuleHandler? onDnsBlockRule,
    })  : _stateProvider = stateProvider,
      _secureVault = secureVault ?? AuraSecureVault(),
        _onToolStarted = onToolStarted,
        _onToolCompleted = onToolCompleted,
        _onDnsBlockRule = onDnsBlockRule {
    _instances.removeWhere((reference) => reference.target == null);
    _instances.add(WeakReference<AuraAIBrain>(this));
  }

  void setDnsBlockRuleHandler(AuraDnsBlockRuleHandler handler) {
    _onDnsBlockRule = handler;
  }

  Future<bool> setShieldActive(bool active) async {
    final result = await _shieldChannel.invokeMethod<bool>(
      active ? 'startShield' : 'stopShield',
    );
    return result ?? false;
  }

  Future<bool> addDnsBlockRule(String domain) async {
    final handler = _onDnsBlockRule;
    if (handler != null) return handler(domain);
    final result = await _engineChannel.invokeMethod<bool>(
      'addDnsBlockRule',
      {'domain': domain},
    );
    return result ?? false;
  }

  Future<String> analyzeCyberThreat(String userInput) =>
      analyzeThreatPayload(userInput);

  Future<bool> preloadModel() async {
    final model = await _getModel();
    return !_forceRuleFallback && model['trees'] is List;
  }

  static Future<void> purgeAllInMemoryModels() async {
    final brains = _instances
        .map((reference) => reference.target)
        .whereType<AuraAIBrain>()
        .toList(growable: false);
    for (final brain in brains) {
      await brain._purgeCachedModel();
    }
    _instances.removeWhere((reference) => reference.target == null);
    final supportDirectory = await getApplicationSupportDirectory();
    final installedModel = File(
      '${supportDirectory.path}/$_installedModelFileName',
    );
    final installedDigest = File('${installedModel.path}.sha256');
    final installedSignature = File('${installedModel.path}.sig');
    if (await installedModel.exists()) await installedModel.delete();
    if (await installedDigest.exists()) await installedDigest.delete();
    if (await installedSignature.exists()) await installedSignature.delete();
    _forceRuleFallback = false;
  }

  static Future<void> installDownloadedModel({
    required File destination,
    required Uint8List modelBytes,
    required Uint8List signatureBytes,
    required String expectedSha256,
  }) async {
    if (!AuraCryptoLayer.verifySignature(modelBytes, signatureBytes)) {
      modelBytes.fillRange(0, modelBytes.length, 0);
      signatureBytes.fillRange(0, signatureBytes.length, 0);
      await useSafeRuleFallback(
        'La firma RSA/SHA-256 del modelo remoto no es válida.',
        notifyHud: false,
      );
      throw const FormatException('La firma RSA del modelo no es válida.');
    }
    final actualDigest = sha256.convert(modelBytes).toString();
    if (!_isSha256(expectedSha256) ||
        actualDigest != expectedSha256.toLowerCase()) {
      modelBytes.fillRange(0, modelBytes.length, 0);
      signatureBytes.fillRange(0, signatureBytes.length, 0);
      await useSafeRuleFallback(
        'Digest incorrecto para el modelo remoto; se descartó el buffer descargado.',
        notifyHud: false,
      );
      throw const FormatException('El SHA-256 del modelo remoto no coincide.');
    }

    Map<String, dynamic>? decoded;
    try {
      decoded = _decodeAndValidateModel(utf8.decode(modelBytes));
      final brains = _instances
          .map((reference) => reference.target)
          .whereType<AuraAIBrain>()
          .toList(growable: false);
      final vault =
          brains.isEmpty ? AuraSecureVault() : brains.first._secureVault;
      final secureKey = await vault.getOrCreateModelMasterKey();
      final encryptedHex = AuraCryptoLayer.encryptModel(
        utf8.decode(modelBytes),
        secureKey,
      );
      final encryptedBytes = Uint8List.fromList(utf8.encode(encryptedHex));
      final localDigest = sha256.convert(encryptedBytes).toString();
      await _writeModelPair(
        destination,
        encryptedBytes,
        localDigest,
        signatureBytes,
      );
      _forceRuleFallback = false;
      for (final brain in brains) {
        _clearModelValue(brain._modelCache);
        final cachedModel =
            Map<String, dynamic>.from(jsonDecode(jsonEncode(decoded)) as Map);
        brain._modelCache = cachedModel;
        brain._modelLoad = Future<Map<String, dynamic>>.value(cachedModel);
      }
    } finally {
      if (decoded != null) _clearModelValue(decoded);
      modelBytes.fillRange(0, modelBytes.length, 0);
      signatureBytes.fillRange(0, signatureBytes.length, 0);
    }
  }

  static Future<void> useSafeRuleFallback(
    String reason, {
    bool notifyHud = true,
  }) async {
    _forceRuleFallback = true;
    for (final brain in _instances
        .map((reference) => reference.target)
        .whereType<AuraAIBrain>()) {
      _clearModelValue(brain._modelCache);
      brain._modelCache = null;
      brain._modelLoad = Future<Map<String, dynamic>>.value(
        <String, dynamic>{},
      );
    }
    if (notifyHud) onModelIntegrityFailure?.call(reason);
  }

  static bool _isSha256(String value) =>
      RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(value.trim());

  static Map<String, dynamic> _decodeAndValidateModel(String plaintext) {
    final decoded = jsonDecode(plaintext);
    try {
      if (decoded is! Map ||
          decoded['trees'] is! List ||
          (decoded['trees'] as List).length != 500) {
        throw const FormatException(
          'El modelo no contiene un bosque válido de 500 árboles.',
        );
      }
      for (final tree in decoded['trees'] as List) {
        if (tree is! Map || !tree.containsKey('root')) {
          throw const FormatException('Raíz de árbol inválida en el bosque.');
        }
        _validateNode(tree['root']);
      }
      return Map<String, dynamic>.from(decoded);
    } on Object {
      _clearModelValue(decoded);
      rethrow;
    }
  }

  static void _validateNode(Object? rawNode, [int depth = 0]) {
    if (rawNode is! Map || depth > 32) {
      throw const FormatException('Nodo inválido en el modelo local.');
    }
    if (rawNode['type'] == 'leaf') {
      final value = rawNode['value'];
      if (value is! int || (value != 0 && value != 1)) {
        throw const FormatException('La hoja debe contener un voto binario.');
      }
      return;
    }
    final featureIndex = rawNode['feature_index'];
    if (rawNode['type'] != 'split' ||
        featureIndex is! int ||
        featureIndex < 0 ||
        featureIndex >= 6 ||
        rawNode['threshold'] is! num) {
      throw const FormatException('Nodo de bifurcación inválido.');
    }
    _validateNode(rawNode['left'], depth + 1);
    _validateNode(rawNode['right'], depth + 1);
  }

  static Future<void> _writeModelPair(
    File destination,
    Uint8List encryptedBytes,
    String digest,
    Uint8List signatureBytes,
  ) async {
    await destination.parent.create(recursive: true);
    final digestFile = File('${destination.path}.sha256');
    final signatureFile = File('${destination.path}.sig');
    final modelTemporary = File('${destination.path}.tmp');
    final digestTemporary = File('${digestFile.path}.tmp');
    final signatureTemporary = File('${signatureFile.path}.tmp');
    try {
      await modelTemporary.writeAsBytes(encryptedBytes, flush: true);
      await digestTemporary.writeAsString(digest, flush: true);
      await signatureTemporary.writeAsBytes(signatureBytes, flush: true);
      await modelTemporary.rename(destination.path);
      await digestTemporary.rename(digestFile.path);
      await signatureTemporary.rename(signatureFile.path);
    } on Object {
      if (await modelTemporary.exists()) await modelTemporary.delete();
      if (await digestTemporary.exists()) await digestTemporary.delete();
      if (await signatureTemporary.exists()) await signatureTemporary.delete();
      rethrow;
    } finally {
      encryptedBytes.fillRange(0, encryptedBytes.length, 0);
      signatureBytes.fillRange(0, signatureBytes.length, 0);
    }
  }

  Future<Map<String, dynamic>> _getModel() async {
    if (_forceRuleFallback) return <String, dynamic>{};
    final loadedModel = await (_modelLoad ??= _loadModel());
    if (_forceRuleFallback) {
      _clearModelValue(loadedModel);
      _modelCache = null;
      return <String, dynamic>{};
    }
    _modelCache = loadedModel;
    return loadedModel;
  }

  Future<void> _purgeCachedModel() async {
    final cachedLoad = _modelLoad;
    _modelLoad = null;
    _clearModelValue(_modelCache);
    _modelCache = null;
    if (cachedLoad != null) _clearModelValue(await cachedLoad);
  }

  static void _clearModelValue(Object? value) {
    if (value is Map) {
      for (final nestedValue in value.values.toList(growable: false)) {
        _clearModelValue(nestedValue);
      }
      value.clear();
    } else if (value is List) {
      for (final nestedValue in value.toList(growable: false)) {
        _clearModelValue(nestedValue);
      }
      value.clear();
    }
  }

  Future<String> analyzeThreatPayload(String payload) async {
    try {
      final extractedDomains = _extractDomains(payload);
      final blocklistedDomains = await shared_features.AuraAIInference
          .findBlocklistedDomains(extractedDomains);
      for (final domain in blocklistedDomains) {
        await _recordDomainOutcome(
          domain,
          'blocked',
          source: 'blocklist',
        );
      }
      final blocklistResults = await _enforceBlocklistHits(blocklistedDomains);
      final protectedDomains = <String>[];
      final analyzableDomains = <String>[];
      for (final domain in extractedDomains) {
        if (blocklistedDomains.contains(domain)) continue;
        if (AuraDynamicWhitelist.instance.isSafeHost(domain)) {
          protectedDomains.add(domain);
        } else {
          analyzableDomains.add(domain);
        }
      }
      for (final domain in protectedDomains) {
        await _recordDomainOutcome(
          domain,
          'allowed',
          source: 'allowlist',
        );
        developer.log(
          'Dominio protegido por el Escudo Allowlist: $domain',
          name: 'AuraAIInference',
          level: 800,
        );
      }
      if (extractedDomains.isNotEmpty && analyzableDomains.isEmpty) {
        final protectedResults = protectedDomains.map(
          (domain) => 'Dominio protegido por el Escudo Allowlist: $domain.',
        );
        return <String>[...blocklistResults, ...protectedResults].join('\n');
      }
      final inferencePayload = extractedDomains.isEmpty
          ? payload
          : jsonEncode(<String, Object?>{
              'hosts': analyzableDomains
                  .map((domain) => <String, String>{'host': domain})
                  .toList(growable: false),
            });

      if (_forceRuleFallback) {
        final domains = _extractDomains(inferencePayload);
        if (domains.isEmpty) {
          return 'Análisis local limitado a dominios: no se encontró un dominio válido.';
        }
        return _analyzeWithDefaultRules(domains);
      }
      if (!inferencePayload.contains('.')) {
        return 'Análisis local limitado a dominios: no se encontró un dominio válido.';
      }
      final model = await _getModel();
      if (_forceRuleFallback) {
        final domains = _extractDomains(inferencePayload);
        if (domains.isEmpty) {
          return 'Análisis local limitado a dominios: no se encontró un dominio válido.';
        }
        return _analyzeWithDefaultRules(domains);
      }
      final inferenceResults = await AuraAIInference.analyzeThreatPayload(
        rawData: inferencePayload,
        modelStructure: model,
        suspiciousTlds: _suspiciousTlds.toList(growable: false),
        blocklistChecked: true,
      );
      if (inferenceResults.isEmpty) {
        return 'Análisis local limitado a dominios: no se encontró un dominio válido.';
      }

      final results = <String>[
        ...blocklistResults,
        ...protectedDomains
          .map(
            (domain) => 'Dominio protegido por el Escudo Allowlist: $domain.',
          ),
      ];
      for (final inference in inferenceResults) {
        final domain = inference.host;
        final threatScore = inference.threatScore;
        final isThreat = inference.isThreat;
        if (AuraWhitelist.isSafe(domain)) {
          await _recordDomainOutcome(
            domain,
            'allowed',
            source: 'allowlist',
            modelVersion: model['model_version'] is String
                ? model['model_version'] as String
                : null,
          );
          results.add(
            'Dominio seguro por allowlist: $domain (0% de votos de amenaza).',
          );
          continue;
        }
        await _recordDomainOutcome(
          domain,
          isThreat ? 'blocked' : 'allowed',
          source: 'ml',
          modelVersion: model['model_version'] is String
              ? model['model_version'] as String
              : null,
        );
        _stateProvider?.recordLocalForestEvaluation();

        if (isThreat) {
          _stateProvider?.setSecurityLevel(AuraSecurityLevel.critical);
          final arguments = <String, Object?>{'domain': domain};
          _onToolStarted?.call('mitigate_network_threat', arguments);
          Map<String, Object?> result;
          try {
            final blocked = await addDnsBlockRule(domain);
            result = {
              'ok': blocked,
              'domain': domain,
              'enforcement_scope': 'device-wide',
              if (!blocked) 'error': 'El motor no confirmó la regla DNS.',
            };
          } on Object catch (error) {
            result = {
              'ok': false,
              'domain': domain,
              'error': error.toString(),
            };
          }
          _onToolCompleted?.call(
            'mitigate_network_threat',
            arguments,
            result,
          );
          results.add(
            'AMENAZA: $domain (${(threatScore * 100).toStringAsFixed(0)}% '
            'de votos); ${result['ok'] == true ? 'bloqueo confirmado' : 'bloqueo no confirmado'}.',
          );
        } else {
          results.add(
            'Sin amenaza según el modelo local: $domain '
            '(${(threatScore * 100).toStringAsFixed(0)}% de votos de amenaza).',
          );
        }
      }
      return results.join('\n');
    } on Object catch (error) {
      return 'ERROR DE ANÁLISIS LOCAL: ${error.toString()}';
    }
  }

  Future<List<String>> _enforceBlocklistHits(Set<String> domains) async {
    final results = <String>[];
    for (final domain in domains) {
      _stateProvider?.setSecurityLevel(AuraSecurityLevel.critical);
      final arguments = <String, Object?>{'domain': domain};
      _onToolStarted?.call('mitigate_network_threat', arguments);
      var blocked = false;
      Object? failure;
      try {
        blocked = await addDnsBlockRule(domain);
      } on Object catch (error) {
        failure = error;
      }
      final toolResult = <String, Object?>{
        'ok': blocked,
        'domain': domain,
        'enforcement_scope': 'device-wide',
        if (failure != null) 'error': failure.toString(),
        if (!blocked && failure == null)
          'error': 'El motor no confirmó la regla DNS.',
      };
      _onToolCompleted?.call(
        'mitigate_network_threat',
        arguments,
        toolResult,
      );
      results.add(
        'AMENAZA: $domain (blocklist verificada; no se ejecutó ML); '
        '${blocked ? 'bloqueo confirmado' : 'bloqueo no confirmado'}.',
      );
    }
    return results;
  }

  Future<void> _recordDomainOutcome(
    String domain,
    String outcome, {
    required String source,
    String? modelVersion,
  }) async {
    if (!Platform.isAndroid) return;
    try {
      await _telemetryChannel.invokeMethod<bool>(
        'recordDomainOutcome',
        <String, Object>{
          'domain': domain,
          'outcome': outcome,
          'source': source,
          if (modelVersion != null) 'model_version': modelVersion,
        },
      );
    } on Object catch (error, stackTrace) {
      developer.log(
        'No se pudo encolar el evento opcional de telemetría.',
        name: 'AuraTelemetry',
        error: error,
        stackTrace: stackTrace,
        level: 900,
      );
    }
  }

  Future<Map<String, dynamic>> _loadModel() async {
    Uint8List? artifactBytes;
    Map<String, dynamic>? decoded;
    try {
      final supportDirectory = await getApplicationSupportDirectory();
      final installedModel = File(
        '${supportDirectory.path}/$_installedModelFileName',
      );
      final installedDigest = File('${installedModel.path}.sha256');
      final installedSignature = File('${installedModel.path}.sig');
      final secureKey = await _secureVault.getOrCreateModelMasterKey();
      if (await installedModel.exists()) {
        artifactBytes = await installedModel.readAsBytes();
        if (artifactBytes.isEmpty ||
          artifactBytes.length > _maxEncryptedModelHexBytes) {
          throw const FormatException(
            'El modelo cifrado local está vacío o supera el tamaño permitido.',
          );
        }
        if (!await installedDigest.exists()) {
          throw const FormatException(
            'Falta el digest del modelo cifrado instalado.',
          );
        }
        final expectedDigest = (await installedDigest.readAsString()).trim();
        final actualDigest = sha256.convert(artifactBytes).toString();
        if (!_isSha256(expectedDigest) ||
            actualDigest != expectedDigest.toLowerCase()) {
          throw const FormatException(
            'El SHA-256 del modelo cifrado local no coincide.',
          );
        }
        final plaintext = await AuraCryptoLayer.decryptModelSecure(
          utf8.decode(artifactBytes),
          secureKey,
        );
        final plaintextBytes = Uint8List.fromList(
          utf8.encode(plaintext),
        );
        try {
          if (!await installedSignature.exists()) {
            throw const FormatException(
              'Falta la firma RSA del modelo instalado.',
            );
          }
          final signatureBytes = await installedSignature.readAsBytes();
          try {
            if (!AuraCryptoLayer.verifySignature(
              plaintextBytes,
              signatureBytes,
            )) {
              throw const FormatException(
                'La firma RSA del modelo instalado no es válida.',
              );
            }
          } finally {
            signatureBytes.fillRange(0, signatureBytes.length, 0);
          }
        } finally {
          plaintextBytes.fillRange(0, plaintextBytes.length, 0);
        }
        decoded = _decodeAndValidateModel(plaintext);
      } else {
        final sourceData = await rootBundle.load(_modelAssetPath);
        artifactBytes = Uint8List.fromList(
          sourceData.buffer.asUint8List(
            sourceData.offsetInBytes,
            sourceData.lengthInBytes,
          ),
        );
        if (artifactBytes.isEmpty || artifactBytes.length > _maxModelBytes) {
          throw const FormatException(
            'El modelo base está vacío o supera el tamaño permitido.',
          );
        }
        final expectedDigest =
            (await rootBundle.loadString(_modelDigestAssetPath)).trim();
        final actualDigest = sha256.convert(artifactBytes).toString();
        if (!_isSha256(expectedDigest) ||
            actualDigest != expectedDigest.toLowerCase()) {
          throw const FormatException(
            'El SHA-256 del modelo base empaquetado no coincide.',
          );
        }
        decoded = _decodeAndValidateModel(utf8.decode(artifactBytes));
      }
      return decoded;
    } on Object catch (error) {
      if (decoded != null) _clearModelValue(decoded);
      await useSafeRuleFallback(
        'Integridad del modelo no verificada; se activaron las reglas locales: $error',
      );
      return <String, dynamic>{};
    } finally {
      if (artifactBytes != null) {
        artifactBytes.fillRange(0, artifactBytes.length, 0);
      }
    }
  }

  String _analyzeWithDefaultRules(Iterable<String> domains) {
    final results = <String>[];
    for (final domain in domains) {
      if (AuraWhitelist.isSafe(domain)) {
        results.add('Regla local: dominio permitido por allowlist: $domain.');
        continue;
      }
      final features = extractFeatures(domain);
      final suspiciousTld = features.last == 1;
      final highEntropy = features[1] >= 3.8;
      results.add(
        suspiciousTld || highEntropy
            ? 'Regla local conservadora: revisar manualmente $domain; '
                'modelo no disponible, no se aplica bloqueo automático.'
            : 'Regla local: $domain no coincide con un indicador básico; '
                'modelo no disponible, resultado no concluyente.',
      );
    }
    return results.join('\n');
  }

  List<String> _extractDomains(String payload) {
    final domains = <String>{};
    try {
      _collectDomains(jsonDecode(payload), domains);
    } on FormatException {
      const domainPattern =
          r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]{1,63})+';
      for (final match in RegExp(domainPattern).allMatches(payload)) {
        final value = match.group(0);
        if (value != null) domains.add(_normalizeDomain(value));
      }
    }
    return domains.where((domain) => domain.contains('.')).toList();
  }

  void _collectDomains(Object? value, Set<String> domains) {
    if (value is Map) {
      for (final entry in value.entries) {
        final key = entry.key.toString().toLowerCase();
        if (const {
              'domain',
              'host',
              'hostname',
              'qname',
              'requested_domain',
            }.contains(key) &&
            entry.value is String) {
          final domain = _normalizeDomain(entry.value as String);
          if (domain.contains('.')) domains.add(domain);
        } else {
          _collectDomains(entry.value, domains);
        }
      }
    } else if (value is List) {
      for (final entry in value) {
        _collectDomains(entry, domains);
      }
    }
  }
}

String _normalizeDomain(String input) {
  var candidate = input.trim().toLowerCase();
  if (candidate.contains('://')) {
    candidate = Uri.tryParse(candidate)?.host ?? candidate;
  } else {
    candidate = candidate.split('/').first;
  }
  if (candidate.startsWith('[') && candidate.endsWith(']')) {
    candidate = candidate.substring(1, candidate.length - 1);
  }
  final address = InternetAddress.tryParse(candidate);
  if (address != null) return address.address.toLowerCase();
  if (candidate.contains(':')) return '';
  candidate = candidate.split(':').first;
  return candidate.replaceFirst(RegExp(r'\.$'), '');
}

bool _isAsciiLetter(int character) =>
    (character >= 65 && character <= 90) ||
    (character >= 97 && character <= 122);

bool _isAsciiDigit(int character) => character >= 48 && character <= 57;

bool _isVowel(int character) => 'aeiou'.codeUnits.contains(character);

int _consonantSequenceLength(List<int> characters) {
  var runLength = 0;
  var sequenceCharacters = 0;
  for (final character in characters) {
    if (_isAsciiLetter(character) && !_isVowel(character)) {
      runLength++;
    } else {
      if (runLength >= 3) sequenceCharacters += runLength;
      runLength = 0;
    }
  }
  if (runLength >= 3) sequenceCharacters += runLength;
  return sequenceCharacters;
}
