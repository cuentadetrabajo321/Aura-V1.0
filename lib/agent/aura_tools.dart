import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';

import '../ai_brain.dart';
import '../secure_vault.dart';
import 'aura_crypto_layer.dart';

class ToolStep {
  const ToolStep({
    required this.name,
    required this.arguments,
  });

  final String name;
  final Map<String, dynamic> arguments;
}

class ToolResult {
  const ToolResult({
    required this.summary,
    required this.data,
  });

  final String summary;
  final Map<String, dynamic> data;
}

abstract class AuraTools {
  static final Uri _modelUri = Uri.parse(
    'https://yovanymoreno001-glitch.github.io/Aura-V1.0/model/aura_brain_model.json',
  );
  static final Uri _modelDigestUri = Uri.parse(
    'https://yovanymoreno001-glitch.github.io/Aura-V1.0/model/aura_brain_model.json.sha256',
  );
  static final Uri _modelSignatureUri = Uri.parse(
    'https://yovanymoreno001-glitch.github.io/Aura-V1.0/model/aura_brain_model.json.sig',
  );
  static const int _maxModelBytes = 5 * 1024 * 1024;
  static const MethodChannel _engineChannel =
      MethodChannel('com.aura.cyberdefense/engine');
    static const MethodChannel _panicChannel =
      MethodChannel('com.aura.cyberdefense/panic');
  static final AuraSecureVault _secureVault = AuraSecureVault();

  static Future<ToolResult> execute(
    ToolStep step, {
    void Function(String message)? onProgress,
  }) async {
    try {
      switch (step.name) {
        case 'update_defenses':
          return await _updateDefenses(onProgress);
        case 'block_domain':
          final domain = step.arguments['domain'];
          final blocked = await _engineChannel.invokeMethod<bool>(
            'addDnsBlockRule',
            {'domain': domain},
          );
          final confirmed = blocked == true;
          return ToolResult(
            summary: confirmed
                ? 'Dominio bloqueado por el motor DNS local.'
                : 'El motor DNS no confirmó el bloqueo del dominio.',
            data: <String, dynamic>{
              'ok': confirmed,
              if (domain != null) 'domain': domain,
            },
          );
        case 'isolate_app':
          final packageName = step.arguments['package_name'];
          final reason = step.arguments['reason'];
          final nativeResult = await _engineChannel.invokeMapMethod<String, dynamic>(
            'openAppDetails',
            <String, dynamic>{
              'package_name': packageName,
              if (reason is String) 'reason': reason,
            },
          );
          if (nativeResult == null) {
            return const ToolResult(
              summary: 'Android no devolvió el resultado de Ajustes.',
              data: <String, dynamic>{'ok': false},
            );
          }
          return ToolResult(
            summary: nativeResult['message'] as String? ??
                nativeResult['error'] as String? ??
                'Android devolvió el resultado de la solicitud.',
            data: Map<String, dynamic>.from(nativeResult),
          );
        case 'panic_isolation':
          final isolated = await _panicChannel.invokeMethod<bool>(
                'panicIsolation',
              ) ??
              false;
          return ToolResult(
            summary: isolated
                ? 'Forwarding del túnel detenido; la interfaz VPN queda en modo de descarte.'
                : 'No se confirmó el aislamiento: el túnel VPN no estaba activo.',
            data: <String, dynamic>{
              'ok': isolated,
              'isolation_active': isolated,
              'scope': 'active_vpn_tun',
              'security_level': isolated ? 'critical' : 'warning',
            },
          );
        case 'resume_network':
          final resumed = await _panicChannel.invokeMethod<bool>(
                'resumeTunnel',
              ) ??
              false;
          return ToolResult(
            summary: resumed
                ? 'Forwarding del túnel restablecido.'
                : 'No se pudo restablecer el forwarding del túnel.',
            data: <String, dynamic>{
              'ok': resumed,
              'security_level': resumed ? 'safe' : 'warning',
            },
          );
        case 'cryptographic_purge':
          await AuraAIBrain.purgeAllInMemoryModels();
          final nativeAuditMemoryPurged = await _engineChannel.invokeMethod<bool>(
                'purgeAuditMemory',
              ) ??
              false;
          await _secureVault.purgeSensitiveData();
          final Map<String, dynamic> auditData = {
            'ok': true,
            'model_cache_purged': true,
            'secure_storage_purged': true,
            'native_audit_memory_purged': nativeAuditMemoryPurged,
            'api_key_present': false,
          };
          return ToolResult(
            summary:
                'Cachés de modelos y datos de SecureVault eliminados. No hay una API key registrada en este almacenamiento.',
            data: auditData,
          );
        default:
          return ToolResult(
            summary: 'Herramienta no reconocida: ${step.name}.',
            data: <String, dynamic>{'ok': false, 'tool': step.name},
          );
      }
    } on PlatformException catch (error) {
      return ToolResult(
        summary: error.message ?? 'Android rechazó la operación solicitada.',
        data: <String, dynamic>{
          'ok': false,
          'code': error.code,
          if (error.details != null) 'details': error.details,
        },
      );
    } on MissingPluginException catch (error) {
      return ToolResult(
        summary: error.message ?? 'El canal nativo de Aura no está disponible.',
        data: <String, dynamic>{'ok': false, 'error': 'missing_plugin'},
      );
    }
  }

  static Future<ToolResult> _updateDefenses(
    void Function(String message)? onProgress,
  ) async {
    try {
      onProgress?.call(
        'Conectando por HTTPS al repositorio público de modelos... 📡',
      );
      onProgress?.call(
        'Buscando la firma RSA y el digest SHA-256 publicados... 🔍',
      );
      final digestResponse = await http.get(
        _modelDigestUri,
        headers: const <String, String>{},
      ).timeout(const Duration(seconds: 30));
      if (digestResponse.statusCode != HttpStatus.ok ||
          digestResponse.bodyBytes.length > 128) {
        throw const HttpException(
          'No se pudo descargar una verificación SHA-256 válida.',
        );
      }

      final signatureResponse = await http.get(
        _modelSignatureUri,
        headers: const <String, String>{},
      ).timeout(const Duration(seconds: 30));
      if (signatureResponse.statusCode != HttpStatus.ok ||
          signatureResponse.bodyBytes.isEmpty ||
          signatureResponse.bodyBytes.length > 1024) {
        throw const HttpException(
          'No se pudo descargar una firma RSA válida para el modelo.',
        );
      }

      onProgress?.call('Descargando el modelo firmado de 500 árboles... 📥');
      final modelResponse = await http.get(
        _modelUri,
        headers: const <String, String>{},
      ).timeout(const Duration(seconds: 30));
      if (modelResponse.statusCode != HttpStatus.ok ||
          modelResponse.bodyBytes.isEmpty ||
          modelResponse.bodyBytes.length > _maxModelBytes) {
        modelResponse.bodyBytes.fillRange(
          0,
          modelResponse.bodyBytes.length,
          0,
        );
        throw const HttpException(
          'El modelo público está vacío, excede el tamaño permitido o no está disponible.',
        );
      }

      final expectedDigest = utf8.decode(digestResponse.bodyBytes).trim();
      final modelBytes = Uint8List.fromList(modelResponse.bodyBytes);
      final signatureBytes = Uint8List.fromList(signatureResponse.bodyBytes);
      if (!AuraCryptoLayer.verifySignature(modelBytes, signatureBytes)) {
        modelBytes.fillRange(0, modelBytes.length, 0);
        signatureBytes.fillRange(0, signatureBytes.length, 0);
        return await _integrityFailure(
          'ERROR CRÍTICO: la firma RSA/SHA-256 no es válida; se descartó la descarga y se activaron las reglas locales.',
        );
      }
      final actualDigest = sha256.convert(modelBytes).toString();
      if (!RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(expectedDigest) ||
          actualDigest != expectedDigest.toLowerCase()) {
        modelBytes.fillRange(0, modelBytes.length, 0);
        signatureBytes.fillRange(0, signatureBytes.length, 0);
        return await _integrityFailure(
          'ERROR CRÍTICO: el SHA-256 remoto no coincide; se descartó la descarga y se activaron las reglas locales.',
        );
      }

      onProgress?.call(
        'Validando la estructura, cifrando para este dispositivo e instalando el modelo local... 🧠',
      );
      final supportDirectory = await getApplicationSupportDirectory();
      await AuraAIBrain.installDownloadedModel(
        destination: File(
          '${supportDirectory.path}/aura_brain_model.enc',
        ),
        modelBytes: modelBytes,
        signatureBytes: signatureBytes,
        expectedSha256: expectedDigest,
      );
      return const ToolResult(
        summary:
            'Modelo de 500 árboles verificado, cifrado con la clave del dispositivo e instalado.',
        data: <String, dynamic>{
          'ok': true,
          'model_updated': true,
          'tree_count': 500,
          'sha256_verified': true,
          'security_level': 'safe',
        },
      );
    } on Object catch (error) {
      await AuraAIBrain.useSafeRuleFallback(
        'No se pudo verificar o instalar el modelo remoto; se activaron las reglas locales: $error',
        notifyHud: false,
      );
      return ToolResult(
        summary:
            'ERROR CRÍTICO: no se verificó el modelo remoto; se descartó el búfer y se usarán las reglas locales. $error',
        data: const <String, dynamic>{
          'ok': false,
          'critical_integrity_failure': true,
          'security_level': 'critical',
        },
      );
    }
  }

  static Future<ToolResult> _integrityFailure(String summary) async {
    await AuraAIBrain.useSafeRuleFallback(summary, notifyHud: false);
    return ToolResult(
      summary: summary,
      data: const <String, dynamic>{
        'ok': false,
        'critical_integrity_failure': true,
        'security_level': 'critical',
      },
    );
  }
}
