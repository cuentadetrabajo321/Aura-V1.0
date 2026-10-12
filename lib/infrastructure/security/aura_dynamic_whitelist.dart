import 'dart:convert';
import 'dart:developer' as developer;
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

class AuraDynamicWhitelist {
  AuraDynamicWhitelist._internal();

  static final AuraDynamicWhitelist instance = AuraDynamicWhitelist._internal();

  static const MethodChannel _networkChannel =
      MethodChannel('com.aura.cyberdefense/engine');
  static const int _maximumAllowedHosts = 1000;
  static const int _maximumAllowlistBytes = 1024 * 1024;
  static const String _fileName = 'aura_dynamic_allowlist.json';
  static const Set<String> _staticSuffixes = <String>{
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
  };
  static final RegExp _hostPattern = RegExp(
    r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
    r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$',
  );

  final Set<String> _dynamicAllowedHosts = <String>{};
  Future<void>? _initialization;

  Future<void> initialize() => _initialization ??= _initialize();

  Future<void> _initialize() async {
    try {
      await _loadAllowlist();
    } catch (_) {
      _initialization = null;
      rethrow;
    }
  }

  Future<void> _loadAllowlist() async {
    final directory = await getApplicationSupportDirectory();
    final file = File('${directory.path}/$_fileName');
    final loadedHosts = <String>{};
    if (await file.exists()) {
      final length = await file.length();
      if (length > _maximumAllowlistBytes) {
        throw const FormatException(
          'La allowlist dinámica supera el tamaño permitido.',
        );
      }
      final Object? decoded = jsonDecode(await file.readAsString());
      if (decoded is! List<dynamic> || decoded.length > _maximumAllowedHosts) {
        throw const FormatException(
          'El archivo de allowlist no tiene un formato válido.',
        );
      }

      for (final value in decoded) {
        if (value is! String) {
          throw const FormatException('La allowlist contiene un host no válido.');
        }
        final host = _normalizeHost(value);
        if (host == null) {
          throw const FormatException(
            'La allowlist contiene un host no válido.',
          );
        }
        loadedHosts.add(host);
      }
    }

    _dynamicAllowedHosts
      ..clear()
      ..addAll(loadedHosts);
    await _syncWithNativeFirewall(loadedHosts);
  }

  bool isSafeHost(String rawInput) {
    final host = _normalizeHost(rawInput);
    if (host == null) return false;
    if (_matchesAnySuffix(host, _dynamicAllowedHosts)) return true;
    return _matchesAnySuffix(host, _staticSuffixes);
  }

  Future<bool> addAllowedHost(String rawHost) async {
    await initialize();
    final host = _normalizeHost(rawHost);
    if (host == null || isSafeHost(host)) return false;
    if (_dynamicAllowedHosts.length >= _maximumAllowedHosts) {
      developer.log(
        'Dynamic allowlist capacity reached.',
        name: 'AuraDynamicWhitelist',
        level: 900,
      );
      return false;
    }

    final previous = Set<String>.of(_dynamicAllowedHosts);
    final updated = <String>{...previous, host};
    return _commit(updated, previous);
  }

  Future<bool> revokeAllowedHost(String rawHost) async {
    await initialize();
    final host = _normalizeHost(rawHost);
    if (host == null || !_dynamicAllowedHosts.contains(host)) return false;

    final previous = Set<String>.of(_dynamicAllowedHosts);
    final updated = Set<String>.of(previous)..remove(host);
    return _commit(updated, previous);
  }

  Future<bool> _commit(Set<String> updated, Set<String> previous) async {
    try {
      await _persist(updated);
      await _syncWithNativeFirewall(updated);
      _dynamicAllowedHosts
        ..clear()
        ..addAll(updated);
      return true;
    } on Object catch (error, stackTrace) {
      try {
        await _persist(previous);
      } on Object catch (rollbackError, rollbackStackTrace) {
        developer.log(
          'Could not restore the persisted dynamic allowlist.',
          name: 'AuraDynamicWhitelist',
          error: rollbackError,
          stackTrace: rollbackStackTrace,
          level: 1000,
        );
      }
      developer.log(
        'Could not apply the dynamic allowlist update.',
        name: 'AuraDynamicWhitelist',
        error: error,
        stackTrace: stackTrace,
        level: 1000,
      );
      return false;
    }
  }

  Future<void> _persist(Set<String> hosts) async {
    final directory = await getApplicationSupportDirectory();
    final file = File('${directory.path}/$_fileName');
    final temporaryFile = File('${file.path}.tmp');
    final content = jsonEncode(hosts.toList()..sort());
    await temporaryFile.writeAsString(content, flush: true);
    await temporaryFile.rename(file.path);
  }

  Future<void> _syncWithNativeFirewall(Set<String> hosts) async {
    final synchronized = await _networkChannel.invokeMethod<bool>(
      'setDynamicSniAllowlist',
      <String, Object?>{
        'domains': <String>{..._staticSuffixes, ...hosts}.toList()..sort(),
      },
    );
    if (synchronized != true) {
      throw StateError('El firewall nativo no confirmó la allowlist dinámica.');
    }
  }

  static String? _normalizeHost(String rawInput) {
    var candidate = rawInput.trim().toLowerCase();
    if (candidate.isEmpty) return null;

    if (candidate.contains('://')) {
      final uri = Uri.tryParse(candidate);
      if (uri == null ||
          (uri.scheme != 'http' && uri.scheme != 'https') ||
          uri.userInfo.isNotEmpty) {
        return null;
      }
      candidate = uri.host.toLowerCase();
    } else if (candidate.contains('/') ||
      candidate.contains('\\') ||
      candidate.contains('?') ||
      candidate.contains('#') ||
      candidate.contains('@') ||
      candidate.contains(':') ||
      candidate.contains('%')) {
      return null;
    }

    if (candidate.endsWith('.')) {
      candidate = candidate.substring(0, candidate.length - 1);
    }
    if (!_hostPattern.hasMatch(candidate) ||
        InternetAddress.tryParse(candidate) != null) {
      return null;
    }
    return candidate;
  }

  static bool _matchesAnySuffix(String host, Iterable<String> suffixes) {
    for (final suffix in suffixes) {
      if (host == suffix || host.endsWith('.$suffix')) return true;
    }
    return false;
  }
}
