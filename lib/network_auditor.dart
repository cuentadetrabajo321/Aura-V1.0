import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

import 'ai_brain.dart';
import 'secure_vault.dart';

enum NetworkAuditAction {
  blocked,
  dgaAlert,
  allowed,
  sniObserved,
  encryptedDnsBlocked,
}

class NetworkAuditEvent {
  const NetworkAuditEvent({
    required this.timestamp,
    required this.sourceApp,
    required this.requestedDomain,
    required this.action,
    this.destinationAddress,
    this.destinationPort,
    this.transportProtocol,
    this.publicDnsResolver = false,
  });

  final int timestamp;
  final String sourceApp;
  final String requestedDomain;
  final NetworkAuditAction action;
  final String? destinationAddress;
  final int? destinationPort;
  final String? transportProtocol;
  final bool publicDnsResolver;

  factory NetworkAuditEvent.fromPlatform(Object? value) {
    if (value is! Map) {
      throw const FormatException('El evento de red no es un mapa.');
    }

    final timestamp = value['timestamp'];
    final sourceApp = value['source_app'];
    final requestedDomain = value['requested_domain'];
    final action = value['action'];
    final destinationAddress = value['destination_address'];
    final destinationPort = value['destination_port'];
    final transportProtocol = value['transport_protocol'];
    final publicDnsResolver = value['public_dns_resolver'];
    final normalizedDestination = destinationAddress is String
        ? _normalizeIpAddress(destinationAddress)
        : null;
    if (timestamp is! num || sourceApp is! String ||
      requestedDomain is! String ||
      (action != 'BLOCKED' && action != 'DGA_ALERT' && action != 'ALLOWED' &&
          action != 'SNI_OBSERVED' && action != 'ENCRYPTED_DNS_BLOCKED') ||
      (destinationAddress != null && destinationAddress is! String) ||
      (destinationAddress is String && normalizedDestination == null) ||
      (destinationPort != null &&
          (destinationPort is! num ||
              !destinationPort.isFinite ||
              destinationPort % 1 != 0 ||
              destinationPort < 1 ||
              destinationPort > 65535)) ||
      (transportProtocol != null && transportProtocol is! String) ||
      (publicDnsResolver != null && publicDnsResolver is! bool)) {
      throw const FormatException('El evento de red tiene campos inválidos.');
    }

    return NetworkAuditEvent(
      timestamp: timestamp.toInt(),
      sourceApp: sourceApp,
      requestedDomain: requestedDomain,
      destinationAddress: normalizedDestination,
      destinationPort: (destinationPort as num?)?.toInt(),
      transportProtocol: transportProtocol as String?,
      publicDnsResolver: publicDnsResolver as bool? ?? false,
      action: switch (action) {
        'BLOCKED' => NetworkAuditAction.blocked,
        'DGA_ALERT' => NetworkAuditAction.dgaAlert,
        'SNI_OBSERVED' => NetworkAuditAction.sniObserved,
        'ENCRYPTED_DNS_BLOCKED' => NetworkAuditAction.encryptedDnsBlocked,
        _ => NetworkAuditAction.allowed,
      },
    );
  }

  Map<String, Object> toJson() {
    final value = <String, Object>{
      'timestamp': timestamp,
      'source_app': sourceApp,
      'requested_domain': requestedDomain,
      'action': switch (action) {
        NetworkAuditAction.blocked => 'BLOCKED',
        NetworkAuditAction.dgaAlert => 'DGA_ALERT',
        NetworkAuditAction.allowed => 'ALLOWED',
        NetworkAuditAction.sniObserved => 'SNI_OBSERVED',
        NetworkAuditAction.encryptedDnsBlocked => 'ENCRYPTED_DNS_BLOCKED',
      },
      'public_dns_resolver': publicDnsResolver,
    };
    if (destinationAddress case final address?) {
      value['destination_address'] = address;
    }
    if (destinationPort case final port?) {
      value['destination_port'] = port;
    }
    if (transportProtocol case final protocol?) {
      value['transport_protocol'] = protocol;
    }
    return value;
  }
}

String? _normalizeIpAddress(String input) {
  var candidate = input.trim();
  if (candidate.startsWith('[') && candidate.endsWith(']')) {
    candidate = candidate.substring(1, candidate.length - 1);
  }
  return InternetAddress.tryParse(candidate)?.address;
}

class AuraNetworkAuditor {
  static const EventChannel _networkEvents =
      EventChannel('com.aura.cyberdefense/network_stream');
    static const MethodChannel _engineChannel =
      MethodChannel('com.aura.cyberdefense/engine');
  static const int _maxRecentEvents = 500;
  static const int _maxPendingWrites = 256;
  static const int _writeBatchSize = 32;

  final StreamController<bool> _networkShieldController =
      StreamController<bool>.broadcast();
  final StreamController<NetworkAuditEvent> _eventController =
      StreamController<NetworkAuditEvent>.broadcast();
  final Queue<NetworkAuditEvent> _recentEvents = Queue<NetworkAuditEvent>();
  final Queue<Map<String, Object>> _pendingWrites =
      Queue<Map<String, Object>>();
    final Queue<NetworkAuditEvent> _pendingThreatEvents =
      Queue<NetworkAuditEvent>();
  final AuraSecureVault _secureVault;
    late final AuraAIBrain _aiBrain;

  StreamSubscription<Object?>? _nativeSubscription;
  Future<void> _writeTask = Future<void>.value();
  bool _writing = false;
  bool _analyzingThreats = false;
  bool _disposed = false;
  int _droppedPendingWrites = 0;

  AuraNetworkAuditor({AuraSecureVault? secureVault, AuraAIBrain? aiBrain})
      : _secureVault = secureVault ?? AuraSecureVault() {
    _aiBrain = aiBrain ?? AuraAIBrain();
    _aiBrain.setDnsBlockRuleHandler(addDnsBlockRule);
    start();
  }

  Stream<bool> get shieldStateStream => _networkShieldController.stream;
  Stream<NetworkAuditEvent> get eventStream => _eventController.stream;
  int get recentEventCount => _recentEvents.length;
  int get droppedPendingWrites => _droppedPendingWrites;

  void start() {
    if (_disposed || _nativeSubscription != null) return;
    _nativeSubscription = _networkEvents.receiveBroadcastStream().listen(
      _handlePlatformEvent,
      onError: (Object error, StackTrace stackTrace) {
        if (!_disposed) _eventController.addError(error, stackTrace);
      },
    );
  }

  void toggleNetworkShield(bool active) {
    if (!_disposed) _networkShieldController.add(active);
  }

  Future<bool> verifyGatewaySafety() async {
    try {
      final addresses = await InternetAddress.lookup('cloudflare.com');
      return addresses.isNotEmpty &&
          addresses.any((address) => address.rawAddress.isNotEmpty);
    } on SocketException {
      return false;
    }
  }

  String buildTelemetryPayload({int limit = 100}) {
    if (limit < 1 || limit > _maxRecentEvents) {
      throw RangeError.range(limit, 1, _maxRecentEvents, 'limit');
    }
    final events = _recentEvents.toList();
    final selected = events.skip(events.length > limit ? events.length - limit : 0);
    return jsonEncode({
      'event_type': 'network_dns_audit',
      'events': selected.map((event) => event.toJson()).toList(),
    });
  }

    Future<String> analyzeRecentNetworkEvents({int limit = 100}) =>
      _aiBrain.analyzeThreatPayload(buildTelemetryPayload(limit: limit));

  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    await _nativeSubscription?.cancel();
    _nativeSubscription = null;
    await _writeTask;
    await _eventController.close();
    await _networkShieldController.close();
    _pendingThreatEvents.clear();
  }

  void _handlePlatformEvent(Object? value) {
    if (_disposed) return;

    late final NetworkAuditEvent event;
    try {
      event = NetworkAuditEvent.fromPlatform(value);
    } on FormatException catch (error, stackTrace) {
      _eventController.addError(error, stackTrace);
      return;
    }
    if (_recentEvents.length == _maxRecentEvents) _recentEvents.removeFirst();
    _recentEvents.addLast(event);
    _eventController.add(event);

    if (event.action == NetworkAuditAction.blocked ||
        event.action == NetworkAuditAction.dgaAlert ||
        event.action == NetworkAuditAction.sniObserved) {
      if (_pendingThreatEvents.length < 64) {
        _pendingThreatEvents.addLast(event);
      }
      _analyzePendingThreats();
    }

    if (_pendingWrites.length == _maxPendingWrites) {
      _pendingWrites.removeFirst();
      _droppedPendingWrites++;
    }
    _pendingWrites.addLast(event.toJson());
    _drainWrites();
  }

  Future<bool> addDnsBlockRule(String domain) async {
    final blocked = await _engineChannel.invokeMethod<bool>(
      'addDnsBlockRule',
      {'domain': domain},
    );
    return blocked ?? false;
  }

  void _analyzePendingThreats() {
    if (_analyzingThreats || _disposed || _pendingThreatEvents.isEmpty) return;
    _analyzingThreats = true;
    unawaited(_drainThreatAnalysis());
  }

  Future<void> _drainThreatAnalysis() async {
    try {
      while (!_disposed && _pendingThreatEvents.isNotEmpty) {
        final event = _pendingThreatEvents.removeFirst();
        try {
          await _aiBrain.analyzeThreatPayload(jsonEncode(event.toJson()));
        } catch (error, stackTrace) {
          if (!_disposed) _eventController.addError(error, stackTrace);
        }
      }
    } finally {
      _analyzingThreats = false;
      if (!_disposed && _pendingThreatEvents.isNotEmpty) {
        _analyzePendingThreats();
      }
    }
  }

  void _drainWrites() {
    if (_writing || _pendingWrites.isEmpty) return;
    _writing = true;
    _writeTask = _writePendingEvents();
  }

  Future<void> _writePendingEvents() async {
    try {
      while (_pendingWrites.isNotEmpty) {
        final batch = <String>[];
        while (_pendingWrites.isNotEmpty && batch.length < _writeBatchSize) {
          batch.add(jsonEncode(_pendingWrites.removeFirst()));
        }
        try {
          await _secureVault.writeLogsSecurely(batch);
        } catch (_) {
          _droppedPendingWrites += batch.length;
        }
      }
    } finally {
      _writing = false;
      if (_pendingWrites.isNotEmpty) _drainWrites();
    }
  }
}