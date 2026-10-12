import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../agent/agent_controller.dart';
import '../agent/agent_event.dart';
import '../ai_brain.dart';
import '../infrastructure/agent/aura_intent_parser.dart';
import '../network_auditor.dart';
import '../providers/aura_state_provider.dart';

const Color _terminalGreen = Color(0xFF00FF00);
const Color _terminalYellow = Color(0xFFFFFF00);

class AuraCoreScreen extends StatefulWidget {
  const AuraCoreScreen({super.key});

  @override
  State<AuraCoreScreen> createState() => _AuraCoreScreenState();
}

class _AuraCoreScreenState extends State<AuraCoreScreen> {
  static const MethodChannel _voiceChannel =
      MethodChannel('com.ciberdefensa.aura/voice');
  static const MethodChannel _shieldChannel =
      MethodChannel('com.ciberdefensa.aura/shield');

  final TextEditingController _inputController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  AuraNetworkAuditor? _networkAuditor;
  StreamSubscription<NetworkAuditEvent>? _networkEventSubscription;
  bool _isListening = false;
  bool _isRunning = false;
  bool _isShieldBusy = false;
  bool _isAuthenticated = false;
  bool _authenticationFailed = false;
  int _lastRenderedEventCount = -1;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _authenticateConsole();
    });
  }

  Future<void> _authenticateConsole() async {
    final controller = AgentController.instance;
    controller.bindSecurityState(context.read<AuraStateProvider>());
    final authenticated = await controller.authenticateBiometricDevice();
    if (!mounted) return;
    if (authenticated) {
      controller.initGreeting();
      _startNetworkAuditor();
      setState(() => _isAuthenticated = true);
      return;
    }

    controller.reportCriticalError(
      'PÁNICO CRÍTICO: AUTENTICACIÓN BIOMÉTRICA DENEGADA. CONSOLA BLOQUEADA.',
    );
    setState(() => _authenticationFailed = true);
    await Future<void>.delayed(const Duration(seconds: 2));
    if (mounted) await SystemNavigator.pop();
  }

  @override
  void dispose() {
    _scrollController.dispose();
    _inputController.dispose();
    unawaited(_disposeNetworkAuditor());
    super.dispose();
  }

  void _startNetworkAuditor() {
    if (_networkAuditor != null) return;
    final state = context.read<AuraStateProvider>();
    final auditor = AuraNetworkAuditor(
      aiBrain: AuraAIBrain(stateProvider: state),
    );
    _networkAuditor = auditor;
    _networkEventSubscription = auditor.eventStream.listen(
      (event) => state.addTelemetryEvent(event.toJson()),
      onError: (Object error, StackTrace stackTrace) {
        AgentController.instance.reportWarning(
          'No se pudo leer la telemetría DNS local: $error',
        );
      },
    );
  }

  Future<void> _disposeNetworkAuditor() async {
    await _networkEventSubscription?.cancel();
    await _networkAuditor?.dispose();
    _networkEventSubscription = null;
    _networkAuditor = null;
  }

  Future<void> _dispatch(String text) async {
    final instruction = text.trim();
    if (instruction.isEmpty || _isRunning) return;
    _inputController.clear();
    setState(() => _isRunning = true);
    try {
      final controller = AgentController.instance;
      controller.reportTerminalInput(instruction);
      _scrollToLatest(controller.history.length, force: true);

      for (var second = 0; second < 3; second++) {
        await Future<void>.delayed(const Duration(seconds: 1));
        if (!mounted) return;
        controller.reportTerminalThinking();
        _scrollToLatest(controller.history.length, force: true);
      }

      final result = await AuraIntentParser.executeCommand(instruction);
      final response = result['response'];
      if (response is String) {
        final notificationSent = await controller.dispatchRealtimeNotification(
          'Aura Mobile Defens',
          response,
        );
        if (!notificationSent && mounted) {
          controller.reportWarning(
            'Alerta no publicada: Android denegó el permiso o el servicio foreground.',
          );
        }
      }
      if (mounted) {
        _scrollToLatest(controller.history.length, force: true);
      }
    } finally {
      if (mounted) setState(() => _isRunning = false);
    }
  }

  Future<void> _captureVoice() async {
    if (_isListening || _isRunning) return;
    setState(() => _isListening = true);
    try {
      final transcript = await _voiceChannel.invokeMethod<String>(
        'startListening',
      );
      if (!mounted || transcript == null || transcript.trim().isEmpty) return;
      _inputController.text = transcript.trim();
      await _dispatch(transcript);
    } on PlatformException catch (error) {
      if (mounted) {
        context.read<AuraStateProvider>().setSecurityLevel(
              AuraSecurityLevel.warning,
            );
        AgentController.instance.reportError(
          error.message ?? 'No se pudo capturar el comando de voz.',
        );
      }
    } on MissingPluginException {
      if (mounted) {
        context.read<AuraStateProvider>().setSecurityLevel(
              AuraSecurityLevel.warning,
            );
        AgentController.instance.reportError(
          'El reconocimiento de voz no está disponible.',
        );
      }
    } finally {
      if (mounted) setState(() => _isListening = false);
    }
  }

  Future<void> _toggleShield() async {
    if (_isShieldBusy || !_isAuthenticated) return;
    final state = context.read<AuraStateProvider>();
    final wasActive = state.isVpnActive;
    setState(() => _isShieldBusy = true);
    try {
      final confirmed = await _shieldChannel.invokeMethod<bool>(
            wasActive ? 'stopShield' : 'startShield',
          ) ??
          false;
      if (!confirmed) {
        AgentController.instance.reportWarning(
          wasActive
              ? 'Android no confirmó la detención del escudo VPN.'
              : 'El escudo VPN no se inició; no se confirmó el consentimiento o el servicio.',
        );
        return;
      }

      state.setVpnActive(!wasActive);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              wasActive ? 'Escudo VPN detenido.' : 'Escudo VPN activo.',
            ),
            duration: const Duration(seconds: 2),
          ),
        );
      }
    } on PlatformException catch (error) {
      AgentController.instance.reportError(
        error.message ?? 'Android rechazó la operación del escudo VPN.',
      );
    } on MissingPluginException {
      AgentController.instance.reportError(
        'El canal nativo del escudo VPN no está disponible.',
      );
    } finally {
      if (mounted) setState(() => _isShieldBusy = false);
    }
  }

  void _scrollToLatest(int eventCount, {bool force = false}) {
    if (!force && eventCount == _lastRenderedEventCount) return;
    _lastRenderedEventCount = eventCount;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_scrollController.hasClients) return;
      _scrollController.jumpTo(_scrollController.position.maxScrollExtent);
    });
  }

  @override
  Widget build(BuildContext context) {
    final vpnActive = context.watch<AuraStateProvider>().isVpnActive;
    return Scaffold(
      backgroundColor: const Color(0xFF000000),
      resizeToAvoidBottomInset: true,
      body: SafeArea(
        child: Column(
          children: [
            const SizedBox(height: 48),
            Row(
              children: [
                const SizedBox(width: 48),
                const Expanded(
                  child: Text(
                    'Aura Mobile Defens',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: Color(0xFF00FFFF),
                      fontFamily: 'monospace',
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                IconButton(
                  key: const ValueKey<String>('vpn-toggle'),
                  tooltip: vpnActive ? 'Detener escudo VPN' : 'Activar escudo VPN',
                  onPressed: _isAuthenticated && !_isShieldBusy
                      ? _toggleShield
                      : null,
                  constraints:
                      const BoxConstraints.tightFor(width: 48, height: 48),
                  icon: _isShieldBusy
                      ? const SizedBox.square(
                          dimension: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : Icon(
                          vpnActive ? Icons.shield : Icons.shield_outlined,
                          color: vpnActive ? _terminalGreen : _terminalYellow,
                        ),
              ),
              ],
            ),
            const SizedBox(height: 16),
            Expanded(
              child: _isAuthenticated || _authenticationFailed
                  ? StreamBuilder<AgentEvent>(
                      stream: AgentController.instance.events,
                      builder: (context, snapshot) {
                        final events = AgentController.instance.history;
                        _scrollToLatest(events.length);
                        return ListView.builder(
                          controller: _scrollController,
                          padding: const EdgeInsets.fromLTRB(14, 14, 14, 18),
                          itemCount: events.length,
                          itemBuilder: (context, index) =>
                              _SyslogLine(event: events[index]),
                        );
                      },
                    )
                  : const SizedBox.expand(),
            ),
            _TerminalInput(
              controller: _inputController,
              isListening: _isListening,
              isRunning: _isRunning || !_isAuthenticated,
              onSubmitted: _dispatch,
              onVoice: _captureVoice,
            ),
          ],
        ),
      ),
    );
  }
}

class _SyslogLine extends StatelessWidget {
  const _SyslogLine({required this.event});

  final AgentEvent event;

  @override
  Widget build(BuildContext context) {
    final terminalPrefix = event.data?['terminal_prefix'] as String?;
    final isThinking = event.data?['terminal_thinking'] == true;
    final defaultPrefix = switch (event.kind) {
      AgentEventKind.thought => '[  INF  ] ',
      AgentEventKind.action => '[  NET  ] ',
      AgentEventKind.success => '[  OK   ] ',
      AgentEventKind.warning => '[  WARN ] ',
      AgentEventKind.error => '[  CRIT ] ',
    };
    final prefix = terminalPrefix ?? defaultPrefix;
    final color = isThinking ? _terminalYellow : _terminalGreen;
    final timestamp = '${event.ts.hour.toString().padLeft(2, '0')}:'
        '${event.ts.minute.toString().padLeft(2, '0')}:'
        '${event.ts.second.toString().padLeft(2, '0')}';

    return Padding(
      padding: const EdgeInsets.only(bottom: 11),
      child: SelectableText.rich(
        TextSpan(
          children: [
            TextSpan(
              text: '$timestamp ',
              style: const TextStyle(color: _terminalGreen),
            ),
            TextSpan(
              text: prefix,
              style: TextStyle(color: color, fontWeight: FontWeight.w700),
            ),
            TextSpan(
              text: event.message,
              style: TextStyle(color: color),
            ),
          ],
        ),
        style: const TextStyle(
          fontFamily: 'monospace',
          fontSize: 12,
          height: 1.45,
        ),
      ),
    );
  }
}

class _TerminalInput extends StatelessWidget {
  const _TerminalInput({
    required this.controller,
    required this.isListening,
    required this.isRunning,
    required this.onSubmitted,
    required this.onVoice,
  });

  final TextEditingController controller;
  final bool isListening;
  final bool isRunning;
  final ValueChanged<String> onSubmitted;
  final VoidCallback onVoice;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.fromLTRB(12, 9, 10, 8),
      decoration: const BoxDecoration(
        color: const Color(0xFF000000),
        border: Border(top: BorderSide(color: Color(0xFF17352B))),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Expanded(
            child: TextField(
              controller: controller,
              enabled: !isRunning,
              autofocus: true,
              textInputAction: TextInputAction.send,
              onSubmitted: onSubmitted,
              cursorColor: _terminalGreen,
              style: const TextStyle(
                color: _terminalGreen,
                fontFamily: 'monospace',
                fontSize: 12,
              ),
              decoration: const InputDecoration(
                hintText: 'comando o consulta táctica',
                hintStyle: TextStyle(
                  color: _terminalGreen,
                  fontFamily: 'monospace',
                ),
                border: InputBorder.none,
                isDense: true,
                contentPadding: EdgeInsets.symmetric(vertical: 9),
              ),
            ),
          ),
          IconButton(
            tooltip: isListening ? 'Escuchando' : 'Dictar consulta',
            onPressed: isRunning || isListening ? null : onVoice,
            constraints: const BoxConstraints.tightFor(width: 38, height: 38),
            padding: EdgeInsets.zero,
            icon: Icon(
              isListening ? Icons.hearing : Icons.mic_none,
              color: _terminalGreen,
              size: 18,
            ),
          ),
        ],
      ),
    );
  }
}
