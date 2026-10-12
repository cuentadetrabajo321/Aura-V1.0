import 'package:aura_mobile_defens/providers/aura_state_provider.dart';
import 'package:aura_mobile_defens/screens/aura_core_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('activates and stops VPN through the native shield channel', (
    tester,
  ) async {
    const shieldChannel = MethodChannel('com.ciberdefensa.aura/shield');
    const biometricChannel = MethodChannel('com.aura.cyberdefense/biometrics');
    const networkEventChannel =
        EventChannel('com.aura.cyberdefense/network_stream');
    final calls = <String>[];
    final state = AuraStateProvider();
    MockStreamHandlerEventSink? networkEventSink;
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    addTearDown(() {
      messenger.setMockMethodCallHandler(shieldChannel, null);
      messenger.setMockMethodCallHandler(biometricChannel, null);
      messenger.setMockStreamHandler(networkEventChannel, null);
      state.dispose();
    });
    messenger.setMockMethodCallHandler(biometricChannel, (_) async => true);
    messenger.setMockMethodCallHandler(shieldChannel, (call) async {
      calls.add(call.method);
      return true;
    });
    messenger.setMockStreamHandler(
      networkEventChannel,
      MockStreamHandler.inline(
        onListen: (_, events) {
          networkEventSink = events;
        },
      ),
    );

    await tester.pumpWidget(
      ChangeNotifierProvider<AuraStateProvider>.value(
        value: state,
        child: const MaterialApp(home: AuraCoreScreen()),
      ),
    );
    await tester.pumpAndSettle();

    expect(networkEventSink, isNotNull);
    networkEventSink!.success(<String, Object>{
      'timestamp': 1,
      'source_app': 'com.example.app',
      'requested_domain': 'example.com',
      'action': 'ALLOWED',
    });
    await tester.pump();
    expect(state.telemetryEvents.single['requested_domain'], 'example.com');

    expect(find.byTooltip('Activar escudo VPN'), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey<String>('vpn-toggle')));
    await tester.pumpAndSettle();
    expect(calls, <String>['startShield']);
    expect(state.isVpnActive, isTrue);

    await tester.tap(find.byKey(const ValueKey<String>('vpn-toggle')));
    await tester.pumpAndSettle();
    expect(calls, <String>['startShield', 'stopShield']);
    expect(state.isVpnActive, isFalse);
  });
}
