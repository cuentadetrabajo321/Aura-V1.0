import 'package:aura_mobile_defens/providers/aura_state_provider.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('AuraStateProvider telemetry severity', () {
    test('does not downgrade a critical state', () {
      final provider = AuraStateProvider();
      provider.setSecurityLevel(AuraSecurityLevel.critical);

      provider.addTelemetryEvent(<String, dynamic>{
        'action': 'BLOCKED',
        'requested_domain': 'malicious.example',
      });

      expect(provider.securityLevel, AuraSecurityLevel.critical);
      provider.dispose();
    });

    test('promotes safe state to warning for a blocked event', () {
      final provider = AuraStateProvider();

      provider.addTelemetryEvent(<String, dynamic>{
        'action': 'DGA_ALERT',
        'requested_domain': 'suspicious.example',
      });

      expect(provider.securityLevel, AuraSecurityLevel.warning);
      provider.dispose();
    });
  });
}
