import 'package:aura_mobile_defens/network_auditor.dart';
import 'package:test/test.dart';

void main() {
  group('NetworkAuditEvent platform events', () {
    test('preserves observed SNI and resolver endpoint metadata', () {
      final event = NetworkAuditEvent.fromPlatform(<String, Object>{
        'timestamp': 123,
        'source_app': 'uid-unavailable',
        'requested_domain': 'dns.google',
        'action': 'SNI_OBSERVED',
        'destination_address': '8.8.8.8',
        'destination_port': 443,
        'transport_protocol': 'TCP',
        'public_dns_resolver': true,
      });

      expect(event.action, NetworkAuditAction.sniObserved);
      expect(event.requestedDomain, 'dns.google');
      expect(event.destinationAddress, '8.8.8.8');
      expect(event.destinationPort, 443);
      expect(event.transportProtocol, 'TCP');
      expect(event.publicDnsResolver, isTrue);
      expect(event.toJson()['action'], 'SNI_OBSERVED');
    });

    test('preserves blocked encrypted DNS endpoint metadata', () {
      final event = NetworkAuditEvent.fromPlatform(<String, Object>{
        'timestamp': 123,
        'source_app': 'uid-unavailable',
        'requested_domain': 'Encrypted DNS attempt',
        'action': 'ENCRYPTED_DNS_BLOCKED',
        'destination_address': '2620:fe::fe',
        'destination_port': 853,
        'transport_protocol': 'UDP',
        'public_dns_resolver': true,
      });

      expect(event.action, NetworkAuditAction.encryptedDnsBlocked);
      expect(event.destinationAddress, '2620:fe::fe');
      expect(event.toJson()['transport_protocol'], 'UDP');
    });

    test('normalizes bracketed IPv6 destination addresses', () {
      final event = NetworkAuditEvent.fromPlatform(<String, Object>{
        'timestamp': 123,
        'source_app': 'uid-unavailable',
        'requested_domain': 'Encrypted DNS attempt',
        'action': 'ENCRYPTED_DNS_BLOCKED',
        'destination_address': '[2001:0db8:0:0:0:0:0:1]',
        'destination_port': 853,
        'transport_protocol': 'UDP',
      });

      expect(event.destinationAddress, '2001:db8::1');
    });

    test('rejects malformed destination IP addresses', () {
      expect(
        () => NetworkAuditEvent.fromPlatform(<String, Object>{
          'timestamp': 123,
          'source_app': 'uid-unavailable',
          'requested_domain': 'dns.google',
          'action': 'SNI_OBSERVED',
          'destination_address': '2001:db8:::1',
        }),
        throwsFormatException,
      );
    });

    test('rejects invalid destination ports', () {
      expect(
        () => NetworkAuditEvent.fromPlatform(<String, Object>{
          'timestamp': 123,
          'source_app': 'uid-unavailable',
          'requested_domain': 'dns.google',
          'action': 'SNI_OBSERVED',
          'destination_port': 70000,
        }),
        throwsFormatException,
      );
    });
  });
}
