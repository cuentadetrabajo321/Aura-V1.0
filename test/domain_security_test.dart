import 'dart:math' as math;

import 'package:aura_mobile_defens/agent/aura_whitelist.dart';
import 'package:aura_mobile_defens/infrastructure/security/aura_dynamic_whitelist.dart';
import 'package:aura_mobile_defens/security/shannon_entropy.dart';
import 'package:test/test.dart';

void main() {
  group('Shannon entropy for DGA detection', () {
    test('empty input has zero entropy', () {
      expect(calculateShannonEntropy(''), 0);
    });

    test('constant input has zero entropy', () {
      expect(calculateShannonEntropy('aaaaaaaa'), 0);
    });

    test('two equally probable symbols have one bit of entropy', () {
      expect(calculateShannonEntropy('abab'), closeTo(1, 1e-12));
    });

    test('four equally probable symbols have two bits of entropy', () {
      expect(calculateShannonEntropy('abcd'), closeTo(2, 1e-12));
    });

    test('computes a non-uniform distribution from Shannon formula', () {
      // For aaab, H = -(3/4 log2(3/4) + 1/4 log2(1/4)).
      final expected =
          -(0.75 * (math.log(0.75) / math.ln2) +
              0.25 * (math.log(0.25) / math.ln2));

      expect(calculateShannonEntropy('aaab'), closeTo(expected, 1e-12));
    });

    test('normalizes character case before counting frequencies', () {
      expect(calculateShannonEntropy('AaBb'), closeTo(1, 1e-12));
    });

    test('a DGA-like hostname exceeds the legitimate-domain entropy', () {
      final legitimateEntropy = calculateShannonEntropy('google.com');
      final dgaEntropy =
          calculateShannonEntropy('q7x2m9v4k1z8p3r6w5n0.biz');

      expect(legitimateEntropy, closeTo(2.6464393446710157, 1e-12));
      expect(dgaEntropy, greaterThan(legitimateEntropy));
      expect(dgaEntropy, greaterThanOrEqualTo(3.8));
    });
  });

  group('AuraWhitelist host boundary checks', () {
    test('allows exact official hosts and valid subdomains', () {
      expect(AuraWhitelist.isSafe('google.com'), isTrue);
      expect(AuraWhitelist.isSafe('https://google.com'), isTrue);
      expect(AuraWhitelist.isSafe('cdn.google.com'), isTrue);
      expect(AuraWhitelist.isSafe('https://cdn.google.com/path'), isTrue);
      expect(AuraWhitelist.isSafe('APPLE.COM.'), isTrue);
    });

    test('does not allow an unrelated attacker domain', () {
      expect(AuraWhitelist.isSafe('attacker.com'), isFalse);
    });

    test('rejects a whitelisted-looking prefix under an attacker domain', () {
      expect(AuraWhitelist.isSafe('google.com.attacker.com'), isFalse);
      expect(AuraWhitelist.isSafe('apple.com.secure-update.net'), isFalse);
      expect(AuraWhitelist.isSafe('notgoogle.com'), isFalse);
    });

    test('rejects user-info tricks whose actual host is not allowlisted', () {
      expect(AuraWhitelist.isSafe('https://google.com@attacker.com'), isFalse);
    });

    test('rejects empty and malformed host input', () {
      expect(AuraWhitelist.isSafe(''), isFalse);
      expect(AuraWhitelist.isSafe('   '), isFalse);
      expect(AuraWhitelist.isSafe('https://'), isFalse);
      expect(AuraWhitelist.isSafe('://google.com'), isFalse);
    });
  });

  group('AuraDynamicWhitelist host boundary checks', () {
    test('validates hosts without throwing on common DNS input', () {
      final whitelist = AuraDynamicWhitelist.instance;

      expect(whitelist.isSafeHost('google.com'), isTrue);
      expect(whitelist.isSafeHost('https://cdn.google.com/path'), isTrue);
      expect(whitelist.isSafeHost('google.com.attacker.com'), isFalse);
      expect(whitelist.isSafeHost('google..com'), isFalse);
    });
  });
}
