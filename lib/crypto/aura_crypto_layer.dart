import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:encrypt/encrypt.dart';
import 'package:flutter/foundation.dart'
    show defaultTargetPlatform, TargetPlatform;
import 'package:flutter/services.dart';

class AuraCryptoException implements Exception {
  const AuraCryptoException(this.message, [this.cause]);

  final String message;
  final Object? cause;

  @override
  String toString() => 'AuraCryptoException: $message';
}

abstract final class AuraCryptoLayer {
  static const int _ivLength = 16;
  static const int _aesBlockLength = 16;
  static const int _maxModelPlaintextBytes = 5 * 1024 * 1024;
  static const int _maxModelCiphertextBytes =
      _maxModelPlaintextBytes + _aesBlockLength;
  static const int _sha256Length = 32;
  static const int _rsa2048SignatureLength = 256;
  static const int _hkdfMaximumLength = 255 * _sha256Length;
  static const MethodChannel _nativeCryptoChannel =
      MethodChannel('com.aura.cyberdefense/engine');
  /// Raw Base64 SubjectPublicKeyInfo DER; verification fails closed when unset.
  static const String _auraPublicKeyEnv = String.fromEnvironment(
    'AURA_PUBLIC_KEY',
    defaultValue: '',
  );
  static const List<int> _sha256DigestInfoPrefix = <int>[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
  ];
  static const String _derivationSalt = 'Aura Mobile Defens model key v1';
  static const String _derivationInfo = 'aura-model-aes-256-cbc-pkcs7';

  /// Overwrites this buffer in place; Dart VM copies and immutable values cannot be erased.
  static void secureZeroMemory(Uint8List buffer) {
    buffer.fillRange(0, buffer.length, 0);
  }

  static Uint8List deriveKeyHKDF({
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    int length = _sha256Length,
  }) {
    if (ikm.isEmpty) {
      throw const AuraCryptoException(
        'El material inicial de HKDF no puede estar vacío.',
      );
    }
    if (salt.isEmpty) {
      throw const AuraCryptoException('El salt de HKDF no puede estar vacío.');
    }
    if (length < 1 || length > _hkdfMaximumLength) {
      throw const AuraCryptoException(
        'La longitud solicitada para HKDF-SHA256 no es válida.',
      );
    }

    final hmac = crypto.Hmac(crypto.sha256, salt);
    final pseudoRandomKey = Uint8List.fromList(hmac.convert(ikm).bytes);
    final derivedKey = Uint8List(length);
    var previousBlock = Uint8List(0);
    try {
      var outputOffset = 0;
      for (var counter = 1; outputOffset < length; counter++) {
        final blockInput = Uint8List(
          previousBlock.length + info.length + 1,
        )
          ..setRange(0, previousBlock.length, previousBlock)
          ..setRange(
            previousBlock.length,
            previousBlock.length + info.length,
            info,
          )
          ..[previousBlock.length + info.length] = counter;
        final block = Uint8List.fromList(
          crypto.Hmac(crypto.sha256, pseudoRandomKey)
              .convert(blockInput)
              .bytes,
        );
        secureZeroMemory(blockInput);
        secureZeroMemory(previousBlock);
        previousBlock = block;
        final blockBytesToCopy = length - outputOffset < block.length
            ? length - outputOffset
            : block.length;
        derivedKey.setRange(
          outputOffset,
          outputOffset + blockBytesToCopy,
          block,
        );
        outputOffset += blockBytesToCopy;
      }
      return derivedKey;
    } on Object catch (error) {
      secureZeroMemory(derivedKey);
      throw AuraCryptoException('No se pudo derivar la clave HKDF.', error);
    } finally {
      secureZeroMemory(pseudoRandomKey);
      secureZeroMemory(previousBlock);
    }
  }

  static bool verifySignature(
    Uint8List fileBytes,
    Uint8List signatureBytes,
  ) {
    try {
      if (_auraPublicKeyEnv.isEmpty || fileBytes.isEmpty) return false;
      final publicKey = _parseBase64PublicKey(_auraPublicKeyEnv);
      final modulus = publicKey.$1;
      final exponent = publicKey.$2;
      if (modulus.bitLength != 2048 ||
          signatureBytes.length != _rsa2048SignatureLength) {
        return false;
      }
      final modulusLength = _rsa2048SignatureLength;

      final signatureInteger = _bigIntFromBytes(signatureBytes);
      if (signatureInteger >= modulus) return false;
      final encodedMessage = _bigIntToBytes(
        signatureInteger.modPow(exponent, modulus),
        modulusLength,
      );
      final digest = crypto.sha256.convert(fileBytes).bytes;
      final digestInfo = <int>[
        ..._sha256DigestInfoPrefix,
        ...digest,
      ];
      final paddingLength = modulusLength - digestInfo.length - 3;
      if (paddingLength < 8 ||
          encodedMessage.length != modulusLength ||
          encodedMessage[0] != 0x00 ||
          encodedMessage[1] != 0x01) {
        return false;
      }
      for (var index = 2; index < 2 + paddingLength; index++) {
        if (encodedMessage[index] != 0xff) return false;
      }
      final separatorIndex = 2 + paddingLength;
      if (encodedMessage[separatorIndex] != 0x00) return false;
      final expectedMessage = <int>[
        ...encodedMessage.sublist(0, separatorIndex + 1),
        ...digestInfo,
      ];
      if (expectedMessage.length != encodedMessage.length) return false;

      var difference = 0;
      for (var index = 0; index < encodedMessage.length; index++) {
        difference |= encodedMessage[index] ^ expectedMessage[index];
      }
      return difference == 0;
    } on Object {
      return false;
    }
  }

  static bool verifyModelSignature({
    required Uint8List modelBytes,
    required Uint8List signatureBytes,
  }) =>
      verifySignature(modelBytes, signatureBytes);

  static (BigInt, BigInt) _parseBase64PublicKey(String base64Key) {
    if (base64Key.isEmpty) {
      throw const FormatException(
        'AURA_PUBLIC_KEY está vacía; inyecte la clave pública RSA en Base64 DER.',
      );
    }
    if (!RegExp(r'^[A-Za-z0-9+/]+={0,2}$').hasMatch(base64Key) ||
        base64Key.length % 4 != 0) {
      throw const FormatException(
        'AURA_PUBLIC_KEY debe ser una sola línea de Base64 DER sin PEM.',
      );
    }
    final der = Uint8List.fromList(base64.decode(base64Key));
    final sequence = _readDerElement(der, 0);
    if (sequence.$1 != 0x30 || sequence.$3 != der.length) {
      throw const FormatException('La clave RSA no contiene una secuencia DER.');
    }

    final first = _readDerElement(sequence.$2, 0);
    if (first.$1 == 0x30) {
      final algorithm = first.$2;
      final algorithmOid = _readDerElement(algorithm, 0);
      const rsaEncryptionOid = <int>[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
      ];
      final actualOidDer = _encodeDerElement(algorithmOid.$1, algorithmOid.$2);
      if (!_bytesEqual(actualOidDer, rsaEncryptionOid)) {
        throw const FormatException('El algoritmo DER no es RSA.');
      }
      if (algorithmOid.$3 < algorithm.length) {
        final parameters = _readDerElement(algorithm, algorithmOid.$3);
        if (parameters.$1 != 0x05 ||
            parameters.$2.isNotEmpty ||
            parameters.$3 != algorithm.length) {
          throw const FormatException(
            'Los parámetros de la clave pública RSA no son válidos.',
          );
        }
      }
      final bitString = _readDerElement(sequence.$2, first.$3);
      if (bitString.$1 != 0x03 ||
          bitString.$2.isEmpty ||
          bitString.$2.first != 0 ||
          bitString.$3 != sequence.$2.length) {
        throw const FormatException('El SubjectPublicKeyInfo RSA no es válido.');
      }
      final rsaSequence = Uint8List.sublistView(bitString.$2, 1);
      final innerSequence = _readDerElement(rsaSequence, 0);
      if (innerSequence.$1 != 0x30 ||
          innerSequence.$3 != rsaSequence.length) {
        throw const FormatException('La clave RSA embebida no es válida.');
      }
      return _readRsaIntegers(innerSequence.$2);
    }
    return _readRsaIntegers(sequence.$2);
  }

  static (BigInt, BigInt) _readRsaIntegers(Uint8List sequence) {
    final modulus = _readDerElement(sequence, 0);
    final exponent = _readDerElement(sequence, modulus.$3);
    if (modulus.$1 != 0x02 || exponent.$1 != 0x02 ||
        exponent.$3 != sequence.length ||
        modulus.$2.isEmpty ||
        exponent.$2.isEmpty ||
        !_isCanonicalPositiveInteger(modulus.$2) ||
        !_isCanonicalPositiveInteger(exponent.$2)) {
      throw const FormatException('Los componentes de la clave RSA no son válidos.');
    }
    final modulusValue = _bigIntFromBytes(modulus.$2);
    final exponentValue = _bigIntFromBytes(exponent.$2);
    if (modulusValue.bitLength != 2048 ||
        exponentValue <= BigInt.one ||
        exponentValue.isEven ||
        exponentValue >= modulusValue) {
      throw const FormatException('La clave pública RSA no cumple los parámetros.');
    }
    return (modulusValue, exponentValue);
  }

  static bool _isCanonicalPositiveInteger(Uint8List bytes) {
    if (bytes.isEmpty || (bytes.first & 0x80) != 0) return false;
    return bytes.length == 1 ||
        bytes.first != 0 ||
        (bytes[1] & 0x80) != 0;
  }

  static (int, Uint8List, int) _readDerElement(
    Uint8List bytes,
    int offset,
  ) {
    if (offset < 0 || offset + 2 > bytes.length) {
      throw const FormatException('La estructura DER está truncada.');
    }
    final tag = bytes[offset];
    var cursor = offset + 1;
    final firstLengthByte = bytes[cursor++];
    int contentLength;
    if ((firstLengthByte & 0x80) == 0) {
      contentLength = firstLengthByte;
    } else {
      final lengthByteCount = firstLengthByte & 0x7f;
      if (lengthByteCount == 0 ||
          lengthByteCount > 4 ||
          cursor + lengthByteCount > bytes.length) {
        throw const FormatException('La longitud DER no es válida.');
      }
      contentLength = 0;
      for (var index = 0; index < lengthByteCount; index++) {
        contentLength = (contentLength << 8) | bytes[cursor++];
      }
      if (contentLength < 128) {
        throw const FormatException('La longitud DER no usa codificación mínima.');
      }
    }
    final contentEnd = cursor + contentLength;
    if (contentEnd > bytes.length) {
      throw const FormatException('El contenido DER está truncado.');
    }
    return (
      tag,
      Uint8List.sublistView(bytes, cursor, contentEnd),
      contentEnd,
    );
  }

  static Uint8List _encodeDerElement(int tag, Uint8List value) {
    final lengthBytes = <int>[];
    if (value.length < 128) {
      lengthBytes.add(value.length);
    } else {
      var remaining = value.length;
      final encodedLength = <int>[];
      while (remaining > 0) {
        encodedLength.insert(0, remaining & 0xff);
        remaining >>= 8;
      }
      lengthBytes
        ..add(0x80 | encodedLength.length)
        ..addAll(encodedLength);
    }
    return Uint8List.fromList(<int>[tag, ...lengthBytes, ...value]);
  }

  static BigInt _bigIntFromBytes(Uint8List bytes) {
    var value = BigInt.zero;
    for (final byte in bytes) {
      value = (value << 8) | BigInt.from(byte);
    }
    return value;
  }

  static Uint8List _bigIntToBytes(BigInt value, int length) {
    final bytes = Uint8List(length);
    var remaining = value;
    for (var index = length - 1; index >= 0; index--) {
      bytes[index] = (remaining & BigInt.from(0xff)).toInt();
      remaining >>= 8;
    }
    if (remaining != BigInt.zero) {
      throw const FormatException('El mensaje RSA excede la longitud esperada.');
    }
    return bytes;
  }

  static bool _bytesEqual(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    var difference = 0;
    for (var index = 0; index < left.length; index++) {
      difference |= left[index] ^ right[index];
    }
    return difference == 0;
  }

  static String encryptModel(
    String plaintext,
    String secureKey, {
    IV? iv,
  }) {
    try {
      if (secureKey.isEmpty) {
        throw const AuraCryptoException('La clave segura está vacía.');
      }
      if (jsonDecode(plaintext) is! Map) {
        throw const AuraCryptoException(
          'El plaintext no es un objeto JSON de modelo.',
        );
      }

      final initializationVector = iv ?? IV.fromSecureRandom(_ivLength);
      if (initializationVector.bytes.length != _ivLength) {
        throw const AuraCryptoException('El vector IV AES debe tener 16 bytes.');
      }
      final derivedKey = _deriveKey(secureKey);
      late final Encrypted ciphertext;
      try {
        ciphertext = Encrypter(
          AES(Key(derivedKey), mode: AESMode.cbc, padding: 'PKCS7'),
        ).encrypt(plaintext, iv: initializationVector);
      } finally {
        secureZeroMemory(derivedKey);
      }
      return <int>[
        ...initializationVector.bytes,
        ...ciphertext.bytes,
      ].map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
    } on AuraCryptoException {
      rethrow;
    } on Object catch (error) {
      throw AuraCryptoException('No se pudo cifrar el modelo.', error);
    }
  }

  static String decryptModel(String encryptedHex, String secureKey) {
    try {
      if (secureKey.isEmpty) {
        throw const AuraCryptoException('La clave segura está vacía.');
      }
      if (encryptedHex.isEmpty ||
          encryptedHex.length.isOdd ||
          !RegExp(r'^[0-9a-fA-F]+$').hasMatch(encryptedHex)) {
        throw const AuraCryptoException('El payload hexadecimal no es válido.');
      }

      final payload = Uint8List.fromList(
        List<int>.generate(
          encryptedHex.length ~/ 2,
          (index) => int.parse(
            encryptedHex.substring(index * 2, index * 2 + 2),
            radix: 16,
          ),
          growable: false,
        ),
      );
      try {
        final ciphertextLength = payload.length - _ivLength;
        if (ciphertextLength < _aesBlockLength ||
            ciphertextLength % _aesBlockLength != 0) {
          throw const AuraCryptoException(
            'La longitud del ciphertext AES no es válida.',
          );
        }
        final iv = IV(Uint8List.sublistView(payload, 0, _ivLength));
        final ciphertext = Encrypted(
          Uint8List.sublistView(payload, _ivLength),
        );
        final derivedKey = _deriveKey(secureKey);
        try {
          return Encrypter(
            AES(Key(derivedKey), mode: AESMode.cbc, padding: 'PKCS7'),
          ).decrypt(ciphertext, iv: iv);
        } finally {
          secureZeroMemory(derivedKey);
        }
      } finally {
        secureZeroMemory(payload);
      }
    } on AuraCryptoException {
      rethrow;
    } on Object catch (error) {
      throw AuraCryptoException('No se pudo descifrar el modelo.', error);
    }
  }

  static Future<String> decryptModelSecure(
    String encryptedHex,
    String secureKey,
  ) async {
    if (defaultTargetPlatform != TargetPlatform.android) {
      return decryptModel(encryptedHex, secureKey);
    }

    Uint8List? payload;
    Uint8List? derivedKey;
    Uint8List? ivBytes;
    Uint8List? ciphertext;
    Uint8List? plaintextBytes;
    try {
      if (secureKey.isEmpty ||
          encryptedHex.isEmpty ||
          encryptedHex.length.isOdd ||
          !RegExp(r'^[0-9a-fA-F]+$').hasMatch(encryptedHex)) {
        throw const AuraCryptoException('El payload cifrado no es válido.');
      }

      payload = Uint8List.fromList(
        List<int>.generate(
          encryptedHex.length ~/ 2,
          (index) => int.parse(
            encryptedHex.substring(index * 2, index * 2 + 2),
            radix: 16,
          ),
          growable: false,
        ),
      );
      final ciphertextLength = payload.length - _ivLength;
      if (ciphertextLength < _aesBlockLength ||
          ciphertextLength % _aesBlockLength != 0 ||
          ciphertextLength > _maxModelCiphertextBytes) {
        throw const AuraCryptoException(
          'La longitud del ciphertext AES no es válida.',
        );
      }

      ivBytes = Uint8List.fromList(payload.sublist(0, _ivLength));
      ciphertext = Uint8List.fromList(payload.sublist(_ivLength));
      derivedKey = _deriveKey(secureKey);
      plaintextBytes = await _nativeCryptoChannel.invokeMethod<Uint8List>(
        'decryptModelNative',
        <String, Object>{
          'encryptedData': ciphertext,
          'keyBytes': derivedKey,
          'ivBytes': ivBytes,
        },
      );
      if (plaintextBytes == null || plaintextBytes.isEmpty) {
        throw const AuraCryptoException(
          'El descifrado nativo devolvió un resultado vacío.',
        );
      }
      return utf8.decode(plaintextBytes);
    } on AuraCryptoException {
      rethrow;
    } on Object catch (error) {
      throw AuraCryptoException(
        'No se pudo descifrar el modelo nativamente.',
        error,
      );
    } finally {
      if (payload != null) secureZeroMemory(payload);
      if (derivedKey != null) secureZeroMemory(derivedKey);
      if (ivBytes != null) secureZeroMemory(ivBytes);
      if (ciphertext != null) secureZeroMemory(ciphertext);
      if (plaintextBytes != null) secureZeroMemory(plaintextBytes);
    }
  }

  static Uint8List _deriveKey(String secureKey) {
    final inputKeyMaterial = Uint8List.fromList(utf8.encode(secureKey));
    final salt = Uint8List.fromList(utf8.encode(_derivationSalt));
    final info = Uint8List.fromList(utf8.encode(_derivationInfo));
    try {
      return deriveKeyHKDF(
        ikm: inputKeyMaterial,
        salt: salt,
        info: info,
      );
    } finally {
      secureZeroMemory(inputKeyMaterial);
      secureZeroMemory(salt);
      secureZeroMemory(info);
    }
  }
}
