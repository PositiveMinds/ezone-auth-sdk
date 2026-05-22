import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/export.dart';

class EzoneDeviceKey {
  final ECPrivateKey _privateKey;
  final ECPublicKey  _publicKey;

  EzoneDeviceKey._(this._privateKey, this._publicKey);

  static const _storage = FlutterSecureStorage();

  static Future<EzoneDeviceKey> getOrCreate(String userId) async {
    final privPem = await _storage.read(key: 'ezone_key_$userId');
    if (privPem != null) {
      return _fromPem(privPem);
    }
    final key = _generate();
    await _storage.write(key: 'ezone_key_$userId', value: _toPem(key._privateKey));
    return key;
  }

  static EzoneDeviceKey _generate() {
    final params = ECDomainParameters('prime384v1');
    final gen = ECKeyGenerator()
      ..init(ParametersWithRandom(
        ECKeyGeneratorParameters(params),
        SecureRandom('Fortuna'),
      ));
    final pair = gen.generateKeyPair();
    return EzoneDeviceKey._(
      pair.privateKey as ECPrivateKey,
      pair.publicKey  as ECPublicKey,
    );
  }

  // Public key as base64url-encoded SPKI DER
  Future<String> get publicKey async {
    final spki = _buildSpki(_publicKey);
    return base64Url.encode(spki).replaceAll('=', '');
  }

  // Sign a base64url-encoded challenge, return base64url DER signature
  Future<String> sign(String challengeBase64url) async {
    final padded = _padBase64(challengeBase64url);
    final data   = base64Url.decode(padded);

    final signer = Signer('SHA-384/ECDSA')
      ..init(true, PrivateKeyParameter<ECPrivateKey>(_privateKey));
    final sig = signer.generateSignature(Uint8List.fromList(data)) as ECSignature;

    final der = _encodeDerSignature(sig);
    return base64Url.encode(der).replaceAll('=', '');
  }

  static Uint8List _buildSpki(ECPublicKey key) {
    final q = key.Q!;
    final x = _bigIntToBytes(q.x!.toBigInteger()!, 48);
    final y = _bigIntToBytes(q.y!.toBigInteger()!, 48);

    // OID for id-ecPublicKey + OID for P-384
    const oidHeader = [
      0x30, 0x76,
      0x30, 0x10,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
      0x03, 0x62, 0x00, 0x04,
    ];

    return Uint8List.fromList([...oidHeader, ...x, ...y]);
  }

  static Uint8List _bigIntToBytes(BigInt n, int length) {
    final hex = n.toRadixString(16).padLeft(length * 2, '0');
    return Uint8List.fromList(
      List.generate(length, (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16)),
    );
  }

  static Uint8List _encodeDerSignature(ECSignature sig) {
    Uint8List encodeInt(BigInt n) {
      var bytes = _bigIntToBytes(n, (n.bitLength + 7) ~/ 8);
      if (bytes[0] & 0x80 != 0) bytes = Uint8List.fromList([0, ...bytes]);
      return Uint8List.fromList([0x02, bytes.length, ...bytes]);
    }
    final r = encodeInt(sig.r);
    final s = encodeInt(sig.s);
    return Uint8List.fromList([0x30, r.length + s.length, ...r, ...s]);
  }

  static String _toPem(ECPrivateKey key) =>
      base64.encode(key.d!.toRadixString(16).codeUnits);

  static EzoneDeviceKey _fromPem(String pem) {
    final hex = String.fromCharCodes(base64.decode(pem));
    final d = BigInt.parse(hex, radix: 16);
    final params = ECDomainParameters('prime384v1');
    final priv = ECPrivateKey(d, params);
    final pub  = ECPublicKey(params.G * d, params);
    return EzoneDeviceKey._(priv, pub);
  }

  static String _padBase64(String s) {
    while (s.length % 4 != 0) s += '=';
    return s.replaceAll('-', '+').replaceAll('_', '/');
  }
}
