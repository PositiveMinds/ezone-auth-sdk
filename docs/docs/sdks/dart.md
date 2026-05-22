---
id: dart
title: Dart / Flutter
---

# Dart SDK

Pure Dart HTTP client with no dependencies beyond `http`. Works in Flutter (iOS, Android, Web, Desktop) and server-side Dart.

## Installation

```yaml title="pubspec.yaml"
dependencies:
  ezone_sdk: ^0.1.0
```

```bash
flutter pub get
```

## Quick start

```dart
import 'package:ezone_sdk/ezone_sdk.dart';

final client = EzoneClient(baseUrl: 'https://auth.yourapp.com');

// Registration
final reg = await client.beginRegistration(email: 'alice@example.com');
print(reg.magicToken);

// Login
final ch = await client.beginLogin(email: 'alice@example.com');
// sign ch.challenge with device key...

final session = await client.completeLogin(
  email: 'alice@example.com',
  challenge: ch.challenge,
  signature: '<base64url sig>',
  devicePublicKey: '<base64url SPKI DER>',
);
print(session.token);
```

## Flutter integration

```dart
// auth_provider.dart
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ezone_sdk/ezone_sdk.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

final ezoneProvider = Provider((ref) => EzoneClient(
  baseUrl: const String.fromEnvironment('EZONE_URL'),
));

final sessionProvider = StateNotifierProvider<SessionNotifier, AsyncValue<Session?>>((ref) {
  return SessionNotifier(ref.watch(ezoneProvider));
});

class SessionNotifier extends StateNotifier<AsyncValue<Session?>> {
  final EzoneClient _client;
  final _storage = const FlutterSecureStorage();

  SessionNotifier(this._client) : super(const AsyncValue.loading()) {
    _loadSaved();
  }

  Future<void> _loadSaved() async {
    final token = await _storage.read(key: 'ezone_token');
    if (token == null) {
      state = const AsyncValue.data(null);
      return;
    }
    try {
      final info = await _client.verifySession(token);
      state = AsyncValue.data(Session(token: token, info: info));
    } catch (_) {
      state = const AsyncValue.data(null);
    }
  }

  Future<void> login(String email, DeviceKey deviceKey) async {
    state = const AsyncValue.loading();
    final ch = await _client.beginLogin(email: email);
    final signature = await deviceKey.sign(ch.challenge);
    final session = await _client.completeLogin(
      email: email,
      challenge: ch.challenge,
      signature: signature,
      devicePublicKey: await deviceKey.publicKey,
    );
    await _storage.write(key: 'ezone_token', value: session.token);
    state = AsyncValue.data(Session(token: session.token));
  }

  Future<void> logout() async {
    await _storage.delete(key: 'ezone_token');
    state = const AsyncValue.data(null);
  }
}
```

## Device keys on Flutter

```dart
import 'package:ezone_sdk/device_key.dart';

// Generates a P-384 keypair and stores it in flutter_secure_storage
final deviceKey = await EzoneDeviceKey.getOrCreate(userId: 'user_abc123');

final publicKey = await deviceKey.publicKey;    // base64url SPKI DER
final signature = await deviceKey.sign(challenge); // base64url
```

## Full API

```dart
class EzoneClient {
  EzoneClient({required String baseUrl, Duration timeout = const Duration(seconds: 10)});

  Future<BeginRegistrationResponse> beginRegistration({required String email});
  Future<SessionResponse> completeRegistration({
    required String magicToken,
    required String devicePublicKey,
    required String deviceName,
  });

  Future<BeginLoginResponse> beginLogin({required String email});
  Future<SessionResponse> completeLogin({
    required String email,
    required String challenge,
    required String signature,
    required String devicePublicKey,
  });

  Future<SessionInfo> verifySession(String token);
  Future<SessionResponse> refreshSession(String token);
  Future<void> logout(String token);

  Future<BeginResetResponse> beginReset({required String email});
  Future<SessionResponse> completeReset({...});

  Future<List<String>> generateRecoveryCodes(String token);
  Future<SessionResponse> recoverWithCode({...});

  Future<List<Device>> listDevices(String token);
  Future<BeginAddDeviceResponse> beginAddDevice(String token);
  Future<Device> completeAddDevice({...});
  Future<void> revokeDevice(String token, String deviceId);
}
```
