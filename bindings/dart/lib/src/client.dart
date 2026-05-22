import 'dart:convert';
import 'package:http/http.dart' as http;

class EzoneError implements Exception {
  final int statusCode;
  final String message;
  EzoneError(this.statusCode, this.message);
  @override
  String toString() => 'EzoneError($statusCode): $message';
}

class SessionResponse {
  final String token;
  final int expiresAt;
  final String? userId;
  final String? deviceId;

  SessionResponse({
    required this.token,
    required this.expiresAt,
    this.userId,
    this.deviceId,
  });

  factory SessionResponse.fromJson(Map<String, dynamic> j) => SessionResponse(
        token:     j['token'] as String,
        expiresAt: j['expires_at'] as int,
        userId:    j['user_id'] as String?,
        deviceId:  j['device_id'] as String?,
      );
}

class SessionInfo {
  final String userId;
  final String email;
  final int expiresAt;

  SessionInfo({required this.userId, required this.email, required this.expiresAt});

  factory SessionInfo.fromJson(Map<String, dynamic> j) => SessionInfo(
        userId:    j['user_id'] as String,
        email:     j['email'] as String,
        expiresAt: j['expires_at'] as int,
      );
}

class Device {
  final String deviceId;
  final String deviceName;
  final int registeredAt;

  Device({required this.deviceId, required this.deviceName, required this.registeredAt});

  factory Device.fromJson(Map<String, dynamic> j) => Device(
        deviceId:     j['device_id'] as String,
        deviceName:   j['device_name'] as String,
        registeredAt: j['registered_at'] as int,
      );
}

class BeginRegistrationResponse {
  final String magicToken;
  BeginRegistrationResponse(this.magicToken);
  factory BeginRegistrationResponse.fromJson(Map<String, dynamic> j) =>
      BeginRegistrationResponse(j['magic_token'] as String);
}

class BeginLoginResponse {
  final String challenge;
  BeginLoginResponse(this.challenge);
  factory BeginLoginResponse.fromJson(Map<String, dynamic> j) =>
      BeginLoginResponse(j['challenge'] as String);
}

class EzoneClient {
  final String baseUrl;
  final Duration timeout;
  final http.Client _http;

  EzoneClient({
    required this.baseUrl,
    this.timeout = const Duration(seconds: 10),
    http.Client? httpClient,
  }) : _http = httpClient ?? http.Client();

  Uri _uri(String path) => Uri.parse('${baseUrl.trimRight()}/v1$path');

  Map<String, String> _headers([String? token]) => {
        'Content-Type': 'application/json',
        if (token != null) 'Authorization': 'Bearer $token',
      };

  Future<Map<String, dynamic>> _post(
    String path,
    Map<String, dynamic> body, {
    String? token,
  }) async {
    final resp = await _http
        .post(_uri(path), headers: _headers(token), body: jsonEncode(body))
        .timeout(timeout);
    return _parse(resp);
  }

  Future<Map<String, dynamic>> _get(String path, String token) async {
    final resp = await _http
        .get(_uri(path), headers: _headers(token))
        .timeout(timeout);
    return _parse(resp);
  }

  Future<void> _delete(String path, String token) async {
    final resp = await _http
        .delete(_uri(path), headers: _headers(token))
        .timeout(timeout);
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      final body = jsonDecode(resp.body) as Map<String, dynamic>;
      throw EzoneError(resp.statusCode, body['error'] as String? ?? 'error');
    }
  }

  Map<String, dynamic> _parse(http.Response resp) {
    final body = jsonDecode(resp.body) as Map<String, dynamic>;
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throw EzoneError(resp.statusCode, body['error'] as String? ?? 'error');
    }
    return body;
  }

  // ── Registration ────────────────────────────────────────────────────────────

  Future<BeginRegistrationResponse> beginRegistration({required String email}) async {
    final j = await _post('/auth/register/begin', {'email': email});
    return BeginRegistrationResponse.fromJson(j);
  }

  Future<SessionResponse> completeRegistration({
    required String magicToken,
    required String devicePublicKey,
    required String deviceName,
  }) async {
    final j = await _post('/auth/register/complete', {
      'magic_token':       magicToken,
      'device_public_key': devicePublicKey,
      'device_name':       deviceName,
    });
    return SessionResponse.fromJson(j);
  }

  // ── Login ────────────────────────────────────────────────────────────────────

  Future<BeginLoginResponse> beginLogin({required String email}) async {
    final j = await _post('/auth/login/begin', {'email': email});
    return BeginLoginResponse.fromJson(j);
  }

  Future<SessionResponse> completeLogin({
    required String email,
    required String challenge,
    required String signature,
    required String devicePublicKey,
  }) async {
    final j = await _post('/auth/login/complete', {
      'email':             email,
      'challenge':         challenge,
      'signature':         signature,
      'device_public_key': devicePublicKey,
    });
    return SessionResponse.fromJson(j);
  }

  // ── Session ──────────────────────────────────────────────────────────────────

  Future<SessionInfo> verifySession(String token) async {
    final j = await _get('/auth/session', token);
    return SessionInfo.fromJson(j);
  }

  Future<SessionResponse> refreshSession(String token) async {
    final j = await _post('/auth/session/refresh', {}, token: token);
    return SessionResponse.fromJson(j);
  }

  Future<void> logout(String token) =>
      _post('/auth/session/logout', {}, token: token);

  // ── Reset ────────────────────────────────────────────────────────────────────

  Future<BeginRegistrationResponse> beginReset({required String email}) async {
    final j = await _post('/auth/reset/begin', {'email': email});
    return BeginRegistrationResponse.fromJson(j);
  }

  Future<SessionResponse> completeReset({
    required String magicToken,
    required String devicePublicKey,
    required String deviceName,
  }) async {
    final j = await _post('/auth/reset/complete', {
      'magic_token':       magicToken,
      'device_public_key': devicePublicKey,
      'device_name':       deviceName,
    });
    return SessionResponse.fromJson(j);
  }

  // ── Recovery ─────────────────────────────────────────────────────────────────

  Future<List<String>> generateRecoveryCodes(String token) async {
    final j = await _post('/auth/recovery/generate', {}, token: token);
    return (j['codes'] as List).cast<String>();
  }

  Future<SessionResponse> recoverWithCode({
    required String email,
    required String code,
    required String devicePublicKey,
    required String deviceName,
  }) async {
    final j = await _post('/auth/recovery/use', {
      'email':             email,
      'code':              code,
      'device_public_key': devicePublicKey,
      'device_name':       deviceName,
    });
    return SessionResponse.fromJson(j);
  }

  // ── Devices ──────────────────────────────────────────────────────────────────

  Future<List<Device>> listDevices(String token) async {
    final j = await _get('/auth/devices', token);
    return (j['devices'] as List)
        .map((d) => Device.fromJson(d as Map<String, dynamic>))
        .toList();
  }

  Future<BeginRegistrationResponse> beginAddDevice(String token) async {
    final j = await _post('/auth/devices/add/begin', {}, token: token);
    return BeginRegistrationResponse.fromJson(j);
  }

  Future<Device> completeAddDevice({
    required String magicToken,
    required String devicePublicKey,
    required String deviceName,
  }) async {
    final j = await _post('/auth/devices/add/complete', {
      'magic_token':       magicToken,
      'device_public_key': devicePublicKey,
      'device_name':       deviceName,
    });
    return Device.fromJson(j);
  }

  Future<void> revokeDevice(String token, String deviceId) =>
      _delete('/auth/devices/$deviceId', token);

  void close() => _http.close();
}
