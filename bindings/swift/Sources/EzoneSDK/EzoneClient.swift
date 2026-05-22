import Foundation

public struct EzoneError: Error, LocalizedError {
    public let statusCode: Int
    public let message: String
    public var errorDescription: String? { "EzoneError(\(statusCode)): \(message)" }
}

// ── Response models ───────────────────────────────────────────────────────────

public struct SessionResponse: Codable {
    public let token:     String
    public let expiresAt: Int
    public let userId:    String?
    public let deviceId:  String?
    enum CodingKeys: String, CodingKey {
        case token, userId = "user_id", deviceId = "device_id", expiresAt = "expires_at"
    }
}

public struct SessionInfo: Codable {
    public let userId:    String
    public let email:     String
    public let expiresAt: Int
    enum CodingKeys: String, CodingKey {
        case userId = "user_id", email, expiresAt = "expires_at"
    }
}

public struct BeginRegistrationResponse: Codable {
    public let magicToken: String
    enum CodingKeys: String, CodingKey { case magicToken = "magic_token" }
}

public struct BeginLoginResponse: Codable {
    public let challenge: String
}

public struct Device: Codable {
    public let deviceId:     String
    public let deviceName:   String
    public let registeredAt: Int
    enum CodingKeys: String, CodingKey {
        case deviceId = "device_id", deviceName = "device_name", registeredAt = "registered_at"
    }
}

public struct DevicesResponse: Codable {
    public let devices: [Device]
}

public struct RecoveryCodesResponse: Codable {
    public let codes: [String]
}

// ── Client ────────────────────────────────────────────────────────────────────

public class EzoneClient {
    private let baseURL: URL
    private let session: URLSession

    public init(baseURL: URL, timeout: TimeInterval = 10) {
        self.baseURL = baseURL
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = timeout
        self.session = URLSession(configuration: config)
    }

    // ── Registration ─────────────────────────────────────────────────────────

    public func beginRegistration(email: String) async throws -> BeginRegistrationResponse {
        try await post("/v1/auth/register/begin", body: ["email": email])
    }

    public func completeRegistration(
        magicToken: String, devicePublicKey: String, deviceName: String
    ) async throws -> SessionResponse {
        try await post("/v1/auth/register/complete", body: [
            "magic_token": magicToken, "device_public_key": devicePublicKey, "device_name": deviceName,
        ])
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    public func beginLogin(email: String) async throws -> BeginLoginResponse {
        try await post("/v1/auth/login/begin", body: ["email": email])
    }

    public func completeLogin(
        email: String, challenge: String, signature: String, devicePublicKey: String
    ) async throws -> SessionResponse {
        try await post("/v1/auth/login/complete", body: [
            "email": email, "challenge": challenge,
            "signature": signature, "device_public_key": devicePublicKey,
        ])
    }

    // ── Session ───────────────────────────────────────────────────────────────

    public func verifySession(_ token: String) async throws -> SessionInfo {
        try await get("/v1/auth/session", token: token)
    }

    public func refreshSession(_ token: String) async throws -> SessionResponse {
        try await post("/v1/auth/session/refresh", body: [:], token: token)
    }

    public func logout(_ token: String) async throws {
        let _: [String: Bool] = try await post("/v1/auth/session/logout", body: [:], token: token)
    }

    // ── Reset ─────────────────────────────────────────────────────────────────

    public func beginReset(email: String) async throws -> BeginRegistrationResponse {
        try await post("/v1/auth/reset/begin", body: ["email": email])
    }

    public func completeReset(
        magicToken: String, devicePublicKey: String, deviceName: String
    ) async throws -> SessionResponse {
        try await post("/v1/auth/reset/complete", body: [
            "magic_token": magicToken, "device_public_key": devicePublicKey, "device_name": deviceName,
        ])
    }

    // ── Recovery ──────────────────────────────────────────────────────────────

    public func generateRecoveryCodes(_ token: String) async throws -> RecoveryCodesResponse {
        try await post("/v1/auth/recovery/generate", body: [:], token: token)
    }

    public func recoverWithCode(
        email: String, code: String, devicePublicKey: String, deviceName: String
    ) async throws -> SessionResponse {
        try await post("/v1/auth/recovery/use", body: [
            "email": email, "code": code,
            "device_public_key": devicePublicKey, "device_name": deviceName,
        ])
    }

    // ── Devices ───────────────────────────────────────────────────────────────

    public func listDevices(_ token: String) async throws -> DevicesResponse {
        try await get("/v1/auth/devices", token: token)
    }

    public func beginAddDevice(_ token: String) async throws -> BeginRegistrationResponse {
        try await post("/v1/auth/devices/add/begin", body: [:], token: token)
    }

    public func completeAddDevice(
        magicToken: String, devicePublicKey: String, deviceName: String
    ) async throws -> Device {
        try await post("/v1/auth/devices/add/complete", body: [
            "magic_token": magicToken, "device_public_key": devicePublicKey, "device_name": deviceName,
        ])
    }

    public func revokeDevice(_ token: String, deviceId: String) async throws {
        let url = baseURL.appendingPathComponent("v1/auth/devices/\(deviceId)")
        var req = URLRequest(url: url)
        req.httpMethod = "DELETE"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (_, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw EzoneError(statusCode: (resp as? HTTPURLResponse)?.statusCode ?? 0,
                             message: "revoke failed")
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private func post<T: Decodable>(
        _ path: String,
        body: [String: String],
        token: String? = nil
    ) async throws -> T {
        var req = URLRequest(url: baseURL.appendingPathComponent(path.dropFirst()))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let t = token { req.setValue("Bearer \(t)", forHTTPHeaderField: "Authorization") }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        return try await send(req)
    }

    private func get<T: Decodable>(_ path: String, token: String) async throws -> T {
        var req = URLRequest(url: baseURL.appendingPathComponent(path.dropFirst()))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        return try await send(req)
    }

    private func send<T: Decodable>(_ req: URLRequest) async throws -> T {
        let (data, resp) = try await session.data(for: req)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        if status < 200 || status >= 300 {
            let err = try? JSONDecoder().decode([String: String].self, from: data)
            throw EzoneError(statusCode: status, message: err?["error"] ?? "error")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
}
