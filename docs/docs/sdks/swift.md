---
id: swift
title: Swift / iOS / macOS
---

# Swift SDK

URLSession-based client with async/await support. Targets iOS 15+, macOS 12+, watchOS 8+, tvOS 15+.

## Installation

**Swift Package Manager** — add to `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/ezone-sdk/ezone-swift", from: "0.1.0"),
],
targets: [
    .target(name: "YourApp", dependencies: ["EzoneSDK"]),
]
```

Or in Xcode: File → Add Package Dependencies → paste the repository URL.

## Quick start

```swift
import EzoneSDK

let ezone = EzoneClient(baseURL: URL(string: "https://auth.yourapp.com")!)

// Registration
let reg = try await ezone.beginRegistration(email: "alice@example.com")
print(reg.magicToken)

// Login
let challenge = try await ezone.beginLogin(email: "alice@example.com")
let signature = try deviceKey.sign(challenge: challenge.challenge) // CryptoKit

let session = try await ezone.completeLogin(
    email: "alice@example.com",
    challenge: challenge.challenge,
    signature: signature,
    devicePublicKey: deviceKey.publicKeyBase64
)
print(session.token)
```

## Secure Enclave key management

```swift
import CryptoKit
import EzoneSDK

class EzoneDeviceKey {
    private let key: SecureEnclave.P256.Signing.PrivateKey

    static func getOrCreate(tag: String) throws -> EzoneDeviceKey {
        // Try to load existing key from Keychain
        if let existing = try? loadFromKeychain(tag: tag) {
            return existing
        }
        // Generate new key in Secure Enclave
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        try saveToKeychain(key, tag: tag)
        return EzoneDeviceKey(key: key)
    }

    var publicKeyBase64: String {
        let spki = buildSPKI(from: key.publicKey)
        return Data(spki).base64URLEncodedString()
    }

    func sign(challenge: String) throws -> String {
        guard let data = Data(base64URLEncoded: challenge) else {
            throw EzoneError.invalidChallenge
        }
        let signature = try key.signature(for: data)
        return Data(signature.derRepresentation).base64URLEncodedString()
    }
}
```

## SwiftUI integration

```swift
import SwiftUI
import EzoneSDK

@MainActor
class AuthViewModel: ObservableObject {
    @Published var token: String?
    @Published var isLoading = false
    @Published var error: Error?

    private let ezone = EzoneClient(baseURL: URL(string: "https://auth.yourapp.com")!)
    private let deviceKey = try! EzoneDeviceKey.getOrCreate(tag: "com.yourapp.ezone")

    func login(email: String) async {
        isLoading = true
        do {
            let ch = try await ezone.beginLogin(email: email)
            let sig = try deviceKey.sign(challenge: ch.challenge)
            let session = try await ezone.completeLogin(
                email: email,
                challenge: ch.challenge,
                signature: sig,
                devicePublicKey: deviceKey.publicKeyBase64
            )
            token = session.token
        } catch {
            self.error = error
        }
        isLoading = false
    }
}

struct LoginView: View {
    @StateObject private var vm = AuthViewModel()
    @State private var email = ""

    var body: some View {
        VStack(spacing: 16) {
            TextField("Email", text: $email)
                .keyboardType(.emailAddress)
                .autocapitalization(.none)
            Button("Sign in") { Task { await vm.login(email: email) } }
                .disabled(vm.isLoading)
        }
        .padding()
    }
}
```

## Full API

```swift
public class EzoneClient {
    public init(baseURL: URL, timeout: TimeInterval = 10)

    public func beginRegistration(email: String) async throws -> BeginRegistrationResponse
    public func completeRegistration(magicToken: String, devicePublicKey: String, deviceName: String) async throws -> SessionResponse

    public func beginLogin(email: String) async throws -> BeginLoginResponse
    public func completeLogin(email: String, challenge: String, signature: String, devicePublicKey: String) async throws -> SessionResponse

    public func verifySession(_ token: String) async throws -> SessionInfo
    public func refreshSession(_ token: String) async throws -> SessionResponse
    public func logout(_ token: String) async throws

    public func beginReset(email: String) async throws -> BeginResetResponse
    public func completeReset(magicToken: String, devicePublicKey: String, deviceName: String) async throws -> SessionResponse

    public func generateRecoveryCodes(_ token: String) async throws -> [String]
    public func recoverWithCode(email: String, code: String, devicePublicKey: String, deviceName: String) async throws -> SessionResponse

    public func listDevices(_ token: String) async throws -> [Device]
    public func beginAddDevice(_ token: String) async throws -> BeginAddDeviceResponse
    public func completeAddDevice(magicToken: String, devicePublicKey: String, deviceName: String) async throws -> Device
    public func revokeDevice(_ token: String, deviceId: String) async throws
}
```
