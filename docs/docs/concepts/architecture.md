---
id: architecture
title: Architecture
---

# Architecture

## Component overview

```
┌──────────────────────────────────────────────────────────────────┐
│                          Client side                             │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────┐   │
│  │  Language   │  │   Browser    │  │  Mobile / Native app  │   │
│  │  SDK client │  │  WebAuthn    │  │  (Secure Enclave key) │   │
│  └──────┬──────┘  └──────┬───────┘  └──────────┬────────────┘   │
└─────────┼────────────────┼──────────────────────┼───────────────┘
          │  HTTP/HTTPS    │                      │
┌─────────▼────────────────▼──────────────────────▼───────────────┐
│                      ezone REST server                           │
│  /v1/auth/*  (15 endpoints)                                      │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │                    C++ Auth layer                        │    │
│  │  begin/complete registration, login, reset, recovery     │    │
│  └────────────────────────┬─────────────────────────────────┘    │
│  ┌─────────────────────────▼────────────────────────────────┐    │
│  │                  CryptoEngine (OpenSSL 3)                │    │
│  │  P-384 · AES-256-GCM · SHA-384 · HMAC-SHA384            │    │
│  └─────────────────────────┬────────────────────────────────┘    │
│  ┌─────────────────────────▼────────────────────────────────┐    │
│  │               StorageAdapter interface                   │    │
│  │  MemoryStorageAdapter (default) | Your implementation    │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

## Layers

### CryptoEngine

The lowest layer. Stateless functions wrapping OpenSSL 3 EVP APIs:

- `generate_keypair()` — P-384 ECDSA key pair
- `sign()` / `verify()` — ECDSA-P384 signature
- `encrypt()` / `decrypt()` — AES-256-GCM
- `hmac_sha384()` — keyed MAC
- `generate_challenge()` / `verify_challenge()` — HMAC-signed stateless challenges
- `issue_token()` / `verify_token()` — compact ES384 session tokens

### StorageAdapter

An abstract interface for user and device record persistence. ezone ships with `MemoryStorageAdapter` for development and testing. For production you implement the interface:

```cpp
class StorageAdapter {
public:
    virtual Result<std::string> create_user(const std::string& email) = 0;
    virtual Result<User>        get_user_by_id(const std::string& id) = 0;
    virtual Result<User>        get_user_by_email(const std::string& email) = 0;
    virtual Result<void>        add_device(const std::string& user_id, const Device& d) = 0;
    virtual Result<Device>      get_device(const std::string& device_id) = 0;
    virtual Result<void>        revoke_device(const std::string& device_id) = 0;
    // ... recovery hash methods
};
```

### Auth layer

Orchestrates registration, login, and recovery flows on top of CryptoEngine and StorageAdapter. Stateless where possible — magic links and challenges are self-verifying; device records are the only persistent state.

### REST server

Thin HTTP wrapper over the Auth layer using cpp-httplib. Each endpoint parses JSON, calls Auth, serialises the response. Security headers are added to every response.

## Data flow: Login

```
1. Client      POST /v1/auth/login/begin  { email }
               ← { challenge: "base64url..." }

2. Client      signs challenge with device private key (never leaves device)

3. Client      POST /v1/auth/login/complete  { email, challenge, signature, device_public_key }
               ← { token: "header.payload.sig", expires_at: 1234567890 }

4. Client      GET /api/anything
               Authorization: Bearer <token>
               ← your application response (token verified in middleware)
```

## Key storage

| Platform | Key storage |
|---|---|
| Browser | IndexedDB (non-extractable WebCrypto key) |
| WebAuthn / FIDO2 | Authenticator secure enclave |
| iOS / macOS | Secure Enclave via CryptoKit |
| Android | Android Keystore |
| Server | OS keystore or encrypted file at rest |
