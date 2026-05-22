# ezone SDK

**Military-grade passwordless authentication. No passwords. No database of credentials. No breach surface.**

ezone is an open-source authentication SDK built on P-384 ECDSA (NSA Suite B), AES-256-GCM, and HMAC-SHA384. Users authenticate with cryptographic device keys — the private key never leaves the device, the server never stores a password hash, and sessions are stateless signed tokens that verify without any database lookup.

---

## Why ezone?

| Traditional auth | ezone |
|---|---|
| Stores password hashes → breach leaks credentials | No passwords exist — nothing to leak |
| Server-side session store → single point of failure | Stateless ES384 tokens — verify anywhere |
| Phishable credentials | Device-bound keys — a fake site gets nothing |
| Password reset = weakest link | Recovery codes + magic links, cryptographically signed |

---

## Features

- **P-384 ECDSA** — NSA Suite B, FIPS 186-5 compliant
- **AES-256-GCM** — authenticated symmetric encryption
- **HMAC-SHA384** — stateless challenge and magic link verification
- **Zero-storage challenges** — self-verifying via HMAC, no session DB needed
- **WebAuthn / FIDO2** — hardware-backed passkeys (TouchID, FaceID, Windows Hello, YubiKey)
- **FIPS 140-3 mode** — via OpenSSL 3.x FIPS provider
- **Multi-device** — independent keypairs per device, individual revocation
- **Recovery codes** — single-use HMAC-hashed codes for lost-device recovery
- **12 language SDKs** — Node.js, Python, Go, Browser, Rust, Java, Dart, Swift, .NET, PHP, Ruby, React Native

---

## Quick start

### 1 — Start the server

```bash
# Docker (fastest)
docker run -p 8080:8080 ghcr.io/ezone-sdk/ezone-server:latest

# Verify
curl http://localhost:8080/v1/health
# {"status":"ok","fips":false}
```

### 2 — Install a client SDK

```bash
npm install ezone-sdk          # Node.js / TypeScript
pip install ezone-sdk          # Python
go get github.com/ezone-sdk/ezone-go   # Go
cargo add ezone                # Rust
```

### 3 — Register and login

```typescript
import { EzoneClient } from 'ezone-sdk';

const ezone = new EzoneClient({ baseUrl: 'http://localhost:8080' });

// Registration — sends magic link to user
const { magic_token } = await ezone.beginRegistration({ email: 'alice@example.com' });

// After user clicks link and sends their device public key:
const session = await ezone.completeRegistration({
  magic_token,
  device_public_key: req.body.device_public_key,
  device_name: 'Alice\'s MacBook',
});

// Login — challenge/response (no password)
const { challenge } = await ezone.beginLogin({ email: 'alice@example.com' });
// client signs challenge with device private key (never transmitted)
const session = await ezone.completeLogin({ email, challenge, signature, device_public_key });

// Verify on protected routes
const user = await ezone.verifySession(req.headers.authorization.replace('Bearer ', ''));
```

See the **[full example app](./examples/web/)** for a working React + Node.js integration.

---

## Language SDKs

| Language | Package | Install |
|---|---|---|
| Node.js / TypeScript | `ezone-sdk` | `npm install ezone-sdk` |
| Python | `ezone-sdk` | `pip install ezone-sdk` |
| Go | `github.com/ezone-sdk/ezone-go` | `go get github.com/ezone-sdk/ezone-go` |
| Browser | `@ezone/browser` | `npm install @ezone/browser` |
| Rust | `ezone` | `cargo add ezone` |
| Java / Kotlin | `io.ezone:ezone-sdk` | Maven / Gradle |
| Dart / Flutter | `ezone_sdk` | `flutter pub add ezone_sdk` |
| Swift / iOS | `EzoneSDK` | Swift Package Manager |
| .NET / C# | `Ezone.SDK` | `dotnet add package Ezone.SDK` |
| PHP | `ezone/ezone-sdk` | `composer require ezone/ezone-sdk` |
| Ruby | `ezone-sdk` | `gem install ezone-sdk` |
| React Native | `@ezone/react-native` | `npm install @ezone/react-native` |

---

## Architecture

```
  Browser / Mobile / Server
         │
  Language SDK client
         │  HTTP/HTTPS
  ┌──────▼──────────────┐
  │  ezone REST server  │   15 endpoints  /v1/auth/*
  │  ─────────────────  │
  │  Auth layer         │   registration · login · reset · recovery · devices
  │  CryptoEngine       │   P-384 · AES-256-GCM · SHA-384 · HMAC-SHA384
  │  StorageAdapter     │   pluggable persistence (MemoryAdapter built-in)
  └─────────────────────┘
```

The C++ core is also available as a shared library with a C API for direct embedding.

---

## Building from source

**Prerequisites**: CMake 3.20+, OpenSSL 3.x, Ninja (optional)

```bash
git clone https://github.com/ezone-sdk/ezone-sdk
cd ezone-sdk

# Build SDK + REST server
cmake -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DEZONE_BUILD_SERVER=ON \
  -DBUILD_SHARED_LIBS=ON

cmake --build build --config Release

# Run tests
ctest --test-dir build --output-on-failure

# Start the server
./build/ezone-server
```

**Windows (PowerShell):**
```powershell
cmake -B build -DCMAKE_BUILD_TYPE=Release -DEZONE_BUILD_SERVER=ON -DBUILD_SHARED_LIBS=ON
cmake --build build --config Release
.\build\Release\ezone-server.exe
```

---

## Configuration

The server is configured via environment variables:

| Variable | Default | Description |
|---|---|---|
| `EZONE_PORT` | `8080` | Listen port |
| `EZONE_HOST` | `0.0.0.0` | Bind address |
| `EZONE_THREADS` | `4` | Worker threads |
| `EZONE_SESSION_TTL` | `3600` | Session token TTL (seconds) |
| `EZONE_CHALLENGE_TTL` | `30` | Login challenge TTL (seconds) |
| `EZONE_TLS_CERT` | — | TLS certificate (PEM) |
| `EZONE_TLS_KEY` | — | TLS private key (PEM) |
| `EZONE_REQUIRE_FIPS` | `false` | Require FIPS 140-3 mode |

See the [full configuration reference](./docs/docs/self-hosting/configuration.md).

---

## Security

- All cryptographic operations use OpenSSL 3.x EVP APIs
- Private keys are **never transmitted or stored server-side**
- Challenges are single-use with nonce + HMAC — replay-proof
- Magic links embed purpose byte — cross-purpose reuse is cryptographically impossible
- `begin_reset` always returns success — prevents user enumeration
- Recovery codes are HMAC-hashed, single-use, atomically consumed
- Server enforces body size limits, rate limiting (60 req/min/IP), and input validation on all auth endpoints
- Security headers on every response: HSTS, CSP, X-Frame-Options, etc.

See the [Threat Model](./docs/docs/security/threat-model.md) and [Security Overview](./docs/docs/security/overview.md).

---

## Documentation

Full documentation: **[docs.ezone.dev](https://docs.ezone.dev)**

- [Getting Started](https://docs.ezone.dev/docs/getting-started)
- [API Reference](https://docs.ezone.dev/docs/api-reference)
- [SDK Guides](https://docs.ezone.dev/docs/sdks)
- [Self-Hosting](https://docs.ezone.dev/docs/self-hosting/server)
- [Security](https://docs.ezone.dev/docs/security/overview)

---

## Contributing

1. Fork the repository
2. Create a branch: `git checkout -b feat/your-feature`
3. Build and test: `cmake --build build && ctest --test-dir build`
4. Open a pull request

Please open an issue before starting large features.

---

## License

MIT — see [LICENSE](./LICENSE).

---

## Reporting vulnerabilities

Please report security issues privately via [GitHub Security Advisories](https://github.com/ezone-sdk/ezone-sdk/security/advisories/new) or email **security@ezone.dev**. Do not open a public issue for security vulnerabilities.
