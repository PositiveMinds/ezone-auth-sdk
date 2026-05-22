---
id: intro
title: Introduction
sidebar_position: 1
---

# ezone SDK

**ezone** is a military-grade, fully passwordless authentication SDK. It provides everything you need to add strong, phishing-resistant authentication to any application — with zero passwords, zero password storage, and no centralised session database required.

## Why ezone?

Traditional authentication stores password hashes. When the database leaks, millions of users are at risk. ezone eliminates this by never touching passwords at all.

Instead, ezone uses:

- **Device-bound cryptographic keys** — each user device generates a P-384 ECDSA keypair that never leaves the device
- **Challenge–response authentication** — the server sends a random challenge; the device signs it with its private key
- **Magic link registration** — initial account creation via HMAC-signed one-time tokens delivered out-of-band
- **Stateless sessions** — compact ES384-signed tokens that the server can verify without any database lookup

## Core guarantees

| Property | How ezone achieves it |
|---|---|
| No password ever stored | Authentication is purely key-based |
| No session database needed | Tokens are self-verifying via ECDSA + HMAC |
| Replay-proof challenges | Each challenge has a nonce + 30s TTL |
| Phishing-resistant | Private keys are device-bound, never transmitted |
| FIPS 140-3 capable | Uses OpenSSL 3.x in FIPS provider mode |

## Cryptographic primitives

ezone uses only well-reviewed, standardised primitives:

| Primitive | Algorithm | Standard |
|---|---|---|
| Key exchange / signing | ECDSA P-384 | NSA Suite B / FIPS 186-5 |
| Symmetric encryption | AES-256-GCM | NIST SP 800-38D |
| Hashing | SHA-384 / SHA-512 | FIPS 180-4 |
| MACs | HMAC-SHA384 | FIPS 198-1 |
| Key derivation | OpenSSL 3 EVP | NIST SP 800-135 |

## Architecture overview

```
┌─────────────────────────────────────────────────────┐
│                  Your Application                   │
│  ┌────────────┐      HTTP/HTTPS      ┌───────────┐  │
│  │ Language   │ ◄──────────────────► │   ezone   │  │
│  │ SDK client │                      │REST server│  │
│  └────────────┘                      └─────┬─────┘  │
│                                            │         │
│                                    ┌───────▼──────┐  │
│                                    │  C++ Core    │  │
│                                    │  (OpenSSL)   │  │
│                                    └──────────────┘  │
└─────────────────────────────────────────────────────┘
```

The C++ core handles all cryptographic operations. Language SDKs communicate with the REST server over HTTP. You can also embed the C++ library directly via the FFI-stable C API.

## What's included

- **C++ SDK** — the cryptographic core, embeddable via native linking or C API
- **REST server** — production-ready HTTP server with 15 auth endpoints
- **11 language clients** — Node.js, Python, Go, Browser, Rust, Java, Dart, Swift, .NET, PHP, Ruby
- **StorageAdapter interface** — bring your own persistence layer, or use the built-in in-memory adapter for testing

## Next steps

- [Getting Started](/docs/getting-started) — deploy the server and complete your first auth flow in 5 minutes
- [Core Concepts: Architecture](/docs/concepts/architecture) — deep dive into how stateless auth works
- [API Reference](/docs/api-reference) — all 15 REST endpoints documented
