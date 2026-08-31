---
id: overview
title: Security Overview
---

# Security Overview

## What ezone protects against

| Threat | How ezone addresses it |
|---|---|
| **Credential stuffing** | No passwords exist — there is nothing to stuff |
| **Phishing** | Device keys are origin-bound (challenge-response, WebAuthn); QR login is IP-bound |
| **Database breach** | No password hashes stored; public keys are non-secret |
| **Replay attacks** | Challenges are single-use with a short TTL and a nonce, across every auth method (challenge-response, WebAuthn, QR, push, biometric) |
| **MITM token theft** | Tokens are short-lived (1h default, configurable via `EZONE_SESSION_TTL`); require TLS |
| **Brute force (device key methods)** | Challenge–response requires a valid private key; the signature itself is the proof |
| **Brute force (OTP)** | 3 attempts then a 15-minute lockout per identifier, plus per-IP and per-identifier rate limits |
| **User enumeration** | `begin_reset` always returns success for any email |
| **Cross-purpose token misuse** | Magic link `purpose` byte prevents a registration token being replayed as a reset token |
| **QR code phishing / screenshot** | AES-256-GCM (or ChaCha20-Poly1305) encrypted, HMAC-signed, IP-bound, 5-minute expiry, and the approving device must already be registered — an attacker who captures a QR code still cannot approve it with an arbitrary keypair |
| **Rate-limit / IP-binding bypass via spoofed headers** | `X-Forwarded-For` is only trusted when `EZONE_TRUST_PROXY` is explicitly enabled — off by default |

## Trust model

- **The server** holds the HMAC key and token signing key. These are the only secrets. Protect them as you would a private key.
- **The client device** holds the P-384 (or Ed25519, with Libsodium) private key. Only the user's device can authenticate as that device.
- **The server never learns the user's private key.** Even in a full server compromise, an attacker cannot impersonate a user on a device they don't control.
- **Biometric auth is device-key auth** — the "biometric" step gates the OS/hardware from releasing the private key to sign; the server only ever sees a signature, never anything biometric.

## Session token properties

Session tokens are ES384-signed (or Ed25519, if configured), compact `header.payload.signature` tokens — not standard JWTs, but structurally similar:

- Short-lived (default 1 hour, `EZONE_SESSION_TTL`)
- Embed the issuing `device_id`, so `verify_session`/`logout`/`refresh_session` always operate on the exact device that authenticated — not just "some active device" on the account
- Cannot be extended or forged without the server's signing key
- Verification is stateless — no DB lookup for the signature itself (a lookup is still made to confirm the device hasn't been revoked and the account is still active)

## Rate limiting and IP binding

Unlike many minimal auth SDKs, ezone's REST server **does** implement rate limiting itself (a per-IP token bucket, `EZONE_RATE_LIMIT`, applied to every `/auth/*` endpoint including status-polling and listing routes) — you don't have to rely solely on a reverse proxy for basic protection, though a proxy/WAF is still recommended in production for defense in depth.

By default, the server trusts only the direct TCP peer address for rate limiting and QR IP-binding. If you run behind a reverse proxy, set `EZONE_TRUST_PROXY=true` **only if that proxy actually overwrites/strips client-supplied `X-Forwarded-For`** — otherwise any client can forge that header to bypass both protections.

## What ezone does NOT provide

- **Audit logging** — hook into server request logs or extend `StorageAdapter`
- **Token revocation list** — the stateless design trades revocation for scalability; `logout(token, revoke_device=true)` revokes the *device*, invalidating all its future tokens, but an already-issued token from that device remains valid until it naturally expires (bounded by the short TTL)
- **IP allowlisting** — implement at your infrastructure layer
- **Multi-factor composition** (e.g. "require both a device key AND an OTP") — each method independently authenticates; composing them is currently the calling application's responsibility

## Reporting vulnerabilities

Please report security issues to security@ezone.dev or via [GitHub private advisory](https://github.com/ezone-sdk/ezone-sdk/security/advisories/new).
