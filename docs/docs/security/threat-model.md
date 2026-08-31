---
id: threat-model
title: Threat Model
---

# Threat Model

## Assets

| Asset | Sensitivity | Stored by |
|---|---|---|
| User's private device key (any method) | Critical | Device only (never transmitted) |
| Server HMAC key | Critical | Server (env var / secrets manager) |
| Server token signing key | Critical | Server (env var / secrets manager) |
| User email addresses / usernames | Medium | StorageAdapter |
| Device / WebAuthn credential / push-device public keys | Low (non-secret) | StorageAdapter |
| Session tokens | Medium | Client (memory / secure storage) |
| OTP codes (plaintext) | High, but ephemeral | Never stored — only an HMAC hash, single-use, short TTL |
| QR session state (challenge, desktop IP) | Medium, ephemeral | In-memory only, per-instance, TTL-bounded |

## Threat actors

### External attacker (no server access)

**What they can do**: intercept traffic (if TLS is absent), attempt login with guessed public keys, brute-force OTP codes (rate-limited and lockout-protected), capture a displayed QR code.

**What they cannot do**:
- Authenticate without the relevant device's private key
- Forge tokens without the server signing key
- Crack challenges without the HMAC key
- Approve a captured QR code with an unregistered keypair — `/auth/qr/approve` verifies the presented public key against a device already registered to *some* account before accepting a signature over it

### Attacker with read access to the database

**What they can do**: read email addresses, public keys, device/credential records, recovery-code hashes.

**What they cannot do**:
- Authenticate (private keys are not in the database, by any method)
- Forge tokens (signing key is not in the database)
- Forge challenge MACs (HMAC key is not in the database)
- Recover a usable recovery code (only its HMAC hash is stored, single-use, cleared on use)

**Conclusion**: A database breach leaks identity metadata (emails, device labels) but not credentials. No passwords, no private keys, no plaintext OTP codes.

### Attacker with full server compromise

**What they can do**: read the HMAC key and signing key, issue fraudulent tokens, intercept future logins, read in-flight OTP codes before delivery.

**What they cannot do**: recover private keys from any existing device, retroactively decrypt past sessions or QR/push challenges (they're ephemeral and not persisted).

**Mitigation**: rotate keys immediately on detected compromise; issue a new server key pair and invalidate all sessions by changing the signing key.

### Attacker who controls a malicious/compromised network position (LAN, Wi-Fi)

Relevant specifically to **QR login**, which is intentionally IP-bound to the desktop's network as an anti-phishing measure (so a QR code shown on one network can't be approved by a phone on a different one).

**What they can do**: if they share the desktop's `/24` subnet, satisfy the IP-binding check.
**What they cannot do**: approve without a private key for an *already-registered* device — IP-binding is defense-in-depth on top of, not instead of, the signature check.

**Caveat**: IP-binding is only as trustworthy as `client_ip()`'s source. Behind a misconfigured reverse proxy with `EZONE_TRUST_PROXY=true`, a client could forge its apparent IP via `X-Forwarded-For`. Only enable that setting when the proxy in front of ezone actually overwrites/strips client-supplied `X-Forwarded-For`.

### Attacker with physical access to user device

**What they can do**: if the device is unlocked, potentially access keys stored in software (e.g. WebCrypto IndexedDB, an app's own encrypted-at-rest key).
**What they cannot do**: extract keys from hardware-backed storage (Secure Enclave, Android Keystore/TEE, FIDO2 hardware key).

**Mitigation**: prefer WebAuthn/passkeys or the biometric-provider flow for hardware-backed key protection over software-only key storage.

## Method-specific notes

- **WebAuthn**: origin- and RP-ID-bound by the browser itself; sign-count is checked for clone detection. `EZONE_WEBAUTHN_RP_ID` must match your real domain in production — the `localhost` default will not verify against a real origin.
- **Push notification**: approval requires a signature from a device already registered (via an authenticated `/auth/push/register` call) — the server never trusts a client-supplied public key for approval, only the one on file.
- **Biometric**: the "biometric" step happens entirely on-device, gating whether the OS releases the private key to sign. The server never receives anything biometric — only a signature — so from the server's perspective this is challenge-response with an extra on-device gate. Each challenge is single-use.
- **OTP**: codes are never logged or stored in plaintext; only an HMAC-SHA384 hash is kept, compared in constant time, and cleared after first use.

## Out of scope

- Side-channel attacks on the server process
- Quantum computing attacks (P-384 and Ed25519 are not post-quantum; plan migration to NIST post-quantum standards when available)
- Social engineering attacks against users
- Compromise of the developer's own email/SMS provider account (magic links and OTP codes are only as trustworthy as their delivery channel)
