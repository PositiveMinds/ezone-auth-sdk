---
id: threat-model
title: Threat Model
---

# Threat Model

## Assets

| Asset | Sensitivity | Stored by |
|---|---|---|
| User's private device key | Critical | Device only (never transmitted) |
| Server HMAC key | Critical | Server (env var / secrets manager) |
| Server token signing key | Critical | Server (env var / secrets manager) |
| User email addresses | Medium | StorageAdapter |
| Device public keys | Low (non-secret) | StorageAdapter |
| Session tokens | Medium | Client (memory / secure storage) |

## Threat actors

### External attacker (no server access)

**What they can do**: intercept traffic (if TLS is absent), attempt login with guessed public keys

**What they cannot do**:
- Authenticate without the device's private key
- Forge tokens without the server signing key
- Crack challenges without the HMAC key

### Attacker with read access to the database

**What they can do**: read email addresses, read public keys, read device records

**What they cannot do**:
- Authenticate (private key is not in the database)
- Forge tokens (signing key is not in the database)
- Forge challenge MACs (HMAC key is not in the database)

**Conclusion**: A database breach leaks email addresses but not credentials. No passwords to crack.

### Attacker with full server compromise

**What they can do**: read the HMAC key and signing key, issue fraudulent tokens, intercept future logins

**What they cannot do**: recover private keys from any existing device, retroactively decrypt past sessions

**Mitigation**: rotate keys immediately on detected compromise; issue a new server key pair and invalidate all sessions by changing the signing key.

### Attacker with physical access to user device

**What they can do**: if the device is unlocked, potentially access keys stored in software (WebCrypto IndexedDB)

**What they cannot do**: extract keys from hardware-backed storage (Secure Enclave, Android Keystore, FIDO2 hardware key)

**Mitigation**: use WebAuthn/passkeys for hardware-backed key protection; require biometric unlock for key access.

## Out of scope

- Side-channel attacks on the server process
- Quantum computing attacks (P-384 is not post-quantum; plan migration to NIST post-quantum standards when available)
- Social engineering attacks against users
