---
id: cryptography
title: Cryptography
---

# Cryptography

All cryptographic operations in ezone use standardised, peer-reviewed algorithms implemented by OpenSSL 3.x.

## Algorithms

### ECDSA P-384 (NSA Suite B)

Used for keypair generation, signing, and verification.

- 384-bit key length provides ~192-bit security level
- Part of NSA Suite B (approved for SECRET and TOP SECRET)
- Standardised in FIPS 186-5 and ANSI X9.62
- Keys serialised as DER-encoded SubjectPublicKeyInfo (SPKI) for cross-platform compatibility

### AES-256-GCM

Used for symmetric encryption of sensitive data at rest.

- 256-bit key, authenticated encryption (provides both confidentiality and integrity)
- 96-bit (12-byte) random IV per encryption operation
- 128-bit authentication tag
- NIST SP 800-38D compliant
- Wire format: `IV(12B) | ciphertext | tag(16B)`

### SHA-384 / SHA-512

Used for hashing. SHA-384 is the default; SHA-512 is available for applications requiring 256-bit security.

- Part of SHA-2 family (FIPS 180-4)
- 384-bit output for SHA-384

### HMAC-SHA384

Used for challenge and magic link authentication.

- Provides message authentication with a secret key
- FIPS 198-1 compliant
- Output: 48 bytes (384 bits)
- Challenge wire format binds nonce + timestamp + TTL

## Key derivation

ezone does not implement its own KDF. Key material is either:
- **Generated fresh**: via `EVP_EC_gen("P-384")` for device keys, `RAND_bytes` for symmetric keys
- **Derived via HKDF**: when splitting a master secret (OpenSSL 3 EVP_KDF)

## SecureBuffer

All private key material is held in `SecureBuffer`, a C++ wrapper that:
1. Allocates on the heap (not stack, to control lifetime)
2. Zeroes the memory via `OPENSSL_cleanse()` on destruction
3. Is non-copyable (only movable) to prevent accidental duplication

```cpp
class SecureBuffer {
    std::vector<uint8_t> data_;
public:
    ~SecureBuffer() {
        if (!data_.empty())
            OPENSSL_cleanse(data_.data(), data_.size());
    }
    // copy constructor = delete
    // copy assignment  = delete
};
```

## FIPS 140-3 mode

When `require_fips = true` in `CryptoConfig`, ezone calls `EVP_default_properties_enable_fips(nullptr, 1)` during initialisation. If the OpenSSL FIPS provider is not loaded, initialisation fails with `CryptoError::FipsUnavailable`.

All algorithms used by ezone are approved under FIPS 140-3:
- AES-256-GCM: ✓ SP 800-38D
- ECDSA P-384: ✓ FIPS 186-5
- SHA-384: ✓ FIPS 180-4
- HMAC-SHA384: ✓ FIPS 198-1

## Randomness

All random bytes come from `RAND_bytes()` (OpenSSL), which uses the OS CSPRNG:
- Linux: `getrandom(2)` / `/dev/urandom`
- macOS: `CCRandomGenerateBytes`
- Windows: `BCryptGenRandom`

## What ezone does NOT do

- No password hashing (no passwords exist)
- No RSA (prefer elliptic curves for equivalent security with smaller keys)
- No MD5, SHA-1 (deprecated)
- No ECB mode
- No deterministic nonces
