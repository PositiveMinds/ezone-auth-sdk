#pragma once

#include "types.h"
#include <memory>

namespace ezone {

// ─── Configuration ────────────────────────────────────────────────────────────

struct CryptoConfig {
    uint32_t challenge_ttl_seconds  = 30;    // Auth challenge lifetime
    uint32_t token_ttl_seconds      = 3600;  // Issued token lifetime (1 hour)
    size_t   challenge_nonce_bytes  = 32;    // Challenge entropy size
    bool     require_fips           = false; // Abort if FIPS mode unavailable
};


// ─── CryptoEngine ─────────────────────────────────────────────────────────────
//
// Thread-safe after construction. All methods are const and stateless.
// Owns only configuration — no mutable OpenSSL state.

class CryptoEngine {
public:
    explicit CryptoEngine(const CryptoConfig& cfg = {});
    ~CryptoEngine();

    CryptoEngine(const CryptoEngine&)            = delete;
    CryptoEngine& operator=(const CryptoEngine&) = delete;

    // ── Key operations ──────────────────────────────────────────────────────

    // Generate a P-384 ECDSA keypair.
    // Private key returned as PKCS#8 DER inside SecureBuffer.
    // Public key returned as SubjectPublicKeyInfo DER.
    Result<KeyPair> generate_keypair() const;

    // Convert public key DER ↔ PEM
    Result<std::string>          public_key_to_pem(const std::vector<uint8_t>& der) const;
    Result<std::vector<uint8_t>> public_key_from_pem(const std::string& pem) const;

    // ── Signing ─────────────────────────────────────────────────────────────

    // ECDSA-P384 / SHA-384 sign.  Returns DER-encoded signature.
    Result<std::vector<uint8_t>> sign(
        const std::vector<uint8_t>& data,
        const SecureBuffer&         private_key_der
    ) const;

    // Verify ECDSA-P384 / SHA-384 signature.
    // Returns Result<true> on valid, Result<false> on invalid (not an error).
    Result<bool> verify(
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& signature_der,
        const std::vector<uint8_t>& public_key_der
    ) const;

    // ── Hashing ─────────────────────────────────────────────────────────────

    Result<std::vector<uint8_t>> hash_sha384(const std::vector<uint8_t>& data) const;
    Result<std::vector<uint8_t>> hash_sha512(const std::vector<uint8_t>& data) const;

    // HMAC-SHA384
    Result<std::vector<uint8_t>> hmac_sha384(
        const std::vector<uint8_t>& data,
        const SecureBuffer&         key
    ) const;

    // ── Symmetric encryption ────────────────────────────────────────────────

    // AES-256-GCM encrypt.
    // Output layout: [ IV (12 B) | ciphertext | GCM tag (16 B) ]
    // aad: optional additional authenticated data (authenticated, not encrypted)
    Result<std::vector<uint8_t>> encrypt_aes256gcm(
        const std::vector<uint8_t>& plaintext,
        const SecureBuffer&         key,
        const std::vector<uint8_t>& aad = {}
    ) const;

    // AES-256-GCM decrypt.  Expects the layout produced by encrypt_aes256gcm.
    Result<SecureBuffer> decrypt_aes256gcm(
        const std::vector<uint8_t>& ciphertext_bundle,
        const SecureBuffer&         key,
        const std::vector<uint8_t>& aad = {}
    ) const;

    // ── Randomness ──────────────────────────────────────────────────────────

    Result<std::vector<uint8_t>> random_bytes(size_t count) const;
    Result<SecureBuffer>         generate_symmetric_key() const;  // 256-bit AES key

    // ── Challenge / Response ─────────────────────────────────────────────────

    // Issue a time-bound, MAC-protected challenge.
    // signing_key: HMAC key held server-side; prevents client forgery.
    Result<Challenge> generate_challenge(const SecureBuffer& signing_key) const;

    // Return true if the challenge is structurally valid, MAC correct, and
    // not expired.  Returns false (not an error) if expired or MAC mismatch.
    Result<bool> verify_challenge(
        const Challenge&    challenge,
        const SecureBuffer& signing_key
    ) const;

    // Compact wire serialisation: nonce‖issued_at(8B BE)‖ttl(4B BE)‖mac
    Result<std::vector<uint8_t>> serialize_challenge(const Challenge& ch) const;
    Result<Challenge>            deserialize_challenge(const std::vector<uint8_t>& data) const;

    // ── Token issuance ───────────────────────────────────────────────────────

    // Issue a stateless auth token (signed compact JSON, similar to JWT).
    // signing_key: P-384 private key DER.
    Result<AuthToken> issue_token(
        const std::string&  user_id,
        const SecureBuffer& private_key_der
    ) const;

    // Verify and decode a token.
    // public_key_der: P-384 public key of the issuer.
    Result<AuthToken> verify_token(
        const std::string&           encoded_token,
        const std::vector<uint8_t>&  public_key_der
    ) const;

    // ── Utilities ────────────────────────────────────────────────────────────

    // Constant-time comparison — never short-circuit (prevents timing attacks)
    static bool constant_time_equal(
        const std::vector<uint8_t>& a,
        const std::vector<uint8_t>& b
    ) noexcept;

    static std::string              base64url_encode(const std::vector<uint8_t>& data);
    static Result<std::vector<uint8_t>> base64url_decode(const std::string& encoded);

    // True when the linked OpenSSL is running in FIPS mode
    static bool is_fips_mode() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ezone
