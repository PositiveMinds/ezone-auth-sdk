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

    // Derive the ezone device_id for a public key: hex(SHA-384(public_key_der)[0:16]).
    // This is the same identifier scheme used internally for challenge-response
    // and push devices, exposed here so callers (e.g. the REST layer) can look
    // devices up by public key for methods — like biometric login — that only
    // learn the signer's identity after verifying a signature.
    static Result<std::string> derive_device_id(const std::vector<uint8_t>& public_key_der);

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
    // device_id: embedded in the token so verify_token can report exactly
    // which device this session belongs to (optional — empty if unused).
    Result<AuthToken> issue_token(
        const std::string&  user_id,
        const SecureBuffer& private_key_der,
        const std::string&  device_id = ""
    ) const;

    // Verify and decode a token.
    // public_key_der: P-384 public key of the issuer.
    Result<AuthToken> verify_token(
        const std::string&           encoded_token,
        const std::vector<uint8_t>&  public_key_der
    ) const;

#ifdef EZONE_LIBSODIUM_ENABLED
    // Issue token using Ed25519 (faster, smaller than P-384)
    // signing_key: 64-byte Ed25519 private key
    Result<AuthToken> issue_token_ed25519(
        const std::string&  user_id,
        const SecureBuffer& private_key,
        const std::string&  device_id = ""
    ) const;

    // Verify Ed25519-signed token
    // public_key: 32-byte Ed25519 public key
    Result<AuthToken> verify_token_ed25519(
        const std::string&           encoded_token,
        const std::vector<uint8_t>&  public_key
    ) const;
#endif

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

    // True when Libsodium is available
    static bool has_libsodium() noexcept;

    // ── Libsodium-backed methods ─────────────────────────────────────────────
    // These provide modern crypto primitives not in OpenSSL:
    //   • Ed25519 — fast signatures (good for mobile)
    //   • X25519  — key exchange
    //   • ChaCha20-Poly1305 — fast AEAD (no AES-NI needed)
    //   • Argon2id — memory-hard KDF
    //   • sodium_memcmp — constant-time comparison
    //   • sodium_memzero — secure memory wiping
    //
    // Declared unconditionally (regardless of EZONE_USE_LIBSODIUM) so callers
    // can branch on has_libsodium() at runtime without needing their own
    // #ifdef. When built without Libsodium, every method below returns a
    // "Libsodium not enabled" failure instead of doing anything.

    // Ed25519 keypair generation (64-byte private key, 32-byte public key)
    struct Ed25519KeyPair {
        SecureBuffer         private_key;  // 64 bytes (seed + public)
        std::vector<uint8_t> public_key;   // 32 bytes
    };
    Result<Ed25519KeyPair> generate_ed25519_keypair() const;

    // Ed25519 sign (returns 64-byte signature)
    Result<std::vector<uint8_t>> sign_ed25519(
        const std::vector<uint8_t>& message,
        const SecureBuffer& private_key
    ) const;

    // Ed25519 verify
    Result<bool> verify_ed25519(
        const std::vector<uint8_t>& message,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& public_key
    ) const;

    // X25519 key exchange
    struct X25519KeyPair {
        SecureBuffer         private_key;  // 32 bytes
        std::vector<uint8_t> public_key;   // 32 bytes
    };
    Result<X25519KeyPair> generate_x25519_keypair() const;

    Result<std::vector<uint8_t>> x25519_exchange(
        const SecureBuffer& private_key,
        const std::vector<uint8_t>& peer_public_key
    ) const;

    // ChaCha20-Poly1305 AEAD encrypt (faster than AES-GCM on mobile)
    // Output: nonce(12) || ciphertext || tag(16)
    Result<std::vector<uint8_t>> encrypt_chacha20poly1305(
        const std::vector<uint8_t>& plaintext,
        const SecureBuffer& key,
        const std::vector<uint8_t>& aad = {}
    ) const;

    // ChaCha20-Poly1305 AEAD decrypt
    Result<SecureBuffer> decrypt_chacha20poly1305(
        const std::vector<uint8_t>& ciphertext_bundle,
        const SecureBuffer& key,
        const std::vector<uint8_t>& aad = {}
    ) const;

    // Argon2id key derivation (memory-hard — resistant to GPU attacks)
    // password: the input secret
    // salt: random salt (16 bytes recommended)
    // ops_limit: time cost (e.g. crypto_pwhash_OPSLIMIT_SENSITIVE)
    // mem_limit: memory cost in bytes (e.g. 256MB)
    Result<SecureBuffer> argon2id_derive(
        const std::vector<uint8_t>& password,
        const std::vector<uint8_t>& salt,
        uint32_t ops_limit = 4,
        size_t mem_limit = 256 * 1024 * 1024
    ) const;

    // Constant-time comparison using Libsodium
    static bool sodium_memcmp(
        const std::vector<uint8_t>& a,
        const std::vector<uint8_t>& b
    ) noexcept;

    // Secure memory zeroing using Libsodium
    static void sodium_memzero(void* ptr, size_t size) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ezone
