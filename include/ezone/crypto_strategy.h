#pragma once

#include "crypto_engine.h"
#include "types.h"
#include <string>

namespace ezone {

// ─── Crypto Strategy ─────────────────────────────────────────────────────────
//
// Automatically selects the best cryptographic algorithm for each use case
// based on platform capabilities:
//
//   Platform                    Signing        Encryption       KDF
//   ─────────────────────────── ────────────── ──────────────── ──────────────
//   Server (AES-NI)             P-384 / Ed25519 AES-256-GCM     Argon2id
//   Mobile (no AES-NI)          Ed25519         ChaCha20-Poly1305 Argon2id
//   FIPS mode                   P-384           AES-256-GCM     N/A (use PBKDF2)
//   Embedded (resource-constrained) Ed25519     ChaCha20-Poly1305 Argon2id-lite
//
// Developers can override any selection via CryptoConfig.

enum class CryptoProfile : uint8_t {
    Auto       = 0,  // Best algorithm for platform (default)
    FIPS       = 1,  // NSA Suite B only (P-384 + AES-256-GCM)
    Performance = 2,  // Fastest available (Ed25519 + ChaCha20)
    Balanced   = 3,  // Good security + performance
};

struct CryptoStrategyConfig {
    CryptoProfile profile = CryptoProfile::Auto;

    // Override specific algorithms (only used when profile = Auto or Balanced)
    bool prefer_ed25519 = false;     // Use Ed25519 instead of P-384
    bool prefer_chacha20 = false;    // Use ChaCha20 instead of AES-GCM
    bool require_fips = false;       // Force FIPS-approved algorithms only
};

class CryptoStrategy {
public:
    explicit CryptoStrategy(const CryptoStrategyConfig& config = {});
    ~CryptoStrategy();

    CryptoStrategy(const CryptoStrategy&) = delete;
    CryptoStrategy& operator=(const CryptoStrategy&) = delete;

    // ── Algorithm Selection ──────────────────────────────────────────────────

    // Should we use Ed25519 for signing?
    bool use_ed25519() const;

    // Should we use ChaCha20-Poly1305 for encryption?
    bool use_chacha20() const;

    // Should we use Argon2id for key derivation?
    bool use_argon2() const;

    // Get the recommended signing key size
    size_t signing_key_size() const;

    // Get the recommended encryption key size
    size_t encryption_key_size() const;

    // ── High-Level Operations ────────────────────────────────────────────────
    //
    // These use the best available algorithm automatically.

    // Generate a signing keypair (Ed25519 or P-384 based on strategy)
    struct SigningKeyPair {
        SecureBuffer         private_key;
        std::vector<uint8_t> public_key;
        std::string          algorithm;  // "ed25519" or "p384"
    };
    Result<SigningKeyPair> generate_signing_keypair(CryptoEngine& engine) const;

    // Sign data with the best available algorithm
    Result<std::vector<uint8_t>> sign(
        CryptoEngine& engine,
        const std::vector<uint8_t>& data,
        const SecureBuffer& private_key,
        const std::string& algorithm
    ) const;

    // Verify signature
    Result<bool> verify(
        CryptoEngine& engine,
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& public_key,
        const std::string& algorithm
    ) const;

    // Encrypt data with the best available algorithm
    Result<std::vector<uint8_t>> encrypt(
        CryptoEngine& engine,
        const std::vector<uint8_t>& plaintext,
        const SecureBuffer& key,
        const std::vector<uint8_t>& aad = {}
    ) const;

    // Decrypt data
    Result<SecureBuffer> decrypt(
        CryptoEngine& engine,
        const std::vector<uint8_t>& ciphertext,
        const SecureBuffer& key,
        const std::vector<uint8_t>& aad = {}
    ) const;

    // Derive a key from a password using the best available KDF
    Result<SecureBuffer> derive_key(
        CryptoEngine& engine,
        const std::vector<uint8_t>& password,
        const std::vector<uint8_t>& salt,
        size_t output_length = 32
    ) const;

    // ── Info ─────────────────────────────────────────────────────────────────

    // Get a human-readable description of the selected algorithms
    std::string describe() const;

    // Check platform capabilities
    static bool has_aes_ni();
    static bool has_libsodium();
    static bool has_fips();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ezone
