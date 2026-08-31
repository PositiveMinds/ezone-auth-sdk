#include "ezone/crypto_strategy.h"

#include <openssl/evp.h>

#ifdef EZONE_LIBSODIUM_ENABLED
#include <sodium.h>
#endif

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace ezone {

// ─── Platform Detection ──────────────────────────────────────────────────────

namespace {

bool detect_aes_ni() {
#if defined(__AES__) && (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    #ifdef _MSC_VER
        int cpu_info[4];
        __cpuid(cpu_info, 1);
        return (cpu_info[2] & (1 << 25)) != 0; // AES-NI bit
    #else
        #ifdef __AES__
            return true; // Compiler enabled AES-NI
        #else
            return false;
        #endif
    #endif
#else
    return false; // Not x86 or no AES-NI support
#endif
}

bool detect_libsodium() {
#ifdef EZONE_LIBSODIUM_ENABLED
    return true;
#else
    return false;
#endif
}

bool detect_fips() {
    return CryptoEngine::is_fips_mode();
}

} // anonymous namespace


// ─── CryptoStrategy::Impl ────────────────────────────────────────────────────

struct CryptoStrategy::Impl {
    CryptoStrategyConfig config;
    bool aes_ni = false;
    bool libsodium = false;
    bool fips = false;

    Impl(const CryptoStrategyConfig& cfg)
        : config(cfg)
        , aes_ni(detect_aes_ni())
        , libsodium(detect_libsodium())
        , fips(detect_fips())
    {}

    // Determine which signing algorithm to use
    std::string select_signing() const {
        // FIPS mode → must use P-384
        if (config.require_fips || fips)
            return "p384";

        // Explicit override
        if (config.prefer_ed25519 && libsodium)
            return "ed25519";

        // Profile-based selection
        switch (config.profile) {
            case CryptoProfile::FIPS:
                return "p384";

            case CryptoProfile::Performance:
                return libsodium ? "ed25519" : "p384";

            case CryptoProfile::Balanced:
                // Ed25519 for mobile (no AES-NI), P-384 for server
                return (!aes_ni && libsodium) ? "ed25519" : "p384";

            case CryptoProfile::Auto:
            default:
                // Best available: Ed25519 if Libsodium + no AES-NI (mobile), else P-384
                return (!aes_ni && libsodium) ? "ed25519" : "p384";
        }
    }

    // Determine which encryption algorithm to use
    std::string select_encryption() const {
        // FIPS mode → must use AES-256-GCM
        if (config.require_fips || fips)
            return "aes-256-gcm";

        // Explicit override
        if (config.prefer_chacha20 && libsodium)
            return "chacha20-poly1305";

        // Profile-based selection
        switch (config.profile) {
            case CryptoProfile::FIPS:
                return "aes-256-gcm";

            case CryptoProfile::Performance:
                return libsodium ? "chacha20-poly1305" : "aes-256-gcm";

            case CryptoProfile::Balanced:
                // ChaCha20 on mobile (no AES-NI), AES-GCM on server
                return (!aes_ni && libsodium) ? "chacha20-poly1305" : "aes-256-gcm";

            case CryptoProfile::Auto:
            default:
                return (!aes_ni && libsodium) ? "chacha20-poly1305" : "aes-256-gcm";
        }
    }

    // Determine which KDF to use
    std::string select_kdf() const {
        if (config.require_fips || fips)
            return "pbkdf2"; // FIPS-approved KDF

        return libsodium ? "argon2id" : "pbkdf2";
    }
};


// ─── CryptoStrategy public API ───────────────────────────────────────────────

CryptoStrategy::CryptoStrategy(const CryptoStrategyConfig& config)
    : impl_(std::make_unique<Impl>(config))
{}

CryptoStrategy::~CryptoStrategy() = default;


bool CryptoStrategy::use_ed25519() const {
    return impl_->select_signing() == "ed25519";
}

bool CryptoStrategy::use_chacha20() const {
    return impl_->select_encryption() == "chacha20-poly1305";
}

bool CryptoStrategy::use_argon2() const {
    return impl_->select_kdf() == "argon2id";
}

size_t CryptoStrategy::signing_key_size() const {
    return use_ed25519() ? 64 : 48; // Ed25519: 64 bytes, P-384: 48 bytes
}

size_t CryptoStrategy::encryption_key_size() const {
    return 32; // Both AES-256 and ChaCha20 use 32-byte keys
}


Result<CryptoStrategy::SigningKeyPair>
CryptoStrategy::generate_signing_keypair(CryptoEngine& engine) const {
    SigningKeyPair kp;

#ifdef EZONE_LIBSODIUM_ENABLED
    if (use_ed25519()) {
        auto result = engine.generate_ed25519_keypair();
        if (!result) return Result<SigningKeyPair>::failure(result.error);
        kp.private_key = std::move(result.value.private_key);
        kp.public_key = std::move(result.value.public_key);
        kp.algorithm = "ed25519";
        return Result<SigningKeyPair>::success(std::move(kp));
    }
#endif
    // Fallback to P-384
    auto result = engine.generate_keypair();
    if (!result) return Result<SigningKeyPair>::failure(result.error);
    kp.private_key = std::move(result.value.private_key_der);
    kp.public_key = std::move(result.value.public_key_der);
    kp.algorithm = "p384";
    return Result<SigningKeyPair>::success(std::move(kp));
}


Result<std::vector<uint8_t>> CryptoStrategy::sign(
    CryptoEngine& engine,
    const std::vector<uint8_t>& data,
    const SecureBuffer& private_key,
    const std::string& algorithm) const
{
#ifdef EZONE_LIBSODIUM_ENABLED
    if (algorithm == "ed25519")
        return engine.sign_ed25519(data, private_key);
#else
    (void)algorithm;
#endif
    return engine.sign(data, private_key);
}


Result<bool> CryptoStrategy::verify(
    CryptoEngine& engine,
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& public_key,
    const std::string& algorithm) const
{
#ifdef EZONE_LIBSODIUM_ENABLED
    if (algorithm == "ed25519")
        return engine.verify_ed25519(data, signature, public_key);
#else
    (void)algorithm;
#endif
    return engine.verify(data, signature, public_key);
}


Result<std::vector<uint8_t>> CryptoStrategy::encrypt(
    CryptoEngine& engine,
    const std::vector<uint8_t>& plaintext,
    const SecureBuffer& key,
    const std::vector<uint8_t>& aad) const
{
#ifdef EZONE_LIBSODIUM_ENABLED
    if (use_chacha20())
        return engine.encrypt_chacha20poly1305(plaintext, key, aad);
#endif
    return engine.encrypt_aes256gcm(plaintext, key, aad);
}


Result<SecureBuffer> CryptoStrategy::decrypt(
    CryptoEngine& engine,
    const std::vector<uint8_t>& ciphertext,
    const SecureBuffer& key,
    const std::vector<uint8_t>& aad) const
{
#ifdef EZONE_LIBSODIUM_ENABLED
    if (use_chacha20())
        return engine.decrypt_chacha20poly1305(ciphertext, key, aad);
#endif
    return engine.decrypt_aes256gcm(ciphertext, key, aad);
}


Result<SecureBuffer> CryptoStrategy::derive_key(
    CryptoEngine& engine,
    const std::vector<uint8_t>& password,
    const std::vector<uint8_t>& salt,
    size_t output_length) const
{
#ifdef EZONE_LIBSODIUM_ENABLED
    if (use_argon2()) {
        return engine.argon2id_derive(password, salt);
    }
#else
    (void)engine; // unused without Libsodium — PBKDF2 fallback below uses OpenSSL directly
#endif
    // Fallback: PBKDF2-HMAC-SHA384 (FIPS-approved iterated, salted KDF).
    // Iteration count follows OWASP's 2023 guidance for PBKDF2-HMAC-SHA-256+
    // (>= 600,000) — deliberately slow to resist brute force / GPU attacks.
    const int iterations = 600000;

    SecureBuffer result(output_length);
    if (PKCS5_PBKDF2_HMAC(
            reinterpret_cast<const char*>(password.data()),
            static_cast<int>(password.size()),
            salt.data(), static_cast<int>(salt.size()),
            iterations, EVP_sha384(),
            static_cast<int>(output_length), result.data()) != 1) {
        return Result<SecureBuffer>::failure("PBKDF2 key derivation failed");
    }
    return Result<SecureBuffer>::success(std::move(result));
}


std::string CryptoStrategy::describe() const {
    std::string desc = "CryptoStrategy: {\n";
    desc += "  signing: " + impl_->select_signing() + "\n";
    desc += "  encryption: " + impl_->select_encryption() + "\n";
    desc += "  kdf: " + impl_->select_kdf() + "\n";
    desc += "  platform: aes_ni=" + std::string(impl_->aes_ni ? "yes" : "no");
    desc += ", libsodium=" + std::string(impl_->libsodium ? "yes" : "no");
    desc += ", fips=" + std::string(impl_->fips ? "yes" : "no") + "\n";
    desc += "}";
    return desc;
}


bool CryptoStrategy::has_aes_ni() { return detect_aes_ni(); }
bool CryptoStrategy::has_libsodium() { return detect_libsodium(); }
bool CryptoStrategy::has_fips() { return detect_fips(); }

} // namespace ezone
