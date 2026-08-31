#pragma once

#include "crypto_engine.h"
#include "types.h"
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ezone {

// ─── Biometric Types ─────────────────────────────────────────────────────────

// Supported biometric types
enum class BiometricType : uint8_t {
    None        = 0,
    Fingerprint = 1,  // TouchID (iOS), fingerprint scanner (Android)
    Face        = 2,  // FaceID (iOS), face unlock (Android)
    Iris        = 3,  // Iris scanner (Samsung)
};

const char* biometric_type_string(BiometricType t) noexcept;

// Device biometric capabilities (queried at startup)
struct BiometricCapability {
    BiometricType type         = BiometricType::None;
    bool          available    = false;  // hardware present
    bool          enrolled     = false;  // user has enrolled biometrics
    std::string   device_name;           // e.g. "iPhone 15 Pro", "Pixel 8"
    std::string   error_message;         // reason if not available
};

// Result of a biometric authentication attempt
struct BiometricResult {
    bool                    success = false;
    BiometricType           matched_type = BiometricType::None;
    std::vector<uint8_t>    signature;       // ECDSA signature over the challenge
    std::vector<uint8_t>    public_key_der;  // device's public key
    std::string             error_message;   // human-readable error if failed
};

// Encrypted payload stored on the device — protects the private key at rest
struct BiometricKeyPayload {
    std::vector<uint8_t> encrypted_private_key; // AES-256-GCM encrypted PKCS#8 DER
    std::vector<uint8_t> iv;                     // 12-byte IV for AES-GCM
    std::vector<uint8_t> tag;                    // 16-byte GCM auth tag
    std::string          key_id;                 // identifier for this key
    BiometricType        biometric_type = BiometricType::None;
};

// ─── Biometric Auth Session ──────────────────────────────────────────────────
//
// Unified interface for biometric authentication across platforms.
// Developers use this to check capabilities, generate keys, sign challenges,
// and manage biometric-protected credentials.

// Platform-specific biometric provider interface.
// Implement for each platform (iOS, Android, Desktop).
class BiometricProvider {
public:
    virtual ~BiometricProvider() = default;

    // Check if biometric hardware is available and enrolled
    virtual BiometricCapability check_capability() = 0;

    // Generate a P-384 keypair protected by biometrics.
    // The private key is encrypted at rest and only accessible after biometric auth.
    // Returns the public key and an encrypted payload for storage.
    virtual Result<BiometricKeyPayload> generate_protected_key(
        const std::string& key_id = ""
    ) = 0;

    // Authenticate using biometrics and sign data with the protected key.
    // This triggers the OS biometric prompt (FaceID/TouchID/fingerprint).
    // prompt_message: text shown to the user (e.g. "Sign in to your account")
    virtual Result<BiometricResult> authenticate_and_sign(
        const BiometricKeyPayload& payload,
        const std::vector<uint8_t>& data_to_sign,
        const std::string& prompt_message = "Authenticate"
    ) = 0;

    // Delete a protected key (removes from secure enclave / keychain)
    virtual Result<void> delete_protected_key(const std::string& key_id) = 0;
};


// ─── BiometricAuthServer ─────────────────────────────────────────────────────
//
// Server-side biometric authentication.
// Works with any BiometricProvider implementation.
// Challenge-response flow: server issues challenge, device signs with
// biometric-protected key, server verifies signature.

class BiometricAuthServer {
public:
    BiometricAuthServer(
        CryptoEngine& engine,
        const SecureBuffer& hmac_key,
        uint32_t challenge_ttl_seconds = 30
    );
    ~BiometricAuthServer();

    BiometricAuthServer(const BiometricAuthServer&) = delete;
    BiometricAuthServer& operator=(const BiometricAuthServer&) = delete;

    // ── Challenge generation ─────────────────────────────────────────────────

    // Generate a challenge for biometric signing.
    // Returns base64url-encoded challenge bytes.
    Result<std::string> generate_challenge();

    // Verify a challenge was issued by this server.
    bool verify_challenge(const std::string& challenge_b64);

    // ── Registration ─────────────────────────────────────────────────────────

    // Register a new biometric-protected key.
    // The client calls BiometricProvider::generate_protected_key() first,
    // then sends the public key and encrypted payload here.
    Result<std::string> register_biometric_key(
        const std::string& user_id,
        const std::string& challenge_b64,
        const std::vector<uint8_t>& public_key_der,
        const BiometricKeyPayload& encrypted_payload,
        const std::string& label = "Biometric"
    );

    // ── Authentication ───────────────────────────────────────────────────────

    // Verify a biometric authentication response.
    // The client calls BiometricProvider::authenticate_and_sign() first,
    // then sends the signature and public key here.
    Result<std::string> verify_biometric_response(
        const std::string& challenge_b64,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& public_key_der
    );

    // ── Integration with Auth class ──────────────────────────────────────────

    // Complete biometric login — verify + issue session token.
    // stored_pub_key: the public key registered for this user's biometric
    Result<std::pair<std::string, std::string>> complete_biometric_login(
        const std::string& challenge_b64,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& public_key_der
    );

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};


// ─── Convenience: Full biometric flow in one call ────────────────────────────
//
// For simple integrations, this runs the entire biometric auth flow:
// 1. Check biometric capability
// 2. Generate challenge
// 3. Sign with biometric
// 4. Verify on server
//
// Returns the signed challenge + public key to send to the server.

struct BiometricFlowResult {
    bool                    capability_ok = false;
    BiometricCapability     capability;
    std::string             challenge;
    BiometricResult         sign_result;
    std::string             error;
};

// Run the full client-side biometric flow.
// Provider: platform-specific BiometricProvider
// key_payload: the encrypted key stored on this device (from registration)
// prompt_message: what to show the user during biometric prompt
BiometricFlowResult run_biometric_flow(
    BiometricProvider& provider,
    const BiometricKeyPayload& key_payload,
    const std::string& prompt_message = "Sign in to your account"
);

} // namespace ezone
