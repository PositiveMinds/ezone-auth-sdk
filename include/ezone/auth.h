#pragma once

#include "crypto_engine.h"
#include "storage_adapter.h"
#include "types.h"
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ezone {

// ─── Server keys ──────────────────────────────────────────────────────────────
//
// Generate once with Auth::generate_server_keys().
// Persist them securely (env vars, HSM, secrets manager).
// Losing them invalidates all active sessions and magic links.

struct ServerKeys {
    SecureBuffer         hmac_key;              // 32-byte HMAC key (challenges + magic links)
    SecureBuffer         token_private_key_der; // P-384 private key (token signing)
    std::vector<uint8_t> token_public_key_der;  // P-384 public key  (token verification)
};


// ─── Config ───────────────────────────────────────────────────────────────────

struct AuthConfig {
    uint32_t magic_link_ttl_seconds  = 900;   // 15 min — how long registration/reset links live
    uint32_t session_ttl_seconds     = 3600;  // 1 hour — issued token lifetime
    uint32_t challenge_ttl_seconds   = 30;    // 30 sec  — login challenge window
    uint8_t  recovery_code_count     = 8;     // how many recovery codes to generate
    bool     revoke_all_on_reset     = false; // true = wipe all devices on account reset
};


// ─── Request / Response types ─────────────────────────────────────────────────

// Returned to the developer after a successful authenticate step.
// Pass `token` to verify_session() on subsequent requests.
struct AuthSession {
    std::string user_id;
    std::string email;
    std::string token;       // opaque signed token — validate with verify_session()
    std::string device_id;   // which device authenticated
    uint64_t    issued_at;
    uint64_t    expires_at;
};

// Returned from begin_registration / begin_reset / begin_add_device.
// Put `magic_token` in your email link: https://yourapp.com/auth?token=<magic_token>
struct PendingAuth {
    std::string magic_token;  // embed in email link
    uint64_t    expires_at;
};

// Sent to the client device during login (step 1).
// Device must sign `challenge_bytes` with its private key.
struct LoginChallenge {
    std::vector<uint8_t> challenge_bytes;  // serialised Challenge — sign this
    uint64_t             expires_at;
};

// Client sends this back after signing the login challenge (step 2).
struct ChallengeResponse {
    std::vector<uint8_t> challenge_bytes; // original bytes from LoginChallenge
    std::vector<uint8_t> signature;       // ECDSA-P384 over challenge_bytes
    std::vector<uint8_t> public_key_der;  // which device key signed it
};

// Recovery codes shown to the user once at registration.
// Store them somewhere safe — ezone only keeps HMAC hashes.
struct RecoveryCodes {
    std::vector<std::string> codes; // format: EZONE-XXXX-XXXX-XXXX
};


// ─── Auth ─────────────────────────────────────────────────────────────────────
//
// Main developer-facing class. One instance per application.
//
// Typical setup:
//   auto keys    = Auth::generate_server_keys().value;   // once, then persist
//   auto storage = std::make_shared<MemoryStorageAdapter>();
//   auto auth    = Auth::create(storage, std::move(keys)).value;

class Auth {
public:
    // Generate server keys — run once, persist the result in a secrets manager.
    static Result<ServerKeys> generate_server_keys();

    // Construct an Auth instance.
    static Result<Auth> create(
        std::shared_ptr<StorageAdapter> storage,
        ServerKeys                      keys,
        AuthConfig                      config = {}
    );

    Auth(Auth&&) noexcept;
    Auth& operator=(Auth&&) noexcept;
    ~Auth();

    // ── Registration ─────────────────────────────────────────────────────────

    // Step 1 — call this when a user submits their email to sign up.
    // Returns a magic token: embed in an email link and send to the user.
    // Returns an error if the email is already registered.
    Result<PendingAuth> begin_registration(const std::string& email);

    // Step 2 — call this when the user clicks the magic link.
    // public_key_der: SubjectPublicKeyInfo DER of the new device's P-384 key.
    // Returns an active session on success.
    Result<AuthSession> complete_registration(
        const std::string&          magic_token,
        const std::vector<uint8_t>& public_key_der,
        const std::string&          device_label = "My Device"
    );

    // ── Login ─────────────────────────────────────────────────────────────────

    // Step 1 — call when user submits their email to log in.
    // Returns a challenge to send to the user's device for signing.
    Result<LoginChallenge> begin_login(const std::string& email);

    // Step 2 — call with the signed challenge from the device.
    // Returns an active session on success.
    Result<AuthSession> complete_login(const ChallengeResponse& response);

    // ── Session management ────────────────────────────────────────────────────

    // Verify a token on every protected request (use in middleware / guards).
    // Returns session info on success, error if expired or invalid.
    Result<AuthSession> verify_session(const std::string& token);

    // Silently refresh a session before it expires.
    // The old token is still valid until it expires naturally.
    Result<AuthSession> refresh_session(const std::string& token);

    // Log out — optionally permanently revokes the device that issued the token.
    // Without revoke_device=true the token just expires on its own (1 hr max).
    Result<void> logout(const std::string& token, bool revoke_device = false);

    // ── Account reset ─────────────────────────────────────────────────────────

    // Step 1 — user says "I lost my device / can't log in".
    // Returns a magic token to email to the user.
    // Does NOT return an error for unknown emails (prevents user enumeration).
    Result<PendingAuth> begin_reset(const std::string& email);

    // Step 2 — user clicks reset link and registers a new device.
    // If AuthConfig::revoke_all_on_reset is true, all existing devices are revoked.
    Result<AuthSession> complete_reset(
        const std::string&          magic_token,
        const std::vector<uint8_t>& new_public_key_der,
        const std::string&          device_label = "My Device"
    );

    // ── Recovery codes ────────────────────────────────────────────────────────

    // Generate recovery codes for a user — call right after registration.
    // Show codes to the user exactly once; ezone only stores HMAC hashes.
    Result<RecoveryCodes> generate_recovery_codes(const std::string& user_id);

    // Use one recovery code to get a reset magic token (then call complete_reset).
    // The used code is invalidated immediately.
    Result<PendingAuth> recover_with_code(
        const std::string& email,
        const std::string& recovery_code
    );

    // ── Multi-device management ───────────────────────────────────────────────

    // Step 1 — authenticated user wants to add another device.
    // Returns a magic token for the new device to use.
    Result<PendingAuth> begin_add_device(const std::string& token);

    // Step 2 — new device completes registration.
    Result<AuthSession> complete_add_device(
        const std::string&          add_token,
        const std::vector<uint8_t>& new_public_key_der,
        const std::string&          device_label = "My Device"
    );

    // Revoke a device — requires an active session from another device.
    Result<void> revoke_device(
        const std::string& token,
        const std::string& device_id
    );

    // List all devices for the authenticated user.
    Result<std::vector<DeviceRecord>> list_devices(const std::string& token);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    explicit Auth(std::unique_ptr<Impl>);
};

} // namespace ezone
