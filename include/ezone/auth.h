#pragma once

#include "crypto_engine.h"
#include "crypto_strategy.h"
#include "storage_adapter.h"
#include "types.h"
#include <functional>
#include <memory>
#include <string>
#include <vector>

// Forward declarations for optional auth method servers
namespace ezone {
class WebAuthnServer;
class QRAuthServer;
class PushAuthServer;
class BiometricAuthServer;
class OTPServer;
}

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


// ─── Auth methods ─────────────────────────────────────────────────────────────
//
// Each method is optional — enable only the ones your app needs.
// Developers choose their auth stack by setting enabled_methods.

enum class AuthMethod : uint8_t {
    Challenge   = 0x01,  // ECDSA challenge-response (default, always available)
    MagicLink   = 0x02,  // Email magic links for registration/reset
    Recovery    = 0x04,  // Single-use recovery codes
    WebAuthn    = 0x08,  // FIDO2/WebAuthn (FaceID, TouchID, Windows Hello, YubiKey)
    QRCode      = 0x10,  // QR code cross-device login
    Push        = 0x20,  // Mobile push notification approval
    OTP         = 0x40,  // SMS/Email one-time password
};

// Bitfield helper — combine with |
inline AuthMethod operator|(AuthMethod a, AuthMethod b) {
    return static_cast<AuthMethod>(
        static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}
inline bool has_method(uint8_t enabled, AuthMethod m) {
    return (enabled & static_cast<uint8_t>(m)) != 0;
}

// Convenience constants
constexpr uint8_t AUTH_METHOD_DEFAULT =
    static_cast<uint8_t>(AuthMethod::Challenge) |
    static_cast<uint8_t>(AuthMethod::MagicLink) |
    static_cast<uint8_t>(AuthMethod::Recovery);

constexpr uint8_t AUTH_METHOD_ALL = 0xFF;


// ─── Config ───────────────────────────────────────────────────────────────────

struct AuthConfig {
    uint32_t magic_link_ttl_seconds  = 900;   // 15 min — how long registration/reset links live
    uint32_t session_ttl_seconds     = 3600;  // 1 hour — issued token lifetime
    uint32_t challenge_ttl_seconds   = 30;    // 30 sec  — login challenge window
    uint8_t  recovery_code_count     = 8;     // how many recovery codes to generate
    bool     revoke_all_on_reset     = false; // true = wipe all devices on account reset

    // ── Enabled auth methods (bitfield) ─────────────────────────────────────
    // Default: Challenge + MagicLink + Recovery (the original ezone stack)
    // Use AUTH_METHOD_ALL to enable everything.
    uint8_t  enabled_methods = AUTH_METHOD_DEFAULT;

    // ── WebAuthn config ─────────────────────────────────────────────────────
    std::string webauthn_rp_id   = "localhost";  // Relying Party ID (your domain)
    std::string webauthn_rp_name = "ezone App";  // Relying Party display name

    // ── QR code config ──────────────────────────────────────────────────────
    uint32_t qr_ttl_seconds = 300;  // 5 min — QR code validity window
    std::string qr_server_url;      // base URL embedded in QR (e.g. "https://auth.example.com")

    // ── Push config ─────────────────────────────────────────────────────────
    uint32_t push_ttl_seconds = 120; // 2 min — push approval window

    // ── OTP config ───────────────────────────────────────────────────────────
    uint32_t otp_code_length       = 6;    // digits
    uint32_t otp_expiry_seconds    = 300;  // 5 minutes
    uint32_t otp_max_attempts      = 3;    // before lockout
    uint32_t otp_lockout_seconds   = 900;  // 15 minutes lockout
    uint32_t otp_rate_limit_ip     = 10;   // per IP per 15 min
    uint32_t otp_rate_limit_phone  = 5;    // per phone/email per 15 min

    // ── Crypto strategy ──────────────────────────────────────────────────────
    // Controls which algorithms are used (auto-detected based on platform)
    CryptoStrategyConfig crypto_strategy;
};


// ─── Request / Response types ─────────────────────────────────────────────────

// Returned to the developer after a successful authenticate step.
// Pass `token` to verify_session() on subsequent requests.
struct AuthSession {
    std::string user_id;
    std::string email;
    std::string username;    // optional — if user registered with a username
    std::string display_name; // optional — shown in UI
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
    // Grants Result<Auth>::failure() access to the private default
    // constructor below — Result<T> needs a placeholder T value to
    // construct a failure result, but Auth has no publicly-constructible
    // "empty" state by design.
    friend struct Result<Auth>;

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

    // Step 1 — call when user submits their email or username to log in.
    // Returns a challenge to send to the user's device for signing.
    // Accepts either email or username — the system looks up the account.
    Result<LoginChallenge> begin_login(const std::string& identifier);

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

    // Issue a session for a user + device that another auth method
    // (WebAuthn, QR, push) has already independently verified.
    // device_id must refer to a DeviceRecord already registered in storage
    // (add_device) belonging to user_id and not revoked.
    Result<AuthSession> create_session(
        const std::string& user_id,
        const std::string& device_id
    );

    // ── Auth method accessors (return nullptr if method not enabled) ──────
    //
    // These return the underlying auth method server if enabled, or nullptr
    // if the method is not in enabled_methods. Use these for method-specific
    // operations (e.g. WebAuthn registration, QR polling, push approval).

    // Check if a specific method is enabled
    bool is_method_enabled(AuthMethod method) const;

    // Get the WebAuthn server (returns nullptr if AuthMethod::WebAuthn not enabled)
    WebAuthnServer* webauthn();
    const WebAuthnServer* webauthn() const;

    // Get the QR auth server (returns nullptr if AuthMethod::QRCode not enabled)
    QRAuthServer* qr_auth();
    const QRAuthServer* qr_auth() const;

    // Get the push auth server (returns nullptr if AuthMethod::Push not enabled)
    PushAuthServer* push_auth();
    const PushAuthServer* push_auth() const;

    // Get the biometric auth server (returns nullptr if not initialized)
    BiometricAuthServer* biometric();
    const BiometricAuthServer* biometric() const;

    // Get the OTP server (returns nullptr if AuthMethod::OTP not enabled)
    OTPServer* otp();
    const OTPServer* otp() const;

    // Get the underlying storage adapter
    std::shared_ptr<StorageAdapter> storage();

    // Get the server keys
    const ServerKeys& keys() const;

    // Get the config
    const AuthConfig& config() const;

private:
    // Only reachable via the Result<Auth> friendship above — produces an
    // empty, unusable instance (impl_ == nullptr). Never call directly;
    // use Auth::create() to get a real, usable Auth.
    Auth() noexcept;

    struct Impl;
    std::unique_ptr<Impl> impl_;
    explicit Auth(std::unique_ptr<Impl>);
};

} // namespace ezone
