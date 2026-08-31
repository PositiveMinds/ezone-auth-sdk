#pragma once

#include "crypto_engine.h"
#include "types.h"
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ezone {

// ─── OTP Types ───────────────────────────────────────────────────────────────

// OTP delivery channel
enum class OTPChannel : uint8_t {
    SMS   = 0,
    Email = 1,
};

const char* otp_channel_string(OTPChannel c) noexcept;

// OTP status
enum class OTPStatus : uint8_t {
    Pending  = 0,  // Code sent, waiting for verification
    Verified = 1,  // Code verified successfully
    Expired  = 2,  // Code expired (5 min default)
    Locked   = 3,  // Too many failed attempts
    Failed   = 4,  // Wrong code
};

const char* otp_status_string(OTPStatus s) noexcept;

// Result of requesting an OTP
struct OTPRequestResult {
    std::string token_id;   // unique ID for this OTP request (use for verification)
    OTPStatus   status = OTPStatus::Pending;
    uint64_t    expires_at = 0;
    uint32_t    attempts_remaining = 3;
};

// Result of verifying an OTP
struct OTPVerifyResult {
    OTPStatus   status = OTPStatus::Verified;
    std::string user_id;        // who verified
    OTPChannel  channel = OTPChannel::SMS;
    std::string code_hash;      // hashed code (for storage)
};

// ─── OTP Config ──────────────────────────────────────────────────────────────

struct OTPConfig {
    uint32_t code_length = 6;         // digits (6 is standard)
    uint32_t expiry_seconds = 300;    // 5 minutes
    uint32_t max_attempts = 3;        // before lockout
    uint32_t lockout_seconds = 900;   // 15 minutes lockout
    uint32_t rate_limit_per_ip = 10;  // max OTP requests per IP per 15 min
    uint32_t rate_limit_per_phone = 5; // max OTP requests per phone per 15 min
    std::string allowed_chars = "0123456789"; // digits only
};


// ─── OTP Callbacks ───────────────────────────────────────────────────────────
//
// Developers provide a callback to deliver OTP codes via their email provider.
// SMS is optional — email-only works for most apps.
// The SDK generates and hashes the code; the callback sends it.

// Send an OTP code via Email (required if OTP is enabled)
using OTPCallback = std::function<Result<void>(
    const std::string& recipient,  // email address (or phone if SMS)
    const std::string& code,       // the plaintext code to deliver
    uint32_t expiry_seconds
)>;


// ─── OTP Server ──────────────────────────────────────────────────────────────
//
// Server-side OTP implementation.
// Generates 6-digit codes, hashes them with HMAC-SHA384, enforces rate limits
// and brute-force lockout, and verifies with constant-time comparison.

class OTPServer {
public:
    OTPServer(
        CryptoEngine& engine,
        const SecureBuffer& hmac_key,
        const OTPConfig& config = {},
        OTPCallback otp_sender = nullptr  // email sender
    );
    ~OTPServer();

    OTPServer(const OTPServer&) = delete;
    OTPServer& operator=(const OTPServer&) = delete;

    // ── Request OTP ──────────────────────────────────────────────────────────

    // Request an OTP code via SMS (requires SMS callback to be set)
    // Returns token_id for verification, or error if rate-limited/locked
    Result<OTPRequestResult> request_sms(
        const std::string& phone,
        const std::string& ip = ""
    );

    // Request an OTP code via Email (uses the otp_sender callback)
    Result<OTPRequestResult> request_email(
        const std::string& email,
        const std::string& ip = ""
    );

    // ── Verify OTP ───────────────────────────────────────────────────────────

    // Verify an OTP code
    // token_id: from request_sms/request_email
    // code: the 6-digit code the user entered
    // Returns verified status or error
    Result<OTPVerifyResult> verify(
        const std::string& token_id,
        const std::string& code
    );

    // ── Status ───────────────────────────────────────────────────────────────

    // Check if a phone/email is currently locked out
    bool is_locked(const std::string& identifier);

    // Get remaining attempts for a token
    uint32_t remaining_attempts(const std::string& token_id);

    // ── Callbacks ─────────────────────────────────────────────────────────────

    // Set the email OTP sender (required for email OTP)
    void set_otp_sender(OTPCallback callback);

    // Set the SMS OTP sender (optional — enables SMS OTP)
    void set_sms_sender(OTPCallback callback);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ezone
