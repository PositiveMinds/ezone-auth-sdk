#include "ezone/otp.h"

#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <unordered_map>

namespace ezone {

// ─── Helpers ─────────────────────────────────────────────────────────────────

namespace {

uint64_t now_sec() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

std::vector<uint8_t> secure_random(size_t count) {
    std::vector<uint8_t> buf(count);
    if (RAND_bytes(buf.data(), static_cast<int>(count)) != 1)
        return {};
    return buf;
}

static const char BASE64URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string base64url_encode(const std::vector<uint8_t>& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < data.size()) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < data.size()) n |= data[i + 2];
        out += BASE64URL_CHARS[(n >> 18) & 0x3F];
        out += BASE64URL_CHARS[(n >> 12) & 0x3F];
        if (i + 1 < data.size()) out += BASE64URL_CHARS[(n >> 6) & 0x3F];
        if (i + 2 < data.size()) out += BASE64URL_CHARS[n & 0x3F];
    }
    return out;
}

// Generate a cryptographically secure OTP code
std::string generate_otp_code(uint32_t length, const std::string& chars) {
    std::string code;
    code.reserve(length);
    auto rand_bytes = secure_random(length);
    if (rand_bytes.empty()) return {};
    for (uint32_t i = 0; i < length; ++i) {
        code += chars[rand_bytes[i] % chars.size()];
    }
    return code;
}

// Generate a unique token_id (16 bytes = 22 chars base64url)
std::string generate_token_id() {
    auto r = secure_random(16);
    if (r.empty()) return {};
    return base64url_encode(r);
}

// Hash an OTP code with HMAC-SHA384 (hex string)
std::string hash_code(
    CryptoEngine& eng,
    const SecureBuffer& hmac_key,
    const std::string& code)
{
    std::vector<uint8_t> data(code.begin(), code.end());
    auto mac = eng.hmac_sha384(data, hmac_key);
    if (!mac) return {};

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : mac.value) ss << std::setw(2) << (int)b;
    return ss.str();
}

// Constant-time string comparison
bool constant_time_eq(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<uint8_t>(a[i]) ^ static_cast<uint8_t>(b[i]);
    return diff == 0;
}

} // anonymous namespace


// ─── OTPChannel / OTPStatus strings ──────────────────────────────────────────

const char* otp_channel_string(OTPChannel c) noexcept {
    switch (c) {
        case OTPChannel::SMS:   return "sms";
        case OTPChannel::Email: return "email";
    }
    return "unknown";
}

const char* otp_status_string(OTPStatus s) noexcept {
    switch (s) {
        case OTPStatus::Pending:  return "pending";
        case OTPStatus::Verified: return "verified";
        case OTPStatus::Expired:  return "expired";
        case OTPStatus::Locked:   return "locked";
        case OTPStatus::Failed:   return "failed";
    }
    return "unknown";
}


// ─── OTPServer::Impl ─────────────────────────────────────────────────────────

struct OTPServer::Impl {
    CryptoEngine& engine;
    SecureBuffer  hmac_key;
    OTPConfig     config;
    OTPCallback   otp_sender;  // email sender
    OTPCallback   sms_sender;  // SMS sender (optional)

    // OTP request state
    struct OTPRequest {
        std::string token_id;
        std::string code_hash;       // HMAC-SHA384 of the code
        std::string identifier;      // phone or email
        OTPChannel  channel;
        uint64_t    created_at = 0;
        uint64_t    expires_at = 0;
        uint32_t    attempts = 0;
        bool        verified = false;
    };

    // Lockout state
    struct LockoutInfo {
        uint32_t    failed_attempts = 0;
        uint64_t    locked_until = 0;
    };

    // Rate limit state
    struct RateBucket {
        uint32_t    count = 0;
        uint64_t    window_start = 0;
    };

    std::unordered_map<std::string, OTPRequest> requests_;    // token_id → request
    std::unordered_map<std::string, OTPRequest> by_identifier_; // phone/email → latest request
    std::unordered_map<std::string, LockoutInfo> lockouts_;   // phone/email → lockout
    std::unordered_map<std::string, RateBucket> rate_limits_; // ip/phone → rate bucket

    mutable std::mutex mu_;

    Impl(CryptoEngine& e, const SecureBuffer& hk, const OTPConfig& cfg,
         OTPCallback sender)
        : engine(e), config(cfg), otp_sender(std::move(sender))
    {
        hmac_key.resize(hk.size());
        std::memcpy(hmac_key.data(), hk.data(), hk.size());
    }

    // Check rate limit (sliding window per 15 min)
    bool check_rate_limit(const std::string& key, uint32_t limit) {
        auto now = now_sec();
        auto& bucket = rate_limits_[key];

        // Reset window every 15 minutes
        if (now - bucket.window_start > 900) {
            bucket.count = 0;
            bucket.window_start = now;
        }

        if (bucket.count >= limit) return false;
        ++bucket.count;
        return true;
    }

    // Check if identifier is locked out
    bool is_locked(const std::string& identifier) {
        auto it = lockouts_.find(identifier);
        if (it == lockouts_.end()) return false;
        // locked_until == 0 means failures are being counted but the
        // threshold hasn't been crossed yet — not locked, and the count
        // must NOT be erased here or every call would reset it back to 0
        // before it ever reaches max_attempts.
        if (it->second.locked_until == 0) return false;
        if (now_sec() < it->second.locked_until) return true;
        // Lockout window has actually elapsed — reset the failure count
        lockouts_.erase(it);
        return false;
    }

    // Record a failed attempt, lockout if threshold exceeded
    void record_failure(const std::string& identifier) {
        auto& info = lockouts_[identifier];
        ++info.failed_attempts;
        if (info.failed_attempts >= config.max_attempts) {
            info.locked_until = now_sec() + config.lockout_seconds;
        }
    }

    // Clear lockout on successful verification
    void clear_lockout(const std::string& identifier) {
        lockouts_.erase(identifier);
    }

    // Clean up expired requests
    void cleanup_expired() {
        auto now = now_sec();
        for (auto it = requests_.begin(); it != requests_.end(); ) {
            if (now > it->second.expires_at)
                it = requests_.erase(it);
            else
                ++it;
        }
    }
};


// ─── OTPServer public API ───────────────────────────────────────────────────

OTPServer::OTPServer(
    CryptoEngine& engine,
    const SecureBuffer& hmac_key,
    const OTPConfig& config,
    OTPCallback otp_sender)
    : impl_(std::make_unique<Impl>(engine, hmac_key, config,
                                    std::move(otp_sender)))
{}

OTPServer::~OTPServer() = default;


Result<OTPRequestResult> OTPServer::request_sms(
    const std::string& phone,
    const std::string& ip)
{
    if (phone.empty())
        return Result<OTPRequestResult>::failure("phone number required");

    std::lock_guard<std::mutex> lock(impl_->mu_);
    impl_->cleanup_expired();

    // Check lockout
    if (impl_->is_locked(phone))
        return Result<OTPRequestResult>::failure(
            "too many failed attempts — try again later");

    // Check rate limit per phone
    if (!impl_->check_rate_limit("phone:" + phone, impl_->config.rate_limit_per_phone))
        return Result<OTPRequestResult>::failure(
            "rate limit exceeded for this phone number");

    // Check rate limit per IP (if provided)
    if (!ip.empty()) {
        if (!impl_->check_rate_limit("ip:" + ip, impl_->config.rate_limit_per_ip))
            return Result<OTPRequestResult>::failure(
                "rate limit exceeded for this IP address");
    }

    // Generate OTP code
    auto code = generate_otp_code(
        impl_->config.code_length, impl_->config.allowed_chars);
    if (code.empty())
        return Result<OTPRequestResult>::failure("failed to generate OTP code");

    // Hash the code
    auto code_hash = hash_code(impl_->engine, impl_->hmac_key, code);
    if (code_hash.empty())
        return Result<OTPRequestResult>::failure("failed to hash OTP code");

    // Generate token_id
    auto token_id = generate_token_id();
    if (token_id.empty())
        return Result<OTPRequestResult>::failure("failed to generate token ID");

    uint64_t now = now_sec();

    // Store request
    Impl::OTPRequest req;
    req.token_id = token_id;
    req.code_hash = code_hash;
    req.identifier = phone;
    req.channel = OTPChannel::SMS;
    req.created_at = now;
    req.expires_at = now + impl_->config.expiry_seconds;
    req.attempts = 0;
    req.verified = false;

    impl_->requests_[token_id] = req;
    impl_->by_identifier_[phone] = req;

    // Send via SMS callback
    if (impl_->sms_sender) {
        auto send_result = impl_->sms_sender(phone, code, impl_->config.expiry_seconds);
        if (!send_result) {
            fprintf(stderr, "[ezone] SMS OTP delivery failed: %s\n",
                    send_result.error.c_str());
            // Don't fail — the code is still valid for verification
        }
    }

    OTPRequestResult result;
    result.token_id = token_id;
    result.status = OTPStatus::Pending;
    result.expires_at = req.expires_at;
    result.attempts_remaining = impl_->config.max_attempts;

    return Result<OTPRequestResult>::success(std::move(result));
}


Result<OTPRequestResult> OTPServer::request_email(
    const std::string& email,
    const std::string& ip)
{
    if (email.empty())
        return Result<OTPRequestResult>::failure("email required");

    std::lock_guard<std::mutex> lock(impl_->mu_);
    impl_->cleanup_expired();

    // Check lockout
    if (impl_->is_locked(email))
        return Result<OTPRequestResult>::failure(
            "too many failed attempts — try again later");

    // Check rate limit per email
    if (!impl_->check_rate_limit("email:" + email, impl_->config.rate_limit_per_phone))
        return Result<OTPRequestResult>::failure(
            "rate limit exceeded for this email");

    // Check rate limit per IP
    if (!ip.empty()) {
        if (!impl_->check_rate_limit("ip:" + ip, impl_->config.rate_limit_per_ip))
            return Result<OTPRequestResult>::failure(
                "rate limit exceeded for this IP address");
    }

    // Generate OTP code
    auto code = generate_otp_code(
        impl_->config.code_length, impl_->config.allowed_chars);
    if (code.empty())
        return Result<OTPRequestResult>::failure("failed to generate OTP code");

    // Hash the code
    auto code_hash = hash_code(impl_->engine, impl_->hmac_key, code);
    if (code_hash.empty())
        return Result<OTPRequestResult>::failure("failed to hash OTP code");

    // Generate token_id
    auto token_id = generate_token_id();
    if (token_id.empty())
        return Result<OTPRequestResult>::failure("failed to generate token ID");

    uint64_t now = now_sec();

    // Store request
    Impl::OTPRequest req;
    req.token_id = token_id;
    req.code_hash = code_hash;
    req.identifier = email;
    req.channel = OTPChannel::Email;
    req.created_at = now;
    req.expires_at = now + impl_->config.expiry_seconds;
    req.attempts = 0;
    req.verified = false;

    impl_->requests_[token_id] = req;
    impl_->by_identifier_[email] = req;

    // Send via callback (email sender)
    if (impl_->otp_sender) {
        auto send_result = impl_->otp_sender(email, code, impl_->config.expiry_seconds);
        if (!send_result) {
            fprintf(stderr, "[ezone] OTP delivery failed: %s\n",
                    send_result.error.c_str());
        }
    }

    OTPRequestResult result;
    result.token_id = token_id;
    result.status = OTPStatus::Pending;
    result.expires_at = req.expires_at;
    result.attempts_remaining = impl_->config.max_attempts;

    return Result<OTPRequestResult>::success(std::move(result));
}


Result<OTPVerifyResult> OTPServer::verify(
    const std::string& token_id,
    const std::string& code)
{
    if (token_id.empty())
        return Result<OTPVerifyResult>::failure("token_id required");
    if (code.empty())
        return Result<OTPVerifyResult>::failure("code required");

    std::lock_guard<std::mutex> lock(impl_->mu_);

    auto it = impl_->requests_.find(token_id);
    if (it == impl_->requests_.end())
        return Result<OTPVerifyResult>::failure("invalid or expired OTP request");

    auto& req = it->second;

    // Check if already verified
    if (req.verified)
        return Result<OTPVerifyResult>::failure("OTP already used");

    // Check expiry
    if (now_sec() > req.expires_at) {
        req.code_hash.clear(); // wipe
        impl_->requests_.erase(it);
        return Result<OTPVerifyResult>::failure("OTP code expired");
    }

    // Check lockout on the identifier
    if (impl_->is_locked(req.identifier))
        return Result<OTPVerifyResult>::failure(
            "too many failed attempts — try again later");

    // Check attempts
    ++req.attempts;
    if (req.attempts > impl_->config.max_attempts) {
        impl_->record_failure(req.identifier);
        return Result<OTPVerifyResult>::failure(
            "too many failed attempts — locked out");
    }

    // Hash the provided code and compare
    auto provided_hash = hash_code(impl_->engine, impl_->hmac_key, code);
    if (provided_hash.empty())
        return Result<OTPVerifyResult>::failure("failed to process code");

    // Constant-time comparison
    if (!constant_time_eq(provided_hash, req.code_hash)) {
        impl_->record_failure(req.identifier);
        uint32_t remaining = impl_->config.max_attempts - req.attempts;
        if (remaining == 0) {
            return Result<OTPVerifyResult>::failure(
                "too many failed attempts — locked out");
        }
        return Result<OTPVerifyResult>::failure(
            "invalid code — " + std::to_string(remaining) + " attempts remaining");
    }

    // Success — mark as verified, clear lockout
    req.verified = true;
    impl_->clear_lockout(req.identifier);

    OTPVerifyResult result;
    result.status = OTPStatus::Verified;
    result.user_id = req.identifier;  // email or phone used as user_id
    result.channel = req.channel;
    result.code_hash = req.code_hash;

    return Result<OTPVerifyResult>::success(std::move(result));
}


bool OTPServer::is_locked(const std::string& identifier) {
    std::lock_guard<std::mutex> lock(impl_->mu_);
    return impl_->is_locked(identifier);
}


uint32_t OTPServer::remaining_attempts(const std::string& token_id) {
    std::lock_guard<std::mutex> lock(impl_->mu_);
    auto it = impl_->requests_.find(token_id);
    if (it == impl_->requests_.end()) return 0;
    if (it->second.attempts >= impl_->config.max_attempts) return 0;
    return impl_->config.max_attempts - it->second.attempts;
}


void OTPServer::set_otp_sender(OTPCallback callback) {
    std::lock_guard<std::mutex> lock(impl_->mu_);
    impl_->otp_sender = std::move(callback);
}

void OTPServer::set_sms_sender(OTPCallback callback) {
    std::lock_guard<std::mutex> lock(impl_->mu_);
    impl_->sms_sender = std::move(callback);
}

} // namespace ezone
