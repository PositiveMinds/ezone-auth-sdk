#pragma once

#include "ezone/types.h"
#include <string>
#include <memory>

namespace ezone {

struct MagicLinkEmail {
    std::string to;           // recipient email address
    std::string magic_token;  // the HMAC-signed token
    std::string app_url;      // base URL of the frontend, e.g. "https://yourapp.com"
    std::string purpose;      // "register" | "login" | "reset" | "add_device"
};

struct OTPEmail {
    std::string to;           // recipient email address
    std::string code;         // the OTP code to deliver
    uint32_t    expiry_seconds = 300; // code lifetime
};

class EmailProvider {
public:
    virtual ~EmailProvider() = default;

    // Send a magic link email. Returns failure if the provider
    // rejects the request (network error, invalid API key, etc.).
    virtual Result<void> send(const MagicLinkEmail& mail) = 0;

    // Send an OTP code email. Default implementation formats a simple text email.
    // Override for custom OTP email templates.
    virtual Result<void> send_otp(const OTPEmail& mail) {
        // Default: just log to stderr (override in production)
        fprintf(stderr, "[ezone] OTP code for %s: %s (expires in %u seconds)\n",
                mail.to.c_str(), mail.code.c_str(), mail.expiry_seconds);
        return Result<void>::success();
    }
};

// ── Log provider (development / testing) ─────────────────────────────────────

// Prints the magic link to stdout instead of sending an email.
// Use this in development so you can click the link without an email server.
class LogEmailProvider : public EmailProvider {
public:
    Result<void> send(const MagicLinkEmail& mail) override;
};

} // namespace ezone
