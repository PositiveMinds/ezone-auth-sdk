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

class EmailProvider {
public:
    virtual ~EmailProvider() = default;

    // Send a magic link email. Returns failure if the provider
    // rejects the request (network error, invalid API key, etc.).
    virtual Result<void> send(const MagicLinkEmail& mail) = 0;
};

// ── Log provider (development / testing) ─────────────────────────────────────

// Prints the magic link to stdout instead of sending an email.
// Use this in development so you can click the link without an email server.
class LogEmailProvider : public EmailProvider {
public:
    Result<void> send(const MagicLinkEmail& mail) override;
};

} // namespace ezone
