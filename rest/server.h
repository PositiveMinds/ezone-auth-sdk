#pragma once

#include "ezone/auth.h"
#include "ezone/email_provider.h"
#include <memory>
#include <string>

namespace ezone::rest {

struct ServerConfig {
    std::string host              = "0.0.0.0";
    int         port              = 8080;
    bool        use_tls           = false;
    std::string cert_path;          // PEM cert  (required if use_tls = true)
    std::string key_path;           // PEM key   (required if use_tls = true)
    std::string api_prefix        = "/v1";
    int         threads           = 4;

    // Frontend URL — used to build magic link URLs in emails.
    // e.g. "https://yourapp.com"
    std::string app_url             = "http://localhost:3000";

    // CORS: set to your frontend origin, e.g. "https://yourapp.com"
    // Empty string disables CORS headers (server-to-server use cases).
    std::string cors_origin;

    // Rate limiting: maximum auth requests per IP per minute (0 = disabled).
    // Applies to all /auth/* endpoints. Use a reverse proxy for
    // production-grade rate limiting in addition to this.
    int         rate_limit_per_min = 60;

    // Maximum request body size in bytes. Requests exceeding this are
    // rejected with 413 before any parsing occurs.
    size_t      max_body_bytes    = 65'536;
};

class RestServer {
public:
    RestServer(
        std::shared_ptr<Auth>          auth,
        const ServerConfig&            cfg      = {},
        std::shared_ptr<EmailProvider> email    = nullptr
    );
    ~RestServer();

    // Blocks until stop() is called or the process receives SIGINT/SIGTERM
    void run();
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ezone::rest
