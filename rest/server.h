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

    // Trust the X-Forwarded-For header for client IP (rate limiting, QR
    // IP-binding). Only enable this when the server sits behind a reverse
    // proxy that overwrites/strips client-supplied X-Forwarded-For — otherwise
    // any client can spoof this header to bypass rate limits and IP binding.
    bool        trust_proxy_headers = false;

    // Distributed rate limiting: when redis_host is set, every replica of
    // this server shares one counter per IP via Redis (a fixed 60-second
    // window, not the in-memory limiter's precise token bucket) instead of
    // each process enforcing its own independent per-instance limit —
    // otherwise the effective limit multiplies by however many replicas are
    // running. Empty (the default) keeps the existing single-process,
    // in-memory limiter, so this is a no-op unless you opt in. Requires the
    // binary to have been built with EZONE_USE_REDIS_RATELIMIT (default ON;
    // see rest/CMakeLists.txt). A Redis outage fails OPEN (requests are
    // allowed, not blocked) so a rate-limiting dependency can never take the
    // whole API down — this trades strict enforcement for availability.
    // No TLS support yet; only plain, optionally password-authenticated
    // connections.
    std::string redis_host;
    int         redis_port     = 6379;
    std::string redis_password;
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
