#include "server.h"

// cpp-httplib — single header, fetched by CMake FetchContent
// See rest/CMakeLists.txt for the fetch target.
#include <httplib.h>

#include "ezone/crypto_engine.h"
#include "ezone/webauthn.h"
#include "ezone/qr_auth.h"
#include "ezone/push_auth.h"
#include "ezone/biometric.h"
#include "ezone/otp.h"

#include <algorithm>
#include <chrono>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>

namespace ezone::rest {

// ─── Minimal JSON helpers ─────────────────────────────────────────────────────

namespace json {

static std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

static std::string str(const std::string& k, const std::string& v) {
    return "\"" + k + "\":\"" + escape(v) + "\"";
}
static std::string num(const std::string& k, uint64_t v) {
    return "\"" + k + "\":" + std::to_string(v);
}
static std::string obj(const std::vector<std::string>& fields) {
    std::string s = "{";
    bool first = true;
    for (auto& f : fields) {
        if (!first) s += ",";
        s += f;
        first = false;
    }
    s += "}";
    return s;
}
static std::string err(const std::string& msg) {
    return obj({ str("error", msg) });
}

// Minimal key lookup in flat JSON body — handles "key":"value" and "key":number
static std::string get_str(const std::string& body, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = body.find(search);
    if (pos == std::string::npos) return {};
    pos += search.size();
    while (pos < body.size() && (body[pos] == ' ' || body[pos] == ':')) ++pos;
    if (pos >= body.size()) return {};
    if (body[pos] == '"') {
        ++pos;
        std::string val;
        for (; pos < body.size() && body[pos] != '"'; ++pos) {
            if (body[pos] == '\\' && pos + 1 < body.size()) { ++pos; }
            val += body[pos];
        }
        return val;
    }
    return {};
}

static bool get_bool(const std::string& body, const std::string& key,
                     bool default_val = false) {
    std::string search = "\"" + key + "\"";
    size_t pos = body.find(search);
    if (pos == std::string::npos) return default_val;
    pos += search.size();
    while (pos < body.size() && (body[pos] == ' ' || body[pos] == ':')) ++pos;
    if (body.substr(pos, 4) == "true")  return true;
    if (body.substr(pos, 5) == "false") return false;
    return default_val;
}

} // namespace json


// ─── Input validation ─────────────────────────────────────────────────────────

// Maximum length of any single JSON field value (8 KB covers the largest
// legitimate input: a base64url-encoded P-384 SPKI DER key is ~160 chars).
static constexpr size_t MAX_FIELD_BYTES = 8 * 1024;
// Maximum bearer token length (compact ES384 token is ~300 chars).
static constexpr size_t MAX_TOKEN_BYTES = 2048;

// Basic RFC 5321 email check: non-empty, has exactly one @, domain has a dot.
static bool valid_email(const std::string& e) {
    if (e.empty() || e.size() > 254) return false;
    auto at = e.find('@');
    if (at == std::string::npos || at == 0 || at == e.size() - 1) return false;
    auto domain = e.substr(at + 1);
    return domain.find('.') != std::string::npos && domain.size() >= 3;
}

// Returns false if the field value looks malformed for its intended use.
static bool valid_field(const std::string& v) {
    return !v.empty() && v.size() <= MAX_FIELD_BYTES;
}


// ─── Rate limiter ─────────────────────────────────────────────────────────────

struct RateLimiter {
    struct Bucket {
        int       tokens;
        std::chrono::steady_clock::time_point last_refill;
    };

    std::unordered_map<std::string, Bucket> buckets_;
    std::mutex                              mu_;
    int                                     limit_;   // max tokens (= per-minute cap)
    std::chrono::steady_clock::time_point   last_prune_{};

    explicit RateLimiter(int per_minute) : limit_(per_minute) {}

    // Evict buckets idle long enough to be back at full capacity. Without
    // this, every distinct source IP (or spoofed X-Forwarded-For value, if
    // trust_proxy_headers is on) that ever hits the server leaves a
    // permanent entry — an unbounded memory-growth DoS over time.
    void prune_stale(std::chrono::steady_clock::time_point now) {
        if (last_prune_ != std::chrono::steady_clock::time_point{} &&
            now - last_prune_ < std::chrono::minutes(5))
            return;
        last_prune_ = now;
        for (auto it = buckets_.begin(); it != buckets_.end(); ) {
            if (now - it->second.last_refill >= std::chrono::minutes(10))
                it = buckets_.erase(it);
            else
                ++it;
        }
    }

    // Returns true if the request is allowed, false if rate-limited.
    bool allow(const std::string& ip) {
        if (limit_ <= 0) return true;
        std::lock_guard<std::mutex> lk(mu_);
        auto now = std::chrono::steady_clock::now();
        prune_stale(now);
        auto& b  = buckets_[ip];

        if (b.tokens == 0 && b.last_refill == std::chrono::steady_clock::time_point{}) {
            // First request from this IP
            b.tokens      = limit_;
            b.last_refill = now;
        } else {
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - b.last_refill).count();
            // Refill proportionally (limit_ tokens per 60 000 ms)
            int refill = static_cast<int>(elapsed_ms * limit_ / 60'000);
            if (refill > 0) {
                b.tokens      = std::min(b.tokens + refill, limit_);
                b.last_refill = now;
            }
        }

        if (b.tokens <= 0) return false;
        --b.tokens;
        return true;
    }
};


// ─── Security headers ─────────────────────────────────────────────────────────

static void apply_security_headers(httplib::Response& res,
                                   const std::string& cors_origin = {}) {
    res.set_header("X-Content-Type-Options",    "nosniff");
    res.set_header("X-Frame-Options",           "DENY");
    res.set_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    res.set_header("Cache-Control",             "no-store, no-cache, must-revalidate");
    res.set_header("Content-Security-Policy",   "default-src 'none'");
    res.set_header("Referrer-Policy",           "no-referrer");
    res.set_header("X-DNS-Prefetch-Control",    "off");
    res.set_header("Permissions-Policy",        "camera=(), microphone=(), geolocation=()");

    if (!cors_origin.empty()) {
        res.set_header("Access-Control-Allow-Origin",  cors_origin);
        res.set_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers",
                       "Authorization, Content-Type, X-Request-ID");
        res.set_header("Access-Control-Max-Age",       "86400");
        res.set_header("Vary",                         "Origin");
    }
}

// All response helpers take the CORS origin so headers are consistent.
static void ok(httplib::Response& res, const std::string& body,
               const std::string& cors = {}) {
    apply_security_headers(res, cors);
    res.set_content(body, "application/json");
    res.status = 200;
}

static void created(httplib::Response& res, const std::string& body,
                    const std::string& cors = {}) {
    apply_security_headers(res, cors);
    res.set_content(body, "application/json");
    res.status = 201;
}

static void bad_req(httplib::Response& res, const std::string& msg,
                    const std::string& cors = {}) {
    apply_security_headers(res, cors);
    res.set_content(json::err(msg), "application/json");
    res.status = 400;
}

static void too_large(httplib::Response& res, const std::string& cors = {}) {
    apply_security_headers(res, cors);
    res.set_content(json::err("request body too large"), "application/json");
    res.status = 413;
}

static void rate_limited(httplib::Response& res, const std::string& cors = {}) {
    apply_security_headers(res, cors);
    res.set_header("Retry-After", "60");
    res.set_content(json::err("too many requests"), "application/json");
    res.status = 429;
}

static void unauth(httplib::Response& res, const std::string& msg = "unauthorized",
                   const std::string& cors = {}) {
    apply_security_headers(res, cors);
    res.set_header("WWW-Authenticate", "Bearer");
    res.set_content(json::err(msg), "application/json");
    res.status = 401;
}

static void forbidden(httplib::Response& res, const std::string& cors = {}) {
    apply_security_headers(res, cors);
    res.set_content(json::err("forbidden"), "application/json");
    res.status = 403;
}

static void not_found(httplib::Response& res, const std::string& cors = {}) {
    apply_security_headers(res, cors);
    res.set_content(json::err("not found"), "application/json");
    res.status = 404;
}

static void conflict(httplib::Response& res, const std::string& msg,
                     const std::string& cors = {}) {
    apply_security_headers(res, cors);
    res.set_content(json::err(msg), "application/json");
    res.status = 409;
}

static void server_err(httplib::Response& res, const std::string& cors = {}) {
    apply_security_headers(res, cors);
    res.set_content(json::err("internal server error"), "application/json");
    res.status = 500;
}

// Extract Bearer token from Authorization header (with length cap).
static std::string bearer_token(const httplib::Request& req) {
    auto it = req.headers.find("Authorization");
    if (it == req.headers.end()) return {};
    const std::string& val = it->second;
    if (val.size() < 8 || val.substr(0, 7) != "Bearer ") return {};
    auto tok = val.substr(7);
    if (tok.size() > MAX_TOKEN_BYTES) return {};
    return tok;
}

// Dispatch Result error to the correct HTTP response.
static bool handle_error(httplib::Response& res, const std::string& msg,
                         const std::string& cors = {}) {
    if (msg.find("already")       != std::string::npos) { conflict(res, msg, cors); return true; }
    if (msg.find("not found")     != std::string::npos) { not_found(res, cors);     return true; }
    if (msg.find("unauthorized")  != std::string::npos) { unauth(res, msg, cors);   return true; }
    if (msg.find("invalid")       != std::string::npos) { bad_req(res, msg, cors);  return true; }
    if (msg.find("expired")       != std::string::npos) { bad_req(res, msg, cors);  return true; }
    if (msg.find("failed")        != std::string::npos) { unauth(res, msg, cors);   return true; }
    if (msg.find("forbidden")     != std::string::npos) { forbidden(res, cors);     return true; }
    // The messages below are ordinary rejections of caller-supplied data
    // (malformed/missing/mismatched fields, truncated or oversized blobs,
    // unsupported versions) coming from SDK-layer input validation -- e.g. a
    // garbage bearer token ("bad signature encoding"/"malformed token") or a
    // hand-crafted QR/WebAuthn blob. They're reachable by anyone sending bad
    // input and must map to 400, not 500: "internal server error" should
    // mean the server is broken, not that the caller sent something invalid.
    if (msg.find("malformed")     != std::string::npos) { bad_req(res, msg, cors);  return true; }
    if (msg.find("missing")       != std::string::npos) { bad_req(res, msg, cors);  return true; }
    if (msg.find("mismatch")      != std::string::npos) { bad_req(res, msg, cors);  return true; }
    if (msg.find("required")      != std::string::npos) { bad_req(res, msg, cors);  return true; }
    if (msg.find("must not be empty") != std::string::npos) { bad_req(res, msg, cors); return true; }
    if (msg.find("too short")     != std::string::npos) { bad_req(res, msg, cors);  return true; }
    if (msg.find("unsupported")   != std::string::npos) { bad_req(res, msg, cors);  return true; }
    if (msg.find("incomplete")    != std::string::npos) { bad_req(res, msg, cors);  return true; }
    if (msg.find("wrong purpose") != std::string::npos) { bad_req(res, msg, cors);  return true; }
    if (msg.find("truncated")     != std::string::npos) { bad_req(res, msg, cors);  return true; }
    if (msg.find("not a map")     != std::string::npos) { bad_req(res, msg, cors);  return true; }
    if (msg.find("bad signature encoding") != std::string::npos) { bad_req(res, msg, cors); return true; }
    if (msg.find("bad payload encoding")   != std::string::npos) { bad_req(res, msg, cors); return true; }
    server_err(res, cors);
    return true;
}


// ─── Impl ─────────────────────────────────────────────────────────────────────

struct RestServer::Impl {
    std::shared_ptr<Auth>          auth;
    ServerConfig                   cfg;
    httplib::Server                svr;
    RateLimiter                    limiter;
    std::shared_ptr<EmailProvider> email;

    Impl(std::shared_ptr<Auth> a, const ServerConfig& c,
         std::shared_ptr<EmailProvider> e)
        : auth(std::move(a)), cfg(c), limiter(c.rate_limit_per_min),
          email(std::move(e))
    {
        // Wire up email provider as OTP sender if OTP is enabled
        if (auth->is_method_enabled(AuthMethod::OTP) && auth->otp() && email) {
            auto email_provider = email;
            auth->otp()->set_otp_sender(
                [email_provider](const std::string& recipient,
                                 const std::string& code,
                                 uint32_t expiry_seconds) -> Result<void> {
                    OTPEmail mail;
                    mail.to = recipient;
                    mail.code = code;
                    mail.expiry_seconds = expiry_seconds;
                    return email_provider->send_otp(mail);
                });
        }
    }

    // Send a magic link email if a provider is configured.
    // Silently logs on failure — auth flow already returned the token to the
    // caller so a delivery failure doesn't break the endpoint.
    void send_magic_link(const std::string& to,
                         const std::string& magic_token,
                         const std::string& purpose) {
        if (!email) return;
        auto result = email->send({ to, magic_token, cfg.app_url, purpose });
        if (!result) {
            // Log but don't fail — caller should have retry / re-send logic
            fprintf(stderr, "[ezone] email delivery failed (%s): %s\n",
                    purpose.c_str(), result.error.c_str());
        }
    }

    // Returns remote IP from X-Forwarded-For (only when trust_proxy_headers
    // is enabled and the server genuinely sits behind a reverse proxy that
    // overwrites this header) or the direct peer address otherwise. Trusting
    // client-supplied X-Forwarded-For unconditionally lets any client spoof
    // its IP to bypass rate limiting and QR-code IP binding.
    std::string client_ip(const httplib::Request& req) const {
        if (cfg.trust_proxy_headers) {
            auto it = req.headers.find("X-Forwarded-For");
            if (it != req.headers.end()) {
                auto& xff = it->second;
                // Take only the first (leftmost) address
                auto comma = xff.find(',');
                return (comma == std::string::npos) ? xff : xff.substr(0, comma);
            }
        }
        return req.remote_addr;
    }

    // Gate every /auth/* request through size + rate checks.
    // Returns false and writes the error response if the request should be blocked.
    bool guard(const httplib::Request& req, httplib::Response& res) {
        const auto& co = cfg.cors_origin;
        if (req.body.size() > cfg.max_body_bytes) { too_large(res, co); return false; }
        if (!limiter.allow(client_ip(req)))        { rate_limited(res, co); return false; }
        return true;
    }

    void register_routes() {
        const std::string& pfx = cfg.api_prefix;
        const std::string& co  = cfg.cors_origin;

        // ── CORS pre-flight ───────────────────────────────────────────────
        if (!co.empty()) {
            svr.Options(".*", [&co](const httplib::Request&, httplib::Response& res) {
                apply_security_headers(res, co);
                res.status = 204;
            });
        }

        // ── Health ────────────────────────────────────────────────────────
        svr.Get(pfx + "/health", [&co](const httplib::Request&, httplib::Response& res) {
            apply_security_headers(res, co);
            res.set_content(
                std::string("{\"status\":\"ok\",\"fips\":") +
                (CryptoEngine::is_fips_mode() ? "true" : "false") + "}",
                "application/json");
            res.status = 200;
        });

        // ── Registration ──────────────────────────────────────────────────
        svr.Post(pfx + "/auth/register/begin",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string email = json::get_str(req.body, "email");
            if (!valid_email(email)) { bad_req(res, "valid email required", co); return; }

            auto r = auth->begin_registration(email);
            if (!r) { handle_error(res, r.error, co); return; }

            send_magic_link(email, r.value.magic_token, "register");

            created(res, json::obj({
                json::str("magic_token", r.value.magic_token),
                json::num("expires_at",  r.value.expires_at)
            }), co);
        });

        svr.Post(pfx + "/auth/register/complete",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string token  = json::get_str(req.body, "magic_token");
            std::string pk_b64 = json::get_str(req.body, "public_key");
            std::string label  = json::get_str(req.body, "device_label");

            if (!valid_field(token) || !valid_field(pk_b64)) {
                bad_req(res, "magic_token and public_key required", co); return;
            }
            if (label.size() > 128) { bad_req(res, "device_label too long", co); return; }

            auto pk = CryptoEngine::base64url_decode(pk_b64);
            if (!pk) { bad_req(res, "invalid public_key encoding", co); return; }

            auto r = auth->complete_registration(token, pk.value, label);
            if (!r) { handle_error(res, r.error, co); return; }

            ok(res, json::obj({
                json::str("token",     r.value.token),
                json::str("user_id",   r.value.user_id),
                json::str("device_id", r.value.device_id),
                json::num("expires_at",r.value.expires_at)
            }), co);
        });

        // ── Login ─────────────────────────────────────────────────────────
        svr.Post(pfx + "/auth/login/begin",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string email = json::get_str(req.body, "email");
            if (!valid_email(email)) { bad_req(res, "valid email required", co); return; }

            auto r = auth->begin_login(email);
            if (!r) { handle_error(res, r.error, co); return; }

            ok(res, json::obj({
                json::str("challenge",  CryptoEngine::base64url_encode(r.value.challenge_bytes)),
                json::num("expires_at", r.value.expires_at)
            }), co);
        });

        svr.Post(pfx + "/auth/login/complete",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string ch_b64  = json::get_str(req.body, "challenge");
            std::string sig_b64 = json::get_str(req.body, "signature");
            std::string pk_b64  = json::get_str(req.body, "public_key");

            if (!valid_field(ch_b64) || !valid_field(sig_b64) || !valid_field(pk_b64)) {
                bad_req(res, "challenge, signature and public_key required", co); return;
            }

            auto ch  = CryptoEngine::base64url_decode(ch_b64);
            auto sig = CryptoEngine::base64url_decode(sig_b64);
            auto pk  = CryptoEngine::base64url_decode(pk_b64);

            if (!ch || !sig || !pk) {
                bad_req(res, "invalid base64url encoding", co); return;
            }

            ChallengeResponse resp{ ch.value, sig.value, pk.value };
            auto r = auth->complete_login(resp);
            if (!r) { handle_error(res, r.error, co); return; }

            ok(res, json::obj({
                json::str("token",     r.value.token),
                json::str("user_id",   r.value.user_id),
                json::str("device_id", r.value.device_id),
                json::num("expires_at",r.value.expires_at)
            }), co);
        });

        // ── Session ───────────────────────────────────────────────────────
        svr.Get(pfx + "/auth/session",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string token = bearer_token(req);
            if (token.empty()) { unauth(res, "unauthorized", co); return; }

            auto r = auth->verify_session(token);
            if (!r) { unauth(res, r.error, co); return; }

            ok(res, json::obj({
                json::str("user_id",   r.value.user_id),
                json::str("email",     r.value.email),
                json::str("device_id", r.value.device_id),
                json::num("issued_at", r.value.issued_at),
                json::num("expires_at",r.value.expires_at)
            }), co);
        });

        svr.Post(pfx + "/auth/session/refresh",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string token = bearer_token(req);
            if (token.empty()) { unauth(res, "unauthorized", co); return; }

            auto r = auth->refresh_session(token);
            if (!r) { unauth(res, r.error, co); return; }

            ok(res, json::obj({
                json::str("token",     r.value.token),
                json::num("expires_at",r.value.expires_at)
            }), co);
        });

        svr.Post(pfx + "/auth/logout",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string token = bearer_token(req);
            if (token.empty()) { unauth(res, "unauthorized", co); return; }

            bool revoke = json::get_bool(req.body, "revoke_device", false);
            auto r = auth->logout(token, revoke);
            if (!r) { handle_error(res, r.error, co); return; }

            ok(res, "{\"status\":\"ok\"}", co);
        });

        // ── Account reset ─────────────────────────────────────────────────
        svr.Post(pfx + "/auth/reset/begin",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string email = json::get_str(req.body, "email");
            if (!valid_email(email)) { bad_req(res, "valid email required", co); return; }

            auto r = auth->begin_reset(email);
            if (!r) { handle_error(res, r.error, co); return; }

            // Always send (or attempt) — even for unknown emails the token is a
            // harmless dummy so the timing and response are identical.
            send_magic_link(email, r.value.magic_token, "reset");

            // Always 200 regardless of whether the email exists (prevents enumeration).
            ok(res, json::obj({
                json::str("magic_token", r.value.magic_token),
                json::num("expires_at",  r.value.expires_at)
            }), co);
        });

        svr.Post(pfx + "/auth/reset/complete",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string token  = json::get_str(req.body, "magic_token");
            std::string pk_b64 = json::get_str(req.body, "public_key");
            std::string label  = json::get_str(req.body, "device_label");

            if (!valid_field(token) || !valid_field(pk_b64)) {
                bad_req(res, "magic_token and public_key required", co); return;
            }

            auto pk = CryptoEngine::base64url_decode(pk_b64);
            if (!pk) { bad_req(res, "invalid public_key encoding", co); return; }

            auto r = auth->complete_reset(token, pk.value, label);
            if (!r) { handle_error(res, r.error, co); return; }

            ok(res, json::obj({
                json::str("token",     r.value.token),
                json::str("user_id",   r.value.user_id),
                json::num("expires_at",r.value.expires_at)
            }), co);
        });

        // ── Recovery codes ────────────────────────────────────────────────
        svr.Post(pfx + "/auth/recovery/generate",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string token = bearer_token(req);
            if (token.empty()) { unauth(res, "unauthorized", co); return; }

            auto sess = auth->verify_session(token);
            if (!sess) { unauth(res, sess.error, co); return; }

            auto r = auth->generate_recovery_codes(sess.value.user_id);
            if (!r) { handle_error(res, r.error, co); return; }

            std::string arr = "[";
            for (size_t i = 0; i < r.value.codes.size(); ++i) {
                if (i) arr += ",";
                arr += "\"" + json::escape(r.value.codes[i]) + "\"";
            }
            arr += "]";
            ok(res, "{\"codes\":" + arr + "}", co);
        });

        svr.Post(pfx + "/auth/recovery/use",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string email = json::get_str(req.body, "email");
            std::string code  = json::get_str(req.body, "code");

            if (!valid_email(email) || code.empty() || code.size() > 64) {
                bad_req(res, "email and code required", co); return;
            }

            auto r = auth->recover_with_code(email, code);
            // Return a generic error — never reveal whether email or code was wrong.
            if (!r) { unauth(res, "authentication failed", co); return; }

            ok(res, json::obj({
                json::str("magic_token", r.value.magic_token),
                json::num("expires_at",  r.value.expires_at)
            }), co);
        });

        // ── Multi-device ──────────────────────────────────────────────────
        svr.Post(pfx + "/auth/devices/add/begin",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string token = bearer_token(req);
            if (token.empty()) { unauth(res, "unauthorized", co); return; }

            auto r = auth->begin_add_device(token);
            if (!r) { handle_error(res, r.error, co); return; }

            // Notify the user that a new device addition was requested
            auto sess = auth->verify_session(bearer_token(req));
            if (sess) send_magic_link(sess.value.email, r.value.magic_token, "add_device");

            ok(res, json::obj({
                json::str("add_token",  r.value.magic_token),
                json::num("expires_at", r.value.expires_at)
            }), co);
        });

        svr.Post(pfx + "/auth/devices/add/complete",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string add_tok = json::get_str(req.body, "add_token");
            std::string pk_b64  = json::get_str(req.body, "public_key");
            std::string label   = json::get_str(req.body, "device_label");

            if (!valid_field(add_tok) || !valid_field(pk_b64)) {
                bad_req(res, "add_token and public_key required", co); return;
            }
            if (label.size() > 128) { bad_req(res, "device_label too long", co); return; }

            auto pk = CryptoEngine::base64url_decode(pk_b64);
            if (!pk) { bad_req(res, "invalid public_key encoding", co); return; }

            auto r = auth->complete_add_device(add_tok, pk.value, label);
            if (!r) { handle_error(res, r.error, co); return; }

            ok(res, json::obj({
                json::str("token",     r.value.token),
                json::str("device_id", r.value.device_id),
                json::num("expires_at",r.value.expires_at)
            }), co);
        });

        svr.Get(pfx + "/auth/devices",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string token = bearer_token(req);
            if (token.empty()) { unauth(res, "unauthorized", co); return; }

            auto r = auth->list_devices(token);
            if (!r) { handle_error(res, r.error, co); return; }

            std::string arr = "[";
            for (size_t i = 0; i < r.value.size(); ++i) {
                const auto& d = r.value[i];
                if (i) arr += ",";
                arr += json::obj({
                    json::str("device_id",  d.device_id),
                    json::str("label",      d.label),
                    json::num("created_at", d.created_at),
                    std::string("\"revoked\":") + (d.revoked ? "true" : "false")
                });
            }
            arr += "]";
            ok(res, "{\"devices\":" + arr + "}", co);
        });

        svr.Delete(pfx + "/auth/devices/:device_id",
        [this, &co](const httplib::Request& req, httplib::Response& res) {
            if (!guard(req, res)) return;
            std::string token     = bearer_token(req);
            std::string device_id = req.path_params.at("device_id");

            if (token.empty())     { unauth(res, "unauthorized", co);        return; }
            if (device_id.empty() || device_id.size() > 64) {
                bad_req(res, "device_id required", co); return;
            }

            auto r = auth->revoke_device(token, device_id);
            if (!r) { handle_error(res, r.error, co); return; }

            ok(res, "{\"status\":\"ok\"}", co);
        });

        // ── WebAuthn (FIDO2) endpoints ───────────────────────────────────
        // Only registered if AuthMethod::WebAuthn is enabled
        if (auth->is_method_enabled(AuthMethod::WebAuthn) && auth->webauthn()) {
            // Begin WebAuthn registration
            svr.Post(pfx + "/auth/webauthn/register/begin",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string token = bearer_token(req);
                if (token.empty()) { unauth(res, "unauthorized", co); return; }

                auto sess = auth->verify_session(token);
                if (!sess) { unauth(res, sess.error, co); return; }

                auto r = auth->webauthn()->begin_registration(
                    sess.value.user_id,
                    sess.value.email,
                    sess.value.email // display name defaults to email
                );
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, json::obj({
                    json::str("challenge",  r.value.challenge),
                    json::str("rp_id",      r.value.rp_id),
                    json::str("rp_name",    r.value.rp_name),
                    json::str("user_id",    r.value.user_id),
                    json::str("user_name",  r.value.user_name)
                }), co);
            });

            // Complete WebAuthn registration
            svr.Post(pfx + "/auth/webauthn/register/complete",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                // Must be authenticated (e.g. via challenge-response) to add a
                // WebAuthn credential — previously this handler read a "token"
                // field from the JSON body and never verified it, so every
                // registered credential was stored with an empty user_id
                // (WebAuthnRegistrationOptions.user_id is never reconstructed
                // here), disconnecting it from any account and colliding with
                // every other user's credentials under that same empty key.
                std::string token = bearer_token(req);
                if (token.empty()) { unauth(res, "unauthorized", co); return; }

                auto sess = auth->verify_session(token);
                if (!sess) { unauth(res, sess.error, co); return; }

                std::string challenge  = json::get_str(req.body, "challenge");
                std::string att_b64    = json::get_str(req.body, "attestation");
                std::string cd_json    = json::get_str(req.body, "client_data_json");
                std::string label      = json::get_str(req.body, "label");

                if (!valid_field(challenge) || !valid_field(att_b64) || !valid_field(cd_json)) {
                    bad_req(res, "challenge, attestation, and client_data_json required", co); return;
                }

                // Reconstruct options from the stored challenge
                WebAuthnRegistrationOptions opts;
                opts.challenge = challenge;
                opts.rp_id = auth->config().webauthn_rp_id;
                opts.rp_name = auth->config().webauthn_rp_name;

                auto r = auth->webauthn()->complete_registration(
                    opts, att_b64, cd_json, label.empty() ? "WebAuthn" : label);
                if (!r) { handle_error(res, r.error, co); return; }

                // Store the credential — user_id comes from the verified
                // session, NOT r.value.user_id (which is only ever a wire
                // encoding ezone reconstructs empty server-side, never the
                // real account id).
                WebAuthnCredentialRecord cred_rec;
                cred_rec.credential_id = r.value.credential_id;
                cred_rec.public_key_der = r.value.public_key_der;
                cred_rec.user_id = sess.value.user_id;
                cred_rec.sign_count = r.value.sign_count;
                cred_rec.created_at = r.value.created_at;
                cred_rec.aaguid = r.value.aaguid;
                cred_rec.label = r.value.label;
                cred_rec.backed_up = r.value.backed_up;
                cred_rec.uv_required = r.value.uv_required;

                auto stored = auth->storage()->add_webauthn_credential(cred_rec);
                if (!stored) { handle_error(res, stored.error, co); return; }

                created(res, json::obj({
                    json::str("credential_id", r.value.credential_id),
                    json::str("label",         r.value.label)
                }), co);
            });

            // Begin WebAuthn authentication
            svr.Post(pfx + "/auth/webauthn/authenticate/begin",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string email = json::get_str(req.body, "email");
                if (!valid_email(email)) { bad_req(res, "valid email required", co); return; }

                auto user = auth->storage()->get_user_by_email(email);
                if (!user) { unauth(res, "authentication failed", co); return; }

                // Get user's WebAuthn credentials
                auto creds = auth->storage()->get_webauthn_credentials(user.value.user_id);
                std::vector<std::string> allow_ids;
                if (creds.ok) {
                    for (auto& c : creds.value)
                        allow_ids.push_back(c.credential_id);
                }

                auto r = auth->webauthn()->begin_authentication(
                    auth->config().webauthn_rp_id, allow_ids);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, json::obj({
                    json::str("challenge", r.value.challenge),
                    json::str("rp_id",     r.value.rp_id)
                }), co);
            });

            // Complete WebAuthn authentication
            svr.Post(pfx + "/auth/webauthn/authenticate/complete",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string email     = json::get_str(req.body, "email");
                std::string challenge = json::get_str(req.body, "challenge");
                std::string cred_id   = json::get_str(req.body, "credential_id");
                std::string sig_b64   = json::get_str(req.body, "signature");
                std::string auth_b64  = json::get_str(req.body, "authenticator_data");
                std::string cd_json   = json::get_str(req.body, "client_data_json");

                if (!valid_field(challenge) || !valid_field(cred_id) ||
                    !valid_field(sig_b64) || !valid_field(auth_b64) || !valid_field(cd_json)) {
                    bad_req(res, "all fields required", co); return;
                }

                auto user = auth->storage()->get_user_by_email(email);
                if (!user) { unauth(res, "authentication failed", co); return; }

                auto creds = auth->storage()->get_webauthn_credentials(user.value.user_id);
                if (!creds || creds.value.empty()) {
                    unauth(res, "no WebAuthn credentials registered", co); return;
                }

                // WebAuthnServer::complete_authentication takes the wire-facing
                // WebAuthnCredential type, not the persisted
                // WebAuthnCredentialRecord — convert.
                std::vector<WebAuthnCredential> stored_creds;
                stored_creds.reserve(creds.value.size());
                for (auto& rec : creds.value) {
                    WebAuthnCredential c;
                    c.credential_id  = rec.credential_id;
                    c.public_key_der = rec.public_key_der;
                    c.user_id        = rec.user_id;
                    c.sign_count     = rec.sign_count;
                    c.created_at     = rec.created_at;
                    c.aaguid         = rec.aaguid;
                    c.label          = rec.label;
                    c.backed_up      = rec.backed_up;
                    c.uv_required    = rec.uv_required;
                    stored_creds.push_back(std::move(c));
                }

                // Build WebAuthnAssertion
                auto sig_decoded = CryptoEngine::base64url_decode(sig_b64);
                auto auth_decoded = CryptoEngine::base64url_decode(auth_b64);
                if (!sig_decoded || !auth_decoded) {
                    bad_req(res, "invalid base64url encoding", co); return;
                }
                WebAuthnAssertion assertion;
                assertion.credential_id = cred_id;
                assertion.signature = std::move(sig_decoded.value);
                assertion.authenticator_data = std::move(auth_decoded.value);
                assertion.client_data_json = std::vector<uint8_t>(cd_json.begin(), cd_json.end());

                // Build options
                WebAuthnAuthenticationOptions opts;
                opts.challenge = challenge;
                opts.rp_id = auth->config().webauthn_rp_id;

                auto r = auth->webauthn()->complete_authentication(
                    opts, assertion, stored_creds);
                if (!r) { handle_error(res, r.error, co); return; }

                // Update sign count in storage
                auth->storage()->update_webauthn_sign_count(
                    r.value.credential_id, r.value.sign_count);

                // Issue session token — find the device record or create one.
                // The WebAuthn credential_id doubles as the device_id here.
                auto dev = auth->storage()->get_device(r.value.credential_id);
                if (!dev) {
                    DeviceRecord dev_rec;
                    dev_rec.device_id = r.value.credential_id;
                    dev_rec.user_id = user.value.user_id;
                    dev_rec.public_key_der = r.value.public_key_der;
                    dev_rec.label = r.value.label;
                    dev_rec.created_at = r.value.created_at;
                    auth->storage()->add_device(dev_rec);
                }

                auto sess = auth->create_session(user.value.user_id, r.value.credential_id);
                if (!sess) { handle_error(res, sess.error, co); return; }

                ok(res, json::obj({
                    json::str("token",         sess.value.token),
                    json::str("user_id",       sess.value.user_id),
                    json::str("credential_id", r.value.credential_id),
                    json::str("label",         r.value.label),
                    json::num("sign_count",    r.value.sign_count),
                    json::num("expires_at",    sess.value.expires_at)
                }), co);
            });

            // List WebAuthn credentials
            svr.Get(pfx + "/auth/webauthn/credentials",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string token = bearer_token(req);
                if (token.empty()) { unauth(res, "unauthorized", co); return; }

                auto sess = auth->verify_session(token);
                if (!sess) { unauth(res, sess.error, co); return; }

                auto creds = auth->storage()->get_webauthn_credentials(sess.value.user_id);
                if (!creds) { handle_error(res, creds.error, co); return; }

                std::string arr = "[";
                for (size_t i = 0; i < creds.value.size(); ++i) {
                    const auto& c = creds.value[i];
                    if (i) arr += ",";
                    arr += json::obj({
                        json::str("credential_id", c.credential_id),
                        json::str("label",         c.label),
                        json::str("aaguid",        c.aaguid),
                        json::num("sign_count",    c.sign_count),
                        json::num("created_at",    c.created_at),
                        std::string("\"backed_up\":") + (c.backed_up ? "true" : "false"),
                        std::string("\"uv_required\":") + (c.uv_required ? "true" : "false")
                    });
                }
                arr += "]";
                ok(res, "{\"credentials\":" + arr + "}", co);
            });

            // Delete WebAuthn credential
            svr.Delete(pfx + "/auth/webauthn/credentials/:credential_id",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string token = bearer_token(req);
                std::string cred_id = req.path_params.at("credential_id");

                if (token.empty()) { unauth(res, "unauthorized", co); return; }
                if (cred_id.empty() || cred_id.size() > 512) {
                    bad_req(res, "credential_id required", co); return;
                }

                auto sess = auth->verify_session(token);
                if (!sess) { unauth(res, sess.error, co); return; }

                // Verify credential belongs to this user
                auto cred = auth->storage()->get_webauthn_credential(cred_id);
                if (!cred) { not_found(res, co); return; }
                if (cred.value.user_id != sess.value.user_id) {
                    forbidden(res, co); return;
                }

                auto r = auth->storage()->remove_webauthn_credential(cred_id);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, "{\"status\":\"ok\"}", co);
            });
        }

        // ── QR Code auth endpoints ────────────────────────────────────────
        // Only registered if AuthMethod::QRCode is enabled
        if (auth->is_method_enabled(AuthMethod::QRCode) && auth->qr_auth()) {
            // Begin QR auth (desktop generates QR code, IP-bound)
            svr.Post(pfx + "/auth/qr/begin",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;

                std::string ip = this->client_ip(req);
                auto r = auth->qr_auth()->begin_qr_auth(ip);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, json::obj({
                    json::str("session_id", r.value.session_id),
                    json::str("qr_data",    r.value.qr_data),
                    json::num("expires_at", r.value.expires_at)
                }), co);
            });

            // Poll QR status (desktop checks if user scanned)
            svr.Get(pfx + "/auth/qr/status",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string session_id = req.get_param_value("session_id");
                if (session_id.empty()) {
                    bad_req(res, "session_id required", co); return;
                }

                auto r = auth->qr_auth()->poll_qr_status(session_id);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, json::obj({
                    json::str("status", qr_status_string(r.value))
                }), co);
            });

            // Complete QR auth (desktop gets session after approval)
            svr.Post(pfx + "/auth/qr/complete",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string session_id = json::get_str(req.body, "session_id");
                if (session_id.empty()) {
                    bad_req(res, "session_id required", co); return;
                }

                auto r = auth->qr_auth()->complete_qr_auth(session_id);
                if (!r) { handle_error(res, r.error, co); return; }

                // The approved device_id was already validated against storage
                // in /auth/qr/approve, so this lookup is trusted.
                auto dev = auth->storage()->get_device(r.value.first);
                if (!dev) { handle_error(res, "approving device not found", co); return; }

                auto sess = auth->create_session(dev.value.user_id, dev.value.device_id);
                if (!sess) { handle_error(res, sess.error, co); return; }

                ok(res, json::obj({
                    json::str("token",     sess.value.token),
                    json::str("user_id",   sess.value.user_id),
                    json::str("device_id", r.value.first),
                    json::num("expires_at", sess.value.expires_at),
                    json::str("status",    "approved")
                }), co);
            });

            // Validate QR (mobile scans QR code, IP-verified)
            svr.Post(pfx + "/auth/qr/validate",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string qr_data = json::get_str(req.body, "qr_data");
                if (!valid_field(qr_data)) {
                    bad_req(res, "qr_data required", co); return;
                }

                std::string ip = this->client_ip(req);
                auto r = auth->qr_auth()->validate_qr(qr_data, ip);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, json::obj({
                    json::str("challenge", r.value),
                    json::str("status",    "scanned")
                }), co);
            });

            // Approve QR login (mobile signs and approves)
            svr.Post(pfx + "/auth/qr/approve",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string session_id = json::get_str(req.body, "session_id");
                std::string device_id  = json::get_str(req.body, "device_id");
                std::string sig_b64    = json::get_str(req.body, "signature");
                std::string pk_b64     = json::get_str(req.body, "public_key");
                std::string label      = json::get_str(req.body, "device_label");

                if (!valid_field(session_id) || !valid_field(sig_b64) || !valid_field(pk_b64)) {
                    bad_req(res, "session_id, signature, and public_key required", co); return;
                }

                auto sig_dec = CryptoEngine::base64url_decode(sig_b64);
                auto pk_dec = CryptoEngine::base64url_decode(pk_b64);
                if (!sig_dec || !pk_dec) {
                    bad_req(res, "invalid base64url encoding", co); return;
                }

                // QR approval must come from a device already registered on
                // some account (via challenge-response registration/add-device).
                // Without this check, anyone who can see the QR code's
                // challenge could approve it with a freshly generated,
                // unregistered keypair and hijack the login.
                if (device_id.empty()) {
                    bad_req(res, "device_id required", co); return;
                }
                auto dev = auth->storage()->get_device(device_id);
                if (!dev || dev.value.revoked) {
                    unauth(res, "device not registered", co); return;
                }
                if (dev.value.public_key_der != pk_dec.value) {
                    unauth(res, "public key does not match registered device", co); return;
                }

                QRApproval approval;
                approval.session_id = session_id;
                approval.device_id = dev.value.device_id;
                approval.signature = std::move(sig_dec.value);
                approval.public_key_der = dev.value.public_key_der;
                approval.device_label = label;

                auto r = auth->qr_auth()->approve_qr(approval);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, "{\"status\":\"approved\"}", co);
            });

            // Deny QR login
            svr.Post(pfx + "/auth/qr/deny",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string session_id = json::get_str(req.body, "session_id");
                if (session_id.empty()) {
                    bad_req(res, "session_id required", co); return;
                }

                auto r = auth->qr_auth()->deny_qr(session_id);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, "{\"status\":\"denied\"}", co);
            });
        }

        // ── Push auth endpoints ───────────────────────────────────────────
        // Only registered if AuthMethod::Push is enabled
        if (auth->is_method_enabled(AuthMethod::Push) && auth->push_auth()) {
            // Register push device
            svr.Post(pfx + "/auth/push/register",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string token      = bearer_token(req);
                if (token.empty()) { unauth(res, "unauthorized", co); return; }

                auto sess = auth->verify_session(token);
                if (!sess) { unauth(res, sess.error, co); return; }

                std::string platform_str = json::get_str(req.body, "platform");
                std::string push_token   = json::get_str(req.body, "push_token");
                std::string pk_b64       = json::get_str(req.body, "public_key");
                std::string label        = json::get_str(req.body, "device_label");

                if (!valid_field(push_token) || !valid_field(pk_b64)) {
                    bad_req(res, "push_token and public_key required", co); return;
                }

                PushPlatform platform = PushPlatform::IOS;
                if (platform_str == "android") platform = PushPlatform::Android;
                else if (platform_str == "web") platform = PushPlatform::Web;

                auto pk = CryptoEngine::base64url_decode(pk_b64);
                if (!pk) { bad_req(res, "invalid public_key encoding", co); return; }

                auto r = auth->push_auth()->register_device(
                    sess.value.user_id, platform, push_token,
                    pk.value, label.empty() ? "Mobile Device" : label);
                if (!r) { handle_error(res, r.error, co); return; }

                created(res, json::obj({
                    json::str("device_id", r.value.device_id),
                    json::str("label",     r.value.label)
                }), co);
            });

            // Begin push auth (server sends push to user's devices)
            svr.Post(pfx + "/auth/push/begin",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string email = json::get_str(req.body, "email");
                if (!valid_email(email)) { bad_req(res, "valid email required", co); return; }

                auto user = auth->storage()->get_user_by_email(email);
                if (!user) { unauth(res, "authentication failed", co); return; }

                auto r = auth->push_auth()->begin_push_auth(user.value.user_id);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, json::obj({
                    json::str("request_id", r.value.request_id),
                    json::num("expires_at", r.value.expires_at)
                }), co);
            });

            // Poll push status
            svr.Get(pfx + "/auth/push/status",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string request_id = req.get_param_value("request_id");
                if (request_id.empty()) {
                    bad_req(res, "request_id required", co); return;
                }

                auto r = auth->push_auth()->poll_push_status(request_id);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, json::obj({
                    json::str("status", push_status_string(r.value))
                }), co);
            });

            // Complete push auth
            svr.Post(pfx + "/auth/push/complete",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string request_id = json::get_str(req.body, "request_id");
                if (request_id.empty()) {
                    bad_req(res, "request_id required", co); return;
                }

                auto r = auth->push_auth()->complete_push_auth(request_id);
                if (!r) { handle_error(res, r.error, co); return; }

                // PushAuthServer keeps its own device registry (populated via
                // /auth/push/register); mirror it into the challenge-response
                // DeviceRecord table on first use so create_session can issue
                // a real token bound to this device.
                auto dev = auth->storage()->get_device(r.value.device_id);
                if (!dev) {
                    DeviceRecord dev_rec;
                    dev_rec.device_id = r.value.device_id;
                    dev_rec.user_id = r.value.user_id;
                    dev_rec.public_key_der = r.value.public_key_der;
                    dev_rec.label = r.value.label;
                    dev_rec.created_at = r.value.created_at;
                    auth->storage()->add_device(dev_rec);
                }

                auto sess = auth->create_session(r.value.user_id, r.value.device_id);
                if (!sess) { handle_error(res, sess.error, co); return; }

                ok(res, json::obj({
                    json::str("token",     sess.value.token),
                    json::str("user_id",   sess.value.user_id),
                    json::str("device_id", r.value.device_id),
                    json::str("label",     r.value.label),
                    json::num("expires_at", sess.value.expires_at),
                    json::str("status",    "approved")
                }), co);
            });

            // Approve push (mobile signs and approves)
            svr.Post(pfx + "/auth/push/approve",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string request_id = json::get_str(req.body, "request_id");
                std::string device_id  = json::get_str(req.body, "device_id");
                std::string sig_b64    = json::get_str(req.body, "signature");
                std::string label      = json::get_str(req.body, "device_label");

                if (!valid_field(request_id) || !valid_field(sig_b64) || !valid_field(device_id)) {
                    bad_req(res, "request_id, device_id, and signature required", co); return;
                }

                auto sig_dec = CryptoEngine::base64url_decode(sig_b64);
                if (!sig_dec) {
                    bad_req(res, "invalid base64url encoding", co); return;
                }
                PushApproval approval;
                approval.request_id = request_id;
                approval.device_id = device_id;
                approval.signature = std::move(sig_dec.value);
                approval.device_label = label;

                auto r = auth->push_auth()->approve_push(approval);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, "{\"status\":\"approved\"}", co);
            });

            // Deny push
            svr.Post(pfx + "/auth/push/deny",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string request_id = json::get_str(req.body, "request_id");
                if (request_id.empty()) {
                    bad_req(res, "request_id required", co); return;
                }

                auto r = auth->push_auth()->deny_push(request_id);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, "{\"status\":\"denied\"}", co);
            });

            // List push devices
            svr.Get(pfx + "/auth/push/devices",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string token = bearer_token(req);
                if (token.empty()) { unauth(res, "unauthorized", co); return; }

                auto sess = auth->verify_session(token);
                if (!sess) { unauth(res, sess.error, co); return; }

                auto devs = auth->push_auth()->list_devices(sess.value.user_id);
                if (!devs) { handle_error(res, devs.error, co); return; }

                std::string arr = "[";
                for (size_t i = 0; i < devs.value.size(); ++i) {
                    const auto& d = devs.value[i];
                    if (i) arr += ",";
                    arr += json::obj({
                        json::str("device_id", d.device_id),
                        json::str("label",     d.label),
                        json::str("platform",  push_platform_string(d.platform)),
                        json::num("created_at", d.created_at),
                        std::string("\"active\":") + (d.active ? "true" : "false")
                    });
                }
                arr += "]";
                ok(res, "{\"devices\":" + arr + "}", co);
            });

            // Deactivate push device
            svr.Delete(pfx + "/auth/push/devices/:device_id",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string token     = bearer_token(req);
                std::string device_id = req.path_params.at("device_id");

                if (token.empty()) { unauth(res, "unauthorized", co); return; }
                if (device_id.empty() || device_id.size() > 64) {
                    bad_req(res, "device_id required", co); return;
                }

                auto r = auth->push_auth()->deactivate_device(device_id);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, "{\"status\":\"ok\"}", co);
            });
        }

        // ── OTP endpoints ─────────────────────────────────────────────────
        // Only registered if AuthMethod::OTP is enabled
        if (auth->is_method_enabled(AuthMethod::OTP) && auth->otp()) {
            // No REST endpoint for SMS OTP: without an SMS gateway wired via
            // OTPServer::set_sms_sender (nothing does this by default — see
            // main.cpp), request_sms would still generate and hash a real
            // code and consume rate-limit budget, just never deliver it
            // anywhere. It also can't complete a login even when verified —
            // StorageAdapter has no phone-indexed user lookup. Embedders of
            // the C++ SDK directly can still call Auth::otp()->request_sms()
            // themselves once they've wired a real gateway.

            // Request OTP — email-based (no SMS gateway needed)
            // Uses the EmailProvider configured on the server
            svr.Post(pfx + "/auth/otp/request",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string email = json::get_str(req.body, "email");
                if (!valid_email(email)) { bad_req(res, "valid email required", co); return; }

                std::string ip = this->client_ip(req);
                auto r = auth->otp()->request_email(email, ip);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, json::obj({
                    json::str("token_id",  r.value.token_id),
                    json::num("expires_at", r.value.expires_at),
                    json::num("attempts_remaining", r.value.attempts_remaining)
                }), co);
            });

            // Request OTP via Email (alias)
            svr.Post(pfx + "/auth/otp/email",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string email = json::get_str(req.body, "email");
                if (!valid_email(email)) { bad_req(res, "valid email required", co); return; }

                std::string ip = this->client_ip(req);
                auto r = auth->otp()->request_email(email, ip);
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, json::obj({
                    json::str("token_id",  r.value.token_id),
                    json::num("expires_at", r.value.expires_at),
                    json::num("attempts_remaining", r.value.attempts_remaining)
                }), co);
            });

            // Verify OTP
            svr.Post(pfx + "/auth/otp/verify",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string token_id = json::get_str(req.body, "token_id");
                std::string code     = json::get_str(req.body, "code");

                if (token_id.empty() || code.empty()) {
                    bad_req(res, "token_id and code required", co); return;
                }
                if (code.size() > 16) {
                    bad_req(res, "invalid code format", co); return;
                }

                auto r = auth->otp()->verify(token_id, code);
                if (!r) { handle_error(res, r.error, co); return; }

                // OTP has no device-key concept — it proves control of an
                // email/phone, not possession of a private key. To still
                // issue a real session (like every other auth method here),
                // bind it to a stable synthetic "OTP device" per user,
                // derived from the user_id rather than a public key. Only
                // done when the identifier matches an existing active
                // account with email verification (SMS/phone identifiers
                // have no equivalent lookup in StorageAdapter yet) — an
                // unmatched identifier still gets a normal 200 with no
                // token, so this can't be used to probe account existence.
                std::string token;
                uint64_t expires_at = 0;
                if (r.value.channel == OTPChannel::Email) {
                    auto user = auth->storage()->get_user_by_email(r.value.user_id);
                    if (user && user.value.active) {
                        auto device_id = CryptoEngine::derive_device_id(std::vector<uint8_t>(
                            user.value.user_id.begin(), user.value.user_id.end()));
                        if (device_id) {
                            if (!auth->storage()->get_device(device_id.value)) {
                                DeviceRecord dev_rec;
                                dev_rec.device_id = device_id.value;
                                dev_rec.user_id = user.value.user_id;
                                dev_rec.label = "OTP (email)";
                                dev_rec.created_at = std::chrono::duration_cast<std::chrono::seconds>(
                                    std::chrono::system_clock::now().time_since_epoch()).count();
                                auth->storage()->add_device(dev_rec);
                            }
                            auto sess = auth->create_session(user.value.user_id, device_id.value);
                            if (sess) { token = sess.value.token; expires_at = sess.value.expires_at; }
                        }
                    }
                }

                std::vector<std::string> fields = {
                    json::str("status", otp_status_string(r.value.status)),
                    json::str("channel", otp_channel_string(r.value.channel)),
                    json::str("code_hash", r.value.code_hash)
                };
                if (!token.empty()) {
                    fields.push_back(json::str("token", token));
                    fields.push_back(json::num("expires_at", expires_at));
                }
                ok(res, json::obj(fields), co);
            });

            // Check OTP lockout status
            svr.Get(pfx + "/auth/otp/status",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string identifier = req.get_param_value("identifier");
                if (identifier.empty()) {
                    bad_req(res, "identifier (phone or email) required", co); return;
                }

                bool locked = auth->otp()->is_locked(identifier);
                ok(res, json::obj({
                    std::string("\"locked\":") + (locked ? "true" : "false")
                }), co);
            });
        }

        // ── Biometric endpoints ─────────────────────────────────────────────
        // Registered whenever a BiometricAuthServer exists (created alongside
        // WebAuthn or Push — see Auth::Impl). A biometric-protected key is
        // just a P-384 device key whose signing step is gated by an OS
        // biometric prompt the server never observes directly; devices are
        // stored the same way as challenge-response devices.
        if (auth->biometric()) {
            // Begin biometric registration — caller must already be logged
            // in via another method to add a biometric-protected device.
            svr.Post(pfx + "/auth/biometric/register/begin",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string token = bearer_token(req);
                if (token.empty()) { unauth(res, "unauthorized", co); return; }

                auto sess = auth->verify_session(token);
                if (!sess) { unauth(res, sess.error, co); return; }

                auto r = auth->biometric()->generate_challenge();
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, json::obj({
                    json::str("challenge", r.value)
                }), co);
            });

            // Complete biometric registration — client sends the public half
            // of a biometric-protected keypair (the private key never leaves
            // the device's secure enclave / keystore).
            svr.Post(pfx + "/auth/biometric/register/complete",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string token = bearer_token(req);
                if (token.empty()) { unauth(res, "unauthorized", co); return; }

                auto sess = auth->verify_session(token);
                if (!sess) { unauth(res, sess.error, co); return; }

                std::string challenge = json::get_str(req.body, "challenge");
                std::string pk_b64    = json::get_str(req.body, "public_key");
                std::string label     = json::get_str(req.body, "label");

                if (!valid_field(challenge) || !valid_field(pk_b64)) {
                    bad_req(res, "challenge and public_key required", co); return;
                }
                if (label.size() > 128) { bad_req(res, "label too long", co); return; }

                auto pk = CryptoEngine::base64url_decode(pk_b64);
                if (!pk) { bad_req(res, "invalid public_key encoding", co); return; }

                // The server never inspects the encrypted private-key
                // payload — it stays on the device.
                BiometricKeyPayload payload;
                auto reg = auth->biometric()->register_biometric_key(
                    sess.value.user_id, challenge, pk.value, payload,
                    label.empty() ? "Biometric" : label);
                if (!reg) { handle_error(res, reg.error, co); return; }

                auto device_id = CryptoEngine::derive_device_id(pk.value);
                if (!device_id) { handle_error(res, device_id.error, co); return; }

                DeviceRecord dev;
                dev.device_id      = device_id.value;
                dev.user_id        = sess.value.user_id;
                dev.public_key_der = pk.value;
                dev.label          = label.empty() ? "Biometric" : label;
                dev.created_at     = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

                auto added = auth->storage()->add_device(dev);
                if (!added) { handle_error(res, added.error, co); return; }

                created(res, json::obj({
                    json::str("device_id", dev.device_id),
                    json::str("label",     dev.label)
                }), co);
            });

            // Begin biometric login — public, no session required yet; the
            // signer's identity is only known once the signature verifies.
            svr.Post(pfx + "/auth/biometric/login/begin",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;

                auto r = auth->biometric()->generate_challenge();
                if (!r) { handle_error(res, r.error, co); return; }

                ok(res, json::obj({
                    json::str("challenge", r.value)
                }), co);
            });

            // Complete biometric login — verify the signature (produced only
            // after the device's OS biometric prompt unlocked the key), then
            // look up which registered device that public key belongs to.
            svr.Post(pfx + "/auth/biometric/login/complete",
            [this, &co](const httplib::Request& req, httplib::Response& res) {
                if (!guard(req, res)) return;
                std::string challenge = json::get_str(req.body, "challenge");
                std::string sig_b64   = json::get_str(req.body, "signature");
                std::string pk_b64    = json::get_str(req.body, "public_key");

                if (!valid_field(challenge) || !valid_field(sig_b64) || !valid_field(pk_b64)) {
                    bad_req(res, "challenge, signature, and public_key required", co); return;
                }

                auto sig = CryptoEngine::base64url_decode(sig_b64);
                auto pk  = CryptoEngine::base64url_decode(pk_b64);
                if (!sig || !pk) { bad_req(res, "invalid base64url encoding", co); return; }

                auto verified = auth->biometric()->verify_biometric_response(
                    challenge, sig.value, pk.value);
                if (!verified) { unauth(res, "authentication failed", co); return; }

                auto device_id = CryptoEngine::derive_device_id(pk.value);
                if (!device_id) { unauth(res, "authentication failed", co); return; }

                auto dev = auth->storage()->get_device(device_id.value);
                if (!dev || dev.value.revoked) {
                    unauth(res, "authentication failed", co); return;
                }

                auto sess = auth->create_session(dev.value.user_id, dev.value.device_id);
                if (!sess) { handle_error(res, sess.error, co); return; }

                ok(res, json::obj({
                    json::str("token",   sess.value.token),
                    json::str("user_id", sess.value.user_id),
                    json::num("expires_at", sess.value.expires_at)
                }), co);
            });
        }

        // ── Methods info endpoint ─────────────────────────────────────────
        svr.Get(pfx + "/auth/methods",
        [this, &co](const httplib::Request&, httplib::Response& res) {
            apply_security_headers(res, co);

            std::string methods = "[";
            bool first = true;
            auto add_method = [&](const char* name, AuthMethod m) {
                if (auth->is_method_enabled(m)) {
                    if (!first) methods += ",";
                    methods += "\"" + std::string(name) + "\"";
                    first = false;
                }
            };
            add_method("challenge", AuthMethod::Challenge);
            add_method("magic_link", AuthMethod::MagicLink);
            add_method("recovery", AuthMethod::Recovery);
            add_method("webauthn", AuthMethod::WebAuthn);
            add_method("qr_code", AuthMethod::QRCode);
            add_method("push", AuthMethod::Push);
            add_method("otp", AuthMethod::OTP);
            // Biometric has no dedicated AuthMethod bit — it's created
            // alongside WebAuthn/Push (see Auth::Impl) — so report it based
            // on whether the server instance actually exists.
            if (auth->biometric()) {
                if (!first) methods += ",";
                methods += "\"biometric\"";
                first = false;
            }
            methods += "]";

            ok(res, json::obj({
                std::string("\"methods\":") + methods
            }), co);
        });
    }
};


// ─── RestServer public API ────────────────────────────────────────────────────

RestServer::RestServer(std::shared_ptr<Auth> auth, const ServerConfig& cfg,
                       std::shared_ptr<EmailProvider> email)
    : impl_(std::make_unique<Impl>(std::move(auth), cfg, std::move(email)))
{
    impl_->register_routes();
}

RestServer::~RestServer() = default;

void RestServer::run() {
    impl_->svr.listen(impl_->cfg.host.c_str(), impl_->cfg.port);
}

void RestServer::stop() {
    impl_->svr.stop();
}

} // namespace ezone::rest
