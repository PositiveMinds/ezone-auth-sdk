#include "server.h"

// cpp-httplib — single header, fetched by CMake FetchContent
// See rest/CMakeLists.txt for the fetch target.
#include <httplib.h>

#include "ezone/crypto_engine.h"

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
static std::string obj(std::initializer_list<std::string> fields) {
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

    explicit RateLimiter(int per_minute) : limit_(per_minute) {}

    // Returns true if the request is allowed, false if rate-limited.
    bool allow(const std::string& ip) {
        if (limit_ <= 0) return true;
        std::lock_guard<std::mutex> lk(mu_);
        auto now = std::chrono::steady_clock::now();
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
          email(std::move(e)) {}

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

    // Returns remote IP from X-Forwarded-For (trusted behind a proxy) or
    // the direct peer address.
    static std::string client_ip(const httplib::Request& req) {
        auto it = req.headers.find("X-Forwarded-For");
        if (it != req.headers.end()) {
            auto& xff = it->second;
            // Take only the first (leftmost) address
            auto comma = xff.find(',');
            return (comma == std::string::npos) ? xff : xff.substr(0, comma);
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
            res.set_content("{\"status\":\"ok\",\"fips\":false}", "application/json");
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
