#include "server.h"
#include "ezone/auth.h"
#include "ezone/storage_adapter.h"
#include "ezone/email_provider.h"
#include "ezone/resend_provider.h"
#include "ezone/crypto_strategy.h"
#ifdef EZONE_POSTGRES_ENABLED
#include "ezone/postgres_adapter.h"
#endif

#include <cstdlib>
#include <csignal>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

// ─── Signal handling ──────────────────────────────────────────────────────────

static ezone::rest::RestServer* g_server = nullptr;

static void on_signal(int) {
    if (g_server) g_server->stop();
}


// ─── Server keys ────────────────────────────────────────────────────────────
//
// Session tokens, magic links, and recovery-code hashes are all only valid
// against the exact HMAC/signing keys that created them. Without a way to
// load a stable, persisted set of keys:
//   - restarting the server invalidates every active session and in-flight
//     magic link
//   - running more than one instance is broken outright — a token issued by
//     instance A won't verify on instance B, since each generates its own
//     random keys independently
//
// EZONE_HMAC_KEY / EZONE_TOKEN_PRIVATE_KEY / EZONE_TOKEN_PUBLIC_KEY (all
// base64url, no padding) load a stable key set; set all three from a secrets
// manager for any real deployment. With none set, fresh keys are generated
// for convenience (dev/test only) and printed once so they can be captured.
static ezone::Result<ezone::ServerKeys> load_or_generate_server_keys() {
    const char* hmac_env    = std::getenv("EZONE_HMAC_KEY");
    const char* priv_env    = std::getenv("EZONE_TOKEN_PRIVATE_KEY");
    const char* pub_env     = std::getenv("EZONE_TOKEN_PUBLIC_KEY");
    int provided = (hmac_env != nullptr) + (priv_env != nullptr) + (pub_env != nullptr);

    if (provided == 3) {
        auto hmac = ezone::CryptoEngine::base64url_decode(hmac_env);
        auto priv = ezone::CryptoEngine::base64url_decode(priv_env);
        auto pub  = ezone::CryptoEngine::base64url_decode(pub_env);
        if (!hmac || !priv || !pub)
            return ezone::Result<ezone::ServerKeys>::failure(
                "EZONE_HMAC_KEY/EZONE_TOKEN_PRIVATE_KEY/EZONE_TOKEN_PUBLIC_KEY "
                "must all be valid base64url");
        if (hmac.value.size() != 32)
            return ezone::Result<ezone::ServerKeys>::failure(
                "EZONE_HMAC_KEY must decode to exactly 32 bytes");

        ezone::ServerKeys keys;
        keys.hmac_key = ezone::SecureBuffer(hmac.value.data(), hmac.value.size());
        keys.token_private_key_der = ezone::SecureBuffer(priv.value.data(), priv.value.size());
        keys.token_public_key_der  = std::move(pub.value);
        return ezone::Result<ezone::ServerKeys>::success(std::move(keys));
    }

    if (provided > 0) {
        return ezone::Result<ezone::ServerKeys>::failure(
            "EZONE_HMAC_KEY, EZONE_TOKEN_PRIVATE_KEY, and EZONE_TOKEN_PUBLIC_KEY "
            "must be set together, or not at all -- got only " +
            std::to_string(provided) + " of 3");
    }

    // None set — generate fresh keys and print them so they CAN be captured,
    // rather than silently discarding them on every restart.
    auto keys = ezone::Auth::generate_server_keys();
    if (!keys) return keys;

    std::cerr <<
        "[ezone] WARNING: no EZONE_HMAC_KEY/EZONE_TOKEN_PRIVATE_KEY/"
        "EZONE_TOKEN_PUBLIC_KEY set -- generated FRESH keys for this run.\n"
        "[ezone] Every session, magic link, and recovery code will be "
        "invalidated on the next restart, and you cannot run more than one\n"
        "[ezone] instance with these keys. For any real deployment, capture "
        "the values below into your secrets manager and set all three env\n"
        "[ezone] vars on every instance:\n"
        "[ezone]   EZONE_HMAC_KEY=" << ezone::CryptoEngine::base64url_encode(keys.value.hmac_key.copy_out()) << "\n" <<
        "[ezone]   EZONE_TOKEN_PRIVATE_KEY=" << ezone::CryptoEngine::base64url_encode(keys.value.token_private_key_der.copy_out()) << "\n" <<
        "[ezone]   EZONE_TOKEN_PUBLIC_KEY=" << ezone::CryptoEngine::base64url_encode(keys.value.token_public_key_der) << "\n";

    return keys;
}


// ─── Entry point ──────────────────────────────────────────────────────────────

int main() {
    auto keys = load_or_generate_server_keys();
    if (!keys) {
        std::cerr << "[ezone] Failed to obtain server keys: "
                  << keys.error << "\n";
        return 1;
    }

    // ── Storage adapter ───────────────────────────────────────────────────────
    std::shared_ptr<ezone::StorageAdapter> storage;

#ifdef EZONE_POSTGRES_ENABLED
    if (const char* db_url = std::getenv("EZONE_DATABASE_URL")) {
        ezone::PostgresConfig pg_cfg;
        pg_cfg.connection_string = db_url;
        if (const char* v = std::getenv("EZONE_DB_POOL_SIZE"))
            pg_cfg.pool_size = std::stoi(v);

        auto pg = ezone::PostgresStorageAdapter::create(pg_cfg);
        if (!pg) {
            std::cerr << "[ezone] PostgreSQL connection failed: " << pg.error << "\n";
            return 1;
        }
        storage = std::move(pg.value);
        std::cout << "[ezone] Storage: PostgreSQL\n";
    }
#endif

    if (!storage) {
        storage = std::make_shared<ezone::MemoryStorageAdapter>();
        std::cout << "[ezone] Storage: in-memory (data will not survive restart)\n";
    }

    // ── Auth instance ─────────────────────────────────────────────────────────
    ezone::AuthConfig auth_cfg;
    // Override defaults from environment if present
    if (const char* v = std::getenv("EZONE_SESSION_TTL"))
        auth_cfg.session_ttl_seconds = static_cast<uint32_t>(std::stoul(v));
    if (const char* v = std::getenv("EZONE_CHALLENGE_TTL"))
        auth_cfg.challenge_ttl_seconds = static_cast<uint32_t>(std::stoul(v));

    // Which auth methods this server exposes. Without this, the REST server
    // is stuck on AUTH_METHOD_DEFAULT (Challenge + MagicLink + Recovery) —
    // WebAuthn/QR/Push/OTP/biometric would be compiled in but unreachable
    // via the shipped binary. Comma-separated list, or "all".
    if (const char* v = std::getenv("EZONE_ENABLED_METHODS")) {
        std::string list = v;
        if (list == "all") {
            auth_cfg.enabled_methods = ezone::AUTH_METHOD_ALL;
        } else {
            uint8_t methods = 0;
            std::stringstream ss(list);
            std::string tok;
            while (std::getline(ss, tok, ',')) {
                if      (tok == "challenge")   methods |= static_cast<uint8_t>(ezone::AuthMethod::Challenge);
                else if (tok == "magic_link")  methods |= static_cast<uint8_t>(ezone::AuthMethod::MagicLink);
                else if (tok == "recovery")    methods |= static_cast<uint8_t>(ezone::AuthMethod::Recovery);
                else if (tok == "webauthn")    methods |= static_cast<uint8_t>(ezone::AuthMethod::WebAuthn);
                else if (tok == "qr_code")     methods |= static_cast<uint8_t>(ezone::AuthMethod::QRCode);
                else if (tok == "push")        methods |= static_cast<uint8_t>(ezone::AuthMethod::Push);
                else if (tok == "otp")         methods |= static_cast<uint8_t>(ezone::AuthMethod::OTP);
                // Note: biometric has no dedicated bit — it's created
                // automatically whenever webauthn or push is enabled.
            }
            if (methods != 0) auth_cfg.enabled_methods = methods;
        }
    }

    // WebAuthn's Relying Party ID must match the domain serving the app —
    // the "localhost" default only works for local development. Without an
    // override, WebAuthn registration/authentication silently fails (origin
    // mismatch) on any real deployment.
    if (const char* v = std::getenv("EZONE_WEBAUTHN_RP_ID"))
        auth_cfg.webauthn_rp_id = v;
    if (const char* v = std::getenv("EZONE_WEBAUTHN_RP_NAME"))
        auth_cfg.webauthn_rp_name = v;

    // Configure crypto strategy from environment
    if (const char* v = std::getenv("EZONE_CRYPTO_PROFILE")) {
        std::string profile = v;
        if (profile == "fips") auth_cfg.crypto_strategy.profile = ezone::CryptoProfile::FIPS;
        else if (profile == "performance") auth_cfg.crypto_strategy.profile = ezone::CryptoProfile::Performance;
        else if (profile == "balanced") auth_cfg.crypto_strategy.profile = ezone::CryptoProfile::Balanced;
    }
    if (std::getenv("EZONE_PREFER_ED25519")) auth_cfg.crypto_strategy.prefer_ed25519 = true;
    if (std::getenv("EZONE_PREFER_CHACHA20")) auth_cfg.crypto_strategy.prefer_chacha20 = true;
    if (std::getenv("EZONE_REQUIRE_FIPS")) auth_cfg.crypto_strategy.require_fips = true;

    auto auth = ezone::Auth::create(storage, std::move(keys.value), auth_cfg);
    if (!auth) {
        std::cerr << "[ezone] Failed to create auth instance: "
                  << auth.error << "\n";
        return 1;
    }

    auto auth_ptr = std::make_shared<ezone::Auth>(std::move(auth.value));

    // ── REST server config ────────────────────────────────────────────────────
    ezone::rest::ServerConfig srv_cfg;

    if (const char* v = std::getenv("EZONE_HOST"))    srv_cfg.host    = v;
    if (const char* v = std::getenv("EZONE_PORT"))    srv_cfg.port    = std::stoi(v);
    if (const char* v = std::getenv("EZONE_THREADS")) srv_cfg.threads = std::stoi(v);
    if (const char* v = std::getenv("EZONE_APP_URL")) srv_cfg.app_url = v;
    if (const char* v = std::getenv("EZONE_CORS_ORIGIN")) srv_cfg.cors_origin = v;
    if (const char* v = std::getenv("EZONE_RATE_LIMIT"))
        srv_cfg.rate_limit_per_min = std::stoi(v);
    if (const char* v = std::getenv("EZONE_TRUST_PROXY"))
        srv_cfg.trust_proxy_headers = (std::string(v) == "1" || std::string(v) == "true");

    // ── TLS config ────────────────────────────────────────────────────────────
    if (const char* v = std::getenv("EZONE_TLS_CERT")) {
        srv_cfg.cert_path = v;
        srv_cfg.use_tls   = true;
    }
    if (const char* v = std::getenv("EZONE_TLS_KEY")) {
        srv_cfg.key_path = v;
    }

    // ── Email provider ────────────────────────────────────────────────────────
    std::shared_ptr<ezone::EmailProvider> email_provider;

    const char* email_provider_env = std::getenv("EZONE_EMAIL_PROVIDER");
    std::string email_provider_name = email_provider_env ? email_provider_env : "log";

    if (email_provider_name == "resend") {
        const char* api_key = std::getenv("EZONE_RESEND_API_KEY");
        const char* from    = std::getenv("EZONE_EMAIL_FROM");

        if (!api_key || !from) {
            std::cerr << "[ezone] EZONE_EMAIL_PROVIDER=resend requires "
                         "EZONE_RESEND_API_KEY and EZONE_EMAIL_FROM to be set.\n";
            return 1;
        }

        ezone::ResendConfig resend_cfg;
        resend_cfg.api_key = api_key;
        resend_cfg.from    = from;

        // Optional subject overrides
        if (const char* v = std::getenv("EZONE_SUBJECT_REGISTER"))
            resend_cfg.register_subject = v;
        if (const char* v = std::getenv("EZONE_SUBJECT_LOGIN"))
            resend_cfg.login_subject = v;
        if (const char* v = std::getenv("EZONE_SUBJECT_RESET"))
            resend_cfg.reset_subject = v;
        if (const char* v = std::getenv("EZONE_SUBJECT_ADD_DEVICE"))
            resend_cfg.add_device_subject = v;

        email_provider = std::make_shared<ezone::ResendEmailProvider>(
            std::move(resend_cfg));
        std::cout << "[ezone] Email provider: Resend (from: " << from << ")\n";
    } else {
        email_provider = std::make_shared<ezone::LogEmailProvider>();
        std::cout << "[ezone] Email provider: log (magic links printed to stdout)\n";
    }

    // ── SMS OTP (optional) ───────────────────────────────────────────────────
    // If you have an SMS gateway (Twilio, Vonage, etc.), wire it up here:
    //
    // if (auth_ptr->otp()) {
    //     auth_ptr->otp()->set_sms_sender(
    //         [](const std::string& phone, const std::string& code,
    //            uint32_t ttl) -> ezone::Result<void> {
    //             // Call your SMS gateway API here
    //             // e.g. twilio_send_sms(phone, "Your OTP: " + code);
    //             return ezone::Result<void>::success();
    //         });
    // }
    //
    // Without this, only email OTP works (no SMS gateway needed).

    // ── Start ─────────────────────────────────────────────────────────────────
    ezone::rest::RestServer server(auth_ptr, srv_cfg, email_provider);
    g_server = &server;

    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    // Print crypto strategy
    ezone::CryptoStrategy strategy(auth_cfg.crypto_strategy);
    std::cout << "[ezone] " << strategy.describe() << "\n";

    std::cout << "[ezone] REST server listening on "
              << srv_cfg.host << ":" << srv_cfg.port << "\n";

    server.run();

    std::cout << "[ezone] Server stopped.\n";
    return 0;
}
