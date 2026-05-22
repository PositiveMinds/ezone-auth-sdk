#include "server.h"
#include "ezone/auth.h"
#include "ezone/storage_adapter.h"
#include "ezone/email_provider.h"
#include "ezone/resend_provider.h"
#ifdef EZONE_POSTGRES_ENABLED
#include "ezone/postgres_adapter.h"
#endif

#include <cstdlib>
#include <csignal>
#include <iostream>
#include <memory>
#include <string>

// ─── Signal handling ──────────────────────────────────────────────────────────

static ezone::rest::RestServer* g_server = nullptr;

static void on_signal(int) {
    if (g_server) g_server->stop();
}


// ─── Entry point ──────────────────────────────────────────────────────────────

int main() {
    // ── Server keys ───────────────────────────────────────────────────────────
    // In production: load from environment variables / secrets manager.
    // Here we generate fresh keys on each start (suitable for dev/testing).
    auto keys = ezone::Auth::generate_server_keys();
    if (!keys) {
        std::cerr << "[ezone] Failed to generate server keys: "
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

    // ── Start ─────────────────────────────────────────────────────────────────
    ezone::rest::RestServer server(auth_ptr, srv_cfg, email_provider);
    g_server = &server;

    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    std::cout << "[ezone] REST server listening on "
              << srv_cfg.host << ":" << srv_cfg.port << "\n";

    server.run();

    std::cout << "[ezone] Server stopped.\n";
    return 0;
}
