#include "ezone/postgres_adapter.h"
#include "ezone/types.h"

#include <libpq-fe.h>

#include <condition_variable>
#include <cstring>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <string>
#include <vector>

namespace ezone {

// ── Hex helpers ───────────────────────────────────────────────────────────────

static std::string to_hex(const std::vector<uint8_t>& bytes) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out += hex[b >> 4];
        out += hex[b & 0xf];
    }
    return out;
}

static std::vector<uint8_t> from_hex(const std::string& h) {
    std::vector<uint8_t> out;
    out.reserve(h.size() / 2);
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        out.push_back(static_cast<uint8_t>((nibble(h[i]) << 4) | nibble(h[i+1])));
    }
    return out;
}

// ── RAII wrapper around a single PGconn ───────────────────────────────────────

struct Conn {
    PGconn* pg = nullptr;

    explicit Conn(const std::string& connstr) {
        pg = PQconnectdb(connstr.c_str());
        if (PQstatus(pg) != CONNECTION_OK) {
            std::string err = PQerrorMessage(pg);
            PQfinish(pg);
            pg = nullptr;
            throw std::runtime_error("PostgreSQL connection failed: " + err);
        }
    }

    ~Conn() { if (pg) PQfinish(pg); }

    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;

    // Execute a parameterized query; throws on error.
    PGresult* exec(const char* sql,
                   const std::vector<const char*>& params) {
        PGresult* res = PQexecParams(
            pg, sql,
            static_cast<int>(params.size()),
            nullptr,        // let server infer types
            params.data(),
            nullptr,        // lengths (text mode)
            nullptr,        // formats (text mode)
            0               // result in text format
        );
        ExecStatusType st = PQresultStatus(res);
        if (st != PGRES_TUPLES_OK && st != PGRES_COMMAND_OK) {
            std::string err = PQresultErrorMessage(res);
            PQclear(res);
            throw std::runtime_error(err);
        }
        return res;  // caller must PQclear
    }
};

// ── Simple blocking connection pool ───────────────────────────────────────────

struct Pool {
    std::queue<std::unique_ptr<Conn>> idle;
    std::mutex mtx;
    std::condition_variable cv;
    std::string connstr;
    int max_size;

    Pool(const std::string& cs, int sz) : connstr(cs), max_size(sz) {
        for (int i = 0; i < sz; ++i)
            idle.push(std::make_unique<Conn>(connstr));
    }

    std::unique_ptr<Conn> acquire() {
        std::unique_lock<std::mutex> lk(mtx);
        cv.wait(lk, [this]{ return !idle.empty(); });
        auto c = std::move(idle.front());
        idle.pop();
        // Reset connection if it dropped
        if (PQstatus(c->pg) != CONNECTION_OK)
            PQreset(c->pg);
        return c;
    }

    void release(std::unique_ptr<Conn> c) {
        std::unique_lock<std::mutex> lk(mtx);
        idle.push(std::move(c));
        lk.unlock();
        cv.notify_one();
    }
};

// Scoped borrow from pool
struct PoolGuard {
    Pool& pool;
    std::unique_ptr<Conn> conn;

    explicit PoolGuard(Pool& p) : pool(p), conn(p.acquire()) {}
    ~PoolGuard() { pool.release(std::move(conn)); }

    Conn* operator->() { return conn.get(); }
};

// ── Schema ────────────────────────────────────────────────────────────────────

static const char* SCHEMA = R"sql(
CREATE TABLE IF NOT EXISTS ez_users (
    user_id    TEXT PRIMARY KEY,
    email      TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL DEFAULT 0,
    active     BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS ez_devices (
    device_id      TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES ez_users(user_id) ON DELETE CASCADE,
    public_key_hex TEXT NOT NULL,
    label          TEXT NOT NULL DEFAULT '',
    created_at     BIGINT NOT NULL DEFAULT 0,
    revoked        BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS ez_devices_user_idx ON ez_devices(user_id);

CREATE TABLE IF NOT EXISTS ez_recovery_hashes (
    user_id   TEXT NOT NULL REFERENCES ez_users(user_id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);
)sql";

static void apply_schema(Conn& conn) {
    PGresult* res = PQexec(conn.pg, SCHEMA);
    ExecStatusType st = PQresultStatus(res);
    PQclear(res);
    if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
        throw std::runtime_error(
            std::string("Schema migration failed: ") + PQerrorMessage(conn.pg));
    }
}

// ── Impl ──────────────────────────────────────────────────────────────────────

struct PostgresStorageAdapter::Impl {
    Pool pool;
    explicit Impl(const PostgresConfig& cfg)
        : pool(cfg.connection_string, cfg.pool_size) {}
};

// ── Factory ───────────────────────────────────────────────────────────────────

Result<std::shared_ptr<PostgresStorageAdapter>>
PostgresStorageAdapter::create(const PostgresConfig& cfg) {
    try {
        auto impl = std::make_unique<Impl>(cfg);

        // Apply schema on first pool connection
        PoolGuard g(impl->pool);
        apply_schema(*g.conn);

        return Result<std::shared_ptr<PostgresStorageAdapter>>::success(
            std::shared_ptr<PostgresStorageAdapter>(
                new PostgresStorageAdapter(std::move(impl))));
    } catch (const std::exception& e) {
        return Result<std::shared_ptr<PostgresStorageAdapter>>::failure(e.what());
    }
}

PostgresStorageAdapter::PostgresStorageAdapter(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

PostgresStorageAdapter::~PostgresStorageAdapter() = default;

// ── Users ─────────────────────────────────────────────────────────────────────

Result<void> PostgresStorageAdapter::create_user(const UserRecord& user) {
    try {
        PoolGuard g(impl_->pool);
        std::string ts = std::to_string(user.created_at);
        std::vector<const char*> p = {
            user.user_id.c_str(), user.email.c_str(), ts.c_str()
        };
        PGresult* res = g->exec(
            "INSERT INTO ez_users (user_id, email, created_at)"
            " VALUES ($1, $2, $3)"
            " ON CONFLICT DO NOTHING",
            p);
        PQclear(res);
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::failure(e.what());
    }
}

static UserRecord row_to_user(PGresult* res, int row) {
    UserRecord u;
    u.user_id    = PQgetvalue(res, row, 0);
    u.email      = PQgetvalue(res, row, 1);
    u.created_at = static_cast<uint64_t>(std::stoul(PQgetvalue(res, row, 2)));
    u.active     = std::string(PQgetvalue(res, row, 3)) == "t";
    return u;
}

Result<UserRecord> PostgresStorageAdapter::get_user_by_id(const std::string& user_id) {
    try {
        PoolGuard g(impl_->pool);
        std::vector<const char*> p = { user_id.c_str() };
        PGresult* res = g->exec(
            "SELECT user_id, email, created_at, active"
            " FROM ez_users WHERE user_id = $1", p);
        if (PQntuples(res) == 0) {
            PQclear(res);
            return Result<UserRecord>::failure("user not found");
        }
        UserRecord u = row_to_user(res, 0);
        PQclear(res);
        return Result<UserRecord>::success(std::move(u));
    } catch (const std::exception& e) {
        return Result<UserRecord>::failure(e.what());
    }
}

Result<UserRecord> PostgresStorageAdapter::get_user_by_email(const std::string& email) {
    try {
        PoolGuard g(impl_->pool);
        std::vector<const char*> p = { email.c_str() };
        PGresult* res = g->exec(
            "SELECT user_id, email, created_at, active"
            " FROM ez_users WHERE email = $1", p);
        if (PQntuples(res) == 0) {
            PQclear(res);
            return Result<UserRecord>::failure("user not found");
        }
        UserRecord u = row_to_user(res, 0);
        PQclear(res);
        return Result<UserRecord>::success(std::move(u));
    } catch (const std::exception& e) {
        return Result<UserRecord>::failure(e.what());
    }
}

Result<void> PostgresStorageAdapter::deactivate_user(const std::string& user_id) {
    try {
        PoolGuard g(impl_->pool);
        std::vector<const char*> p = { user_id.c_str() };
        PGresult* res = g->exec(
            "UPDATE ez_users SET active = FALSE WHERE user_id = $1", p);
        PQclear(res);
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::failure(e.what());
    }
}

// ── Devices ───────────────────────────────────────────────────────────────────

static DeviceRecord row_to_device(PGresult* res, int row) {
    DeviceRecord d;
    d.device_id      = PQgetvalue(res, row, 0);
    d.user_id        = PQgetvalue(res, row, 1);
    d.public_key_der = from_hex(PQgetvalue(res, row, 2));
    d.label          = PQgetvalue(res, row, 3);
    d.created_at     = static_cast<uint64_t>(std::stoul(PQgetvalue(res, row, 4)));
    d.revoked        = std::string(PQgetvalue(res, row, 5)) == "t";
    return d;
}

Result<void> PostgresStorageAdapter::add_device(const DeviceRecord& dev) {
    try {
        PoolGuard g(impl_->pool);
        std::string hex_key = to_hex(dev.public_key_der);
        std::string ts      = std::to_string(dev.created_at);
        std::vector<const char*> p = {
            dev.device_id.c_str(),
            dev.user_id.c_str(),
            hex_key.c_str(),
            dev.label.c_str(),
            ts.c_str()
        };
        PGresult* res = g->exec(
            "INSERT INTO ez_devices"
            " (device_id, user_id, public_key_hex, label, created_at)"
            " VALUES ($1, $2, $3, $4, $5)"
            " ON CONFLICT DO NOTHING",
            p);
        PQclear(res);
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::failure(e.what());
    }
}

Result<std::vector<DeviceRecord>>
PostgresStorageAdapter::get_devices(const std::string& user_id) {
    try {
        PoolGuard g(impl_->pool);
        std::vector<const char*> p = { user_id.c_str() };
        PGresult* res = g->exec(
            "SELECT device_id, user_id, public_key_hex, label, created_at, revoked"
            " FROM ez_devices WHERE user_id = $1 ORDER BY created_at",
            p);
        std::vector<DeviceRecord> devices;
        int n = PQntuples(res);
        devices.reserve(static_cast<size_t>(n));
        for (int i = 0; i < n; ++i)
            devices.push_back(row_to_device(res, i));
        PQclear(res);
        return Result<std::vector<DeviceRecord>>::success(std::move(devices));
    } catch (const std::exception& e) {
        return Result<std::vector<DeviceRecord>>::failure(e.what());
    }
}

Result<DeviceRecord>
PostgresStorageAdapter::get_device(const std::string& device_id) {
    try {
        PoolGuard g(impl_->pool);
        std::vector<const char*> p = { device_id.c_str() };
        PGresult* res = g->exec(
            "SELECT device_id, user_id, public_key_hex, label, created_at, revoked"
            " FROM ez_devices WHERE device_id = $1",
            p);
        if (PQntuples(res) == 0) {
            PQclear(res);
            return Result<DeviceRecord>::failure("device not found");
        }
        DeviceRecord d = row_to_device(res, 0);
        PQclear(res);
        return Result<DeviceRecord>::success(std::move(d));
    } catch (const std::exception& e) {
        return Result<DeviceRecord>::failure(e.what());
    }
}

Result<void> PostgresStorageAdapter::revoke_device(const std::string& device_id) {
    try {
        PoolGuard g(impl_->pool);
        std::vector<const char*> p = { device_id.c_str() };
        PGresult* res = g->exec(
            "UPDATE ez_devices SET revoked = TRUE WHERE device_id = $1", p);
        PQclear(res);
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::failure(e.what());
    }
}

// ── Recovery codes ────────────────────────────────────────────────────────────

Result<void> PostgresStorageAdapter::store_recovery_hash(
    const std::string& user_id,
    const std::string& code_hash)
{
    try {
        PoolGuard g(impl_->pool);
        std::vector<const char*> p = { user_id.c_str(), code_hash.c_str() };
        PGresult* res = g->exec(
            "INSERT INTO ez_recovery_hashes (user_id, code_hash)"
            " VALUES ($1, $2)"
            " ON CONFLICT DO NOTHING",
            p);
        PQclear(res);
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::failure(e.what());
    }
}

Result<bool> PostgresStorageAdapter::consume_recovery_hash(
    const std::string& user_id,
    const std::string& code_hash)
{
    try {
        PoolGuard g(impl_->pool);
        std::vector<const char*> p = { user_id.c_str(), code_hash.c_str() };
        PGresult* res = g->exec(
            "DELETE FROM ez_recovery_hashes"
            " WHERE user_id = $1 AND code_hash = $2"
            " RETURNING code_hash",
            p);
        bool found = PQntuples(res) > 0;
        PQclear(res);
        return Result<bool>::success(found);
    } catch (const std::exception& e) {
        return Result<bool>::failure(e.what());
    }
}

Result<void> PostgresStorageAdapter::clear_recovery_hashes(
    const std::string& user_id)
{
    try {
        PoolGuard g(impl_->pool);
        std::vector<const char*> p = { user_id.c_str() };
        PGresult* res = g->exec(
            "DELETE FROM ez_recovery_hashes WHERE user_id = $1", p);
        PQclear(res);
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::failure(e.what());
    }
}

} // namespace ezone
