#pragma once

#include "storage_adapter.h"
#include <memory>
#include <string>

namespace ezone {

struct PostgresConfig {
    // Connection string, e.g.:
    //   "host=localhost port=5432 dbname=ezone user=ezone password=secret sslmode=require"
    // Or a libpq URI:
    //   "postgresql://ezone:secret@localhost:5432/ezone?sslmode=require"
    std::string connection_string;

    // Connection pool size (number of simultaneous libpq connections).
    // For the default single-threaded server, 4 is plenty.
    int pool_size = 4;
};

// PostgreSQL-backed StorageAdapter using libpq.
//
// Usage:
//   auto adapter = PostgresStorageAdapter::create(cfg);
//   if (!adapter) { /* handle error */ }
//   auto auth = Auth::create(adapter.value, ...);
//
// Schema is created automatically on first connection (CREATE TABLE IF NOT EXISTS).
// All queries use parameterized statements — no SQL injection surface.
//
// Thread safety: the adapter maintains a simple mutex-guarded connection pool;
// it is safe to share a single instance across threads.

class PostgresStorageAdapter : public StorageAdapter {
public:
    static Result<std::shared_ptr<PostgresStorageAdapter>>
        create(const PostgresConfig& cfg);

    ~PostgresStorageAdapter() override;

    Result<void>       create_user(const UserRecord& user)         override;
    Result<UserRecord> get_user_by_id(const std::string& user_id)  override;
    Result<UserRecord> get_user_by_email(const std::string& email) override;
    Result<void>       deactivate_user(const std::string& user_id) override;

    Result<void>                      add_device(const DeviceRecord& dev)         override;
    Result<std::vector<DeviceRecord>> get_devices(const std::string& user_id)     override;
    Result<DeviceRecord>              get_device(const std::string& device_id)    override;
    Result<void>                      revoke_device(const std::string& device_id) override;

    Result<void> store_recovery_hash(
        const std::string& user_id, const std::string& code_hash) override;
    Result<bool> consume_recovery_hash(
        const std::string& user_id, const std::string& code_hash) override;
    Result<void> clear_recovery_hashes(const std::string& user_id) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    explicit PostgresStorageAdapter(std::unique_ptr<Impl> impl);
};

} // namespace ezone
