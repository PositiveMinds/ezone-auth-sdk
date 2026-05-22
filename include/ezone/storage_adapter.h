#pragma once

#include "types.h"
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace ezone {

// ─── Data records ─────────────────────────────────────────────────────────────

struct UserRecord {
    std::string user_id;
    std::string email;
    uint64_t    created_at = 0;
    bool        active     = true;
};

struct DeviceRecord {
    std::string          device_id;       // hex(SHA-384(public_key_der)[0:16])
    std::string          user_id;
    std::vector<uint8_t> public_key_der;
    std::string          label;
    uint64_t             created_at = 0;
    bool                 revoked    = false;
};


// ─── StorageAdapter ───────────────────────────────────────────────────────────
//
// Pure interface — implement with your own database, Redis, file system, etc.
// ezone never calls any storage directly; everything flows through this.

class StorageAdapter {
public:
    virtual ~StorageAdapter() = default;

    // ── Users ────────────────────────────────────────────────────────────────
    virtual Result<void>       create_user(const UserRecord& user)               = 0;
    virtual Result<UserRecord> get_user_by_id(const std::string& user_id)        = 0;
    virtual Result<UserRecord> get_user_by_email(const std::string& email)       = 0;
    virtual Result<void>       deactivate_user(const std::string& user_id)       = 0;

    // ── Devices (one user can have many) ─────────────────────────────────────
    virtual Result<void>                      add_device(const DeviceRecord& dev)          = 0;
    virtual Result<std::vector<DeviceRecord>> get_devices(const std::string& user_id)      = 0;
    virtual Result<DeviceRecord>              get_device(const std::string& device_id)     = 0;
    virtual Result<void>                      revoke_device(const std::string& device_id)  = 0;

    // ── Recovery codes (store only HMAC hashes — never plaintext) ────────────
    virtual Result<void> store_recovery_hash(
        const std::string& user_id,
        const std::string& code_hash)                                                 = 0;
    virtual Result<bool> consume_recovery_hash(
        const std::string& user_id,
        const std::string& code_hash)                                                 = 0;
    virtual Result<void> clear_recovery_hashes(const std::string& user_id)           = 0;
};


// ─── MemoryStorageAdapter ─────────────────────────────────────────────────────
//
// Built-in thread-safe in-memory adapter.
// Zero dependencies — suitable for testing and single-process deployments.
// Data does not survive process restart; swap for a persistent adapter in prod.

class MemoryStorageAdapter : public StorageAdapter {
public:
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
    mutable std::mutex mutex_;

    std::unordered_map<std::string, UserRecord>   users_by_id_;
    std::unordered_map<std::string, std::string>  email_to_id_;    // email  → user_id
    std::unordered_map<std::string, DeviceRecord> devices_;        // dev_id → device
    std::unordered_map<std::string,
        std::vector<std::string>>                 user_devices_;   // user_id → dev_ids
    std::unordered_map<std::string,
        std::set<std::string>>                    recovery_hashes_; // user_id → hashes
};

} // namespace ezone
