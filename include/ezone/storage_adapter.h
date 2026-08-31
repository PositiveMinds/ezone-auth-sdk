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
    std::string username;      // optional — alternative to email for identification
    std::string display_name;  // optional — shown in UI (e.g. "Alice Johnson")
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

// ─── WebAuthn credential record ──────────────────────────────────────────────
// Stored after a successful FIDO2 registration ceremony.
struct WebAuthnCredentialRecord {
    std::string          credential_id;  // base64url-encoded credential identifier
    std::vector<uint8_t> public_key_der; // COSE public key bytes
    std::string          user_id;
    uint64_t             sign_count = 0;
    uint64_t             created_at = 0;
    std::string          aaguid;         // authenticator model identifier
    std::string          label;          // user-friendly label
    bool                 backed_up = false;
    bool                 uv_required = false;
};

// ─── Push device record ──────────────────────────────────────────────────────
// A mobile device registered to receive push auth notifications.
struct PushDeviceRecord {
    std::string          device_id;       // unique device identifier
    std::string          user_id;
    uint8_t              platform = 0;    // 0=IOS, 1=Android, 2=Web
    std::string          push_token;      // APNs/FCM/Web Push token
    std::vector<uint8_t> public_key_der;  // device P-384 public key
    std::string          label;
    uint64_t             created_at = 0;
    bool                 active = true;
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
    virtual Result<UserRecord> get_user_by_username(const std::string& username)  = 0;
    virtual Result<void>       deactivate_user(const std::string& user_id)       = 0;
    virtual Result<void>       update_user(const UserRecord& user)               = 0;

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

    // ── WebAuthn credentials (optional — enable AuthMethod::WebAuthn) ─────────
    virtual Result<void> add_webauthn_credential(const WebAuthnCredentialRecord& cred)    = 0;
    virtual Result<std::vector<WebAuthnCredentialRecord>> get_webauthn_credentials(
        const std::string& user_id)                                                       = 0;
    virtual Result<WebAuthnCredentialRecord> get_webauthn_credential(
        const std::string& credential_id)                                                 = 0;
    virtual Result<void> update_webauthn_sign_count(
        const std::string& credential_id, uint64_t new_count)                             = 0;
    virtual Result<void> remove_webauthn_credential(const std::string& credential_id)     = 0;

    // ── Push devices (optional — enable AuthMethod::Push) ─────────────────────
    virtual Result<void> add_push_device(const PushDeviceRecord& dev)                      = 0;
    virtual Result<std::vector<PushDeviceRecord>> get_push_devices(
        const std::string& user_id)                                                       = 0;
    virtual Result<PushDeviceRecord> get_push_device(const std::string& device_id)         = 0;
    virtual Result<void> deactivate_push_device(const std::string& device_id)              = 0;
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
    Result<UserRecord> get_user_by_username(const std::string& username) override;
    Result<void>       deactivate_user(const std::string& user_id) override;
    Result<void>       update_user(const UserRecord& user)         override;

    Result<void>                      add_device(const DeviceRecord& dev)         override;
    Result<std::vector<DeviceRecord>> get_devices(const std::string& user_id)     override;
    Result<DeviceRecord>              get_device(const std::string& device_id)    override;
    Result<void>                      revoke_device(const std::string& device_id) override;

    Result<void> store_recovery_hash(
        const std::string& user_id, const std::string& code_hash) override;
    Result<bool> consume_recovery_hash(
        const std::string& user_id, const std::string& code_hash) override;
    Result<void> clear_recovery_hashes(const std::string& user_id) override;

    Result<void> add_webauthn_credential(const WebAuthnCredentialRecord& cred) override;
    Result<std::vector<WebAuthnCredentialRecord>> get_webauthn_credentials(
        const std::string& user_id) override;
    Result<WebAuthnCredentialRecord> get_webauthn_credential(
        const std::string& credential_id) override;
    Result<void> update_webauthn_sign_count(
        const std::string& credential_id, uint64_t new_count) override;
    Result<void> remove_webauthn_credential(const std::string& credential_id) override;

    Result<void> add_push_device(const PushDeviceRecord& dev) override;
    Result<std::vector<PushDeviceRecord>> get_push_devices(
        const std::string& user_id) override;
    Result<PushDeviceRecord> get_push_device(const std::string& device_id) override;
    Result<void> deactivate_push_device(const std::string& device_id) override;

private:
    mutable std::mutex mutex_;

    std::unordered_map<std::string, UserRecord>   users_by_id_;
    std::unordered_map<std::string, std::string>  email_to_id_;    // email  → user_id
    std::unordered_map<std::string, std::string>  username_to_id_; // username → user_id
    std::unordered_map<std::string, DeviceRecord> devices_;        // dev_id → device
    std::unordered_map<std::string,
        std::vector<std::string>>                 user_devices_;   // user_id → dev_ids
    std::unordered_map<std::string,
        std::set<std::string>>                    recovery_hashes_; // user_id → hashes
    std::unordered_map<std::string,
        WebAuthnCredentialRecord>                  webauthn_creds_;  // cred_id → credential
    std::unordered_map<std::string,
        std::vector<std::string>>                  user_webauthn_;   // user_id → cred_ids
    std::unordered_map<std::string,
        PushDeviceRecord>                          push_devices_;    // dev_id → push device
    std::unordered_map<std::string,
        std::vector<std::string>>                  user_push_devs_;  // user_id → push dev_ids
};

} // namespace ezone
