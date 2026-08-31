#pragma once

#include "crypto_engine.h"
#include "storage_adapter.h"
#include "types.h"
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ezone {

// ─── Push Auth Types ─────────────────────────────────────────────────────────

// Platform type for the push device
enum class PushPlatform : uint8_t {
    IOS     = 0,  // APNs
    Android = 1,  // FCM
    Web     = 2,  // Web Push
};

const char* push_platform_string(PushPlatform p) noexcept;

// A registered mobile device capable of receiving push notifications
struct PushDevice {
    std::string          device_id;       // unique device identifier
    std::string          user_id;         // owner user_id
    PushPlatform         platform = PushPlatform::IOS;
    std::string          push_token;      // APNs/FCM/Web Push token
    std::vector<uint8_t> public_key_der;  // device's P-384 public key for signing approvals
    std::string          label;           // e.g. "Alice's iPhone"
    uint64_t             created_at = 0;
    bool                 active = true;
};

// Status of a push auth request
enum class PushStatus : uint8_t {
    Pending  = 0,  // Push sent, waiting for response
    Approved = 1,  // User approved on mobile
    Denied   = 2,  // User denied on mobile
    Expired  = 3,  // Push request expired
    Error    = 4   // An error occurred
};

const char* push_status_string(PushStatus s) noexcept;

// A pending push authentication request
struct PushRequest {
    std::string request_id;   // unique request identifier
    std::string user_id;      // user who initiated login
    std::string challenge;    // base64url-encoded challenge
    PushStatus  status = PushStatus::Pending;
    uint64_t    created_at = 0;
    uint64_t    expires_at = 0;
    std::string target_device_id; // if null, sent to all user's devices
};

// Mobile client's approval response
struct PushApproval {
    std::string request_id;               // which request this approval is for
    std::string device_id;                // approving device
    std::vector<uint8_t> signature;       // signature over the challenge
    std::string device_label;             // e.g. "Alice's iPhone"
};

// ─── Push Auth Server ────────────────────────────────────────────────────────
//
// Server-side push notification authentication.
// User initiates login on desktop → server sends push to registered mobile
// devices → user approves (with biometric) → desktop gets authenticated.

// Callback type for sending push notifications
using PushNotificationCallback = std::function<Result<void>(
    const PushDevice& device,
    const std::string& request_id,
    const std::string& challenge
)>;

class PushAuthServer {
public:
    // storage: device registrations are persisted through this adapter
    // (StorageAdapter::PushDeviceRecord) rather than kept in a separate
    // in-memory registry, so push devices survive restarts and are visible
    // to the same storage backend as everything else.
    PushAuthServer(
        CryptoEngine& engine,
        const SecureBuffer& hmac_key,
        std::shared_ptr<StorageAdapter> storage,
        uint32_t push_ttl_seconds = 120, // 2 min default
        PushNotificationCallback push_sender = nullptr
    );
    ~PushAuthServer();

    PushAuthServer(const PushAuthServer&) = delete;
    PushAuthServer& operator=(const PushAuthServer&) = delete;

    // ── Device management ────────────────────────────────────────────────────

    // Register a mobile device for push notifications
    Result<PushDevice> register_device(
        const std::string& user_id,
        PushPlatform platform,
        const std::string& push_token,
        const std::vector<uint8_t>& public_key_der,
        const std::string& label = "Mobile Device"
    );

    // Deactivate a push device
    Result<void> deactivate_device(const std::string& device_id);

    // List active push devices for a user
    Result<std::vector<PushDevice>> list_devices(const std::string& user_id);

    // ── Authentication flow ──────────────────────────────────────────────────

    // Begin push auth — sends push notifications to user's devices.
    // Returns a request_id for polling.
    Result<PushRequest> begin_push_auth(
        const std::string& user_id,
        const std::string& target_device_id = "" // empty = all devices
    );

    // Poll push status — original client calls this to check approval.
    Result<PushStatus> poll_push_status(const std::string& request_id);

    // Complete push auth — once status is Approved, call this to get the session.
    Result<PushDevice> complete_push_auth(const std::string& request_id);

    // ── Mobile flow ──────────────────────────────────────────────────────────

    // Approve a push request — mobile signs the challenge and sends approval.
    Result<void> approve_push(const PushApproval& approval);

    // Deny a push request — mobile user declines the login.
    Result<void> deny_push(const std::string& request_id);

    // ── Callback ─────────────────────────────────────────────────────────────

    // Set or change the push notification callback
    void set_push_sender(PushNotificationCallback callback);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ezone
