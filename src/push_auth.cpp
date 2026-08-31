#include "ezone/push_auth.h"

#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <unordered_map>

namespace ezone {

// ─── Helpers ─────────────────────────────────────────────────────────────────

namespace {

uint64_t now_sec() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

std::vector<uint8_t> secure_random(size_t count) {
    std::vector<uint8_t> buf(count);
    if (RAND_bytes(buf.data(), static_cast<int>(count)) != 1)
        return {};
    return buf;
}

static const char BASE64URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string base64url_encode(const std::vector<uint8_t>& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < data.size()) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < data.size()) n |= data[i + 2];
        out += BASE64URL_CHARS[(n >> 18) & 0x3F];
        out += BASE64URL_CHARS[(n >> 12) & 0x3F];
        if (i + 1 < data.size()) out += BASE64URL_CHARS[(n >> 6) & 0x3F];
        if (i + 2 < data.size()) out += BASE64URL_CHARS[n & 0x3F];
    }
    return out;
}

std::vector<uint8_t> base64url_decode(const std::string& encoded) {
    std::vector<uint8_t> out;
    out.reserve((encoded.size() * 3) / 4);
    uint32_t buf = 0;
    int bits = 0;
    for (char c : encoded) {
        int val = -1;
        if (c >= 'A' && c <= 'Z') val = c - 'A';
        else if (c >= 'a' && c <= 'z') val = c - 'a' + 26;
        else if (c >= '0' && c <= '9') val = c - '0' + 52;
        else if (c == '-') val = 62;
        else if (c == '_') val = 63;
        else continue;
        buf = (buf << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

// Generate a URL-safe request ID (16 bytes = 22 chars base64url)
std::string generate_request_id() {
    auto r = secure_random(16);
    if (r.empty()) return {};
    return base64url_encode(r);
}

// Generate a device ID from public key (same as auth.cpp)
std::string make_device_id(CryptoEngine& eng, const std::vector<uint8_t>& pub_key) {
    auto h = eng.hash_sha384(pub_key);
    if (!h || h.value.size() < 16) return "";
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i)
        ss << std::setw(2) << static_cast<int>(h.value[i]);
    return ss.str();
}

// Convert between the wire-facing PushDevice and the persisted
// StorageAdapter::PushDeviceRecord.
PushDeviceRecord to_record(const PushDevice& d) {
    PushDeviceRecord r;
    r.device_id      = d.device_id;
    r.user_id        = d.user_id;
    r.platform       = static_cast<uint8_t>(d.platform);
    r.push_token     = d.push_token;
    r.public_key_der = d.public_key_der;
    r.label          = d.label;
    r.created_at     = d.created_at;
    r.active         = d.active;
    return r;
}

PushDevice to_device(const PushDeviceRecord& r) {
    PushDevice d;
    d.device_id      = r.device_id;
    d.user_id        = r.user_id;
    d.platform       = static_cast<PushPlatform>(r.platform);
    d.push_token     = r.push_token;
    d.public_key_der = r.public_key_der;
    d.label          = r.label;
    d.created_at     = r.created_at;
    d.active         = r.active;
    return d;
}

} // anonymous namespace


// ─── PushPlatform / PushStatus strings ───────────────────────────────────────

const char* push_platform_string(PushPlatform p) noexcept {
    switch (p) {
        case PushPlatform::IOS:     return "ios";
        case PushPlatform::Android: return "android";
        case PushPlatform::Web:     return "web";
    }
    return "unknown";
}

const char* push_status_string(PushStatus s) noexcept {
    switch (s) {
        case PushStatus::Pending:  return "pending";
        case PushStatus::Approved: return "approved";
        case PushStatus::Denied:   return "denied";
        case PushStatus::Expired:  return "expired";
        case PushStatus::Error:    return "error";
    }
    return "unknown";
}


// ─── PushAuthServer::Impl ────────────────────────────────────────────────────

struct PushAuthServer::Impl {
    CryptoEngine& engine;
    SecureBuffer  hmac_key;
    std::shared_ptr<StorageAdapter> storage;
    uint32_t      push_ttl;
    PushNotificationCallback push_sender;

    // Pending push requests (short-lived — fine to keep in memory only)
    struct PushRequestState {
        PushRequest         data;
        std::string         challenge;   // raw challenge (base64url)
        std::string         device_id;   // which device approved
        std::vector<uint8_t> public_key_der; // approved device's key
        std::string         device_label;
    };
    std::unordered_map<std::string, PushRequestState> requests_; // request_id → state

    mutable std::mutex mu_;

    Impl(CryptoEngine& e, const SecureBuffer& hk,
         std::shared_ptr<StorageAdapter> s, uint32_t ttl,
         PushNotificationCallback cb)
        : engine(e), storage(std::move(s)), push_ttl(ttl), push_sender(std::move(cb))
    {
        hmac_key.resize(hk.size());
        std::memcpy(hmac_key.data(), hk.data(), hk.size());
    }

    // Generate HMAC-signed challenge
    std::string generate_challenge() {
        auto nonce = secure_random(32);
        if (nonce.empty()) return {};

        uint64_t ts = now_sec();
        std::vector<uint8_t> payload(40);
        std::memcpy(payload.data(), nonce.data(), 32);
        for (int i = 0; i < 8; ++i)
            payload[32 + i] = (ts >> (56 - 8 * i)) & 0xFF;

        auto mac = engine.hmac_sha384(payload, hmac_key);
        if (!mac) return {};

        std::vector<uint8_t> full;
        full.reserve(88);
        full.insert(full.end(), payload.begin(), payload.end());
        full.insert(full.end(), mac.value.begin(), mac.value.end());

        return base64url_encode(full);
    }

    // Verify challenge freshness
    bool verify_challenge(const std::string& challenge_b64) {
        auto full = base64url_decode(challenge_b64);
        if (full.size() != 88) return false;

        std::vector<uint8_t> payload(full.begin(), full.begin() + 40);
        std::vector<uint8_t> mac_received(full.begin() + 40, full.end());

        auto mac_expected = engine.hmac_sha384(payload, hmac_key);
        if (!mac_expected) return false;
        if (!CryptoEngine::constant_time_equal(mac_expected.value, mac_received))
            return false;

        uint64_t ts = 0;
        for (int i = 0; i < 8; ++i)
            ts = (ts << 8) | payload[32 + i];

        uint64_t current = now_sec();
        if (current > ts + push_ttl) return false;
        if (ts > current + 30) return false;

        return true;
    }

    // Clean up expired requests
    void cleanup_expired() {
        for (auto it = requests_.begin(); it != requests_.end(); ) {
            if (now_sec() > it->second.data.expires_at) {
                it->second.data.status = PushStatus::Expired;
                it = requests_.erase(it);
            } else {
                ++it;
            }
        }
    }
};


// ─── PushAuthServer public API ───────────────────────────────────────────────

PushAuthServer::PushAuthServer(
    CryptoEngine& engine,
    const SecureBuffer& hmac_key,
    std::shared_ptr<StorageAdapter> storage,
    uint32_t push_ttl_seconds,
    PushNotificationCallback push_sender)
    : impl_(std::make_unique<Impl>(engine, hmac_key, std::move(storage),
                                    push_ttl_seconds, std::move(push_sender)))
{}

PushAuthServer::~PushAuthServer() = default;


Result<PushDevice> PushAuthServer::register_device(
    const std::string& user_id,
    PushPlatform platform,
    const std::string& push_token,
    const std::vector<uint8_t>& public_key_der,
    const std::string& label)
{
    if (user_id.empty())
        return Result<PushDevice>::failure("user_id required");
    if (push_token.empty())
        return Result<PushDevice>::failure("push_token required");
    if (public_key_der.empty())
        return Result<PushDevice>::failure("public_key_der required");

    // Generate device ID from public key
    auto device_id = make_device_id(impl_->engine, public_key_der);
    if (device_id.empty())
        return Result<PushDevice>::failure("failed to derive device ID");

    PushDevice dev;
    dev.device_id = device_id;
    dev.user_id = user_id;
    dev.platform = platform;
    dev.push_token = push_token;
    dev.public_key_der = public_key_der;
    dev.label = label.empty() ? "Mobile Device" : label;
    dev.created_at = now_sec();
    dev.active = true;

    // Check for duplicate
    auto existing = impl_->storage->get_push_device(device_id);
    if (existing.ok)
        return Result<PushDevice>::failure("device already registered");

    auto added = impl_->storage->add_push_device(to_record(dev));
    if (!added) return Result<PushDevice>::failure(added.error);

    return Result<PushDevice>::success(std::move(dev));
}


Result<void> PushAuthServer::deactivate_device(const std::string& device_id) {
    return impl_->storage->deactivate_push_device(device_id);
}


Result<std::vector<PushDevice>> PushAuthServer::list_devices(
    const std::string& user_id)
{
    auto recs = impl_->storage->get_push_devices(user_id);
    if (!recs) return Result<std::vector<PushDevice>>::failure(recs.error);

    std::vector<PushDevice> out;
    out.reserve(recs.value.size());
    for (auto& r : recs.value)
        out.push_back(to_device(r));
    return Result<std::vector<PushDevice>>::success(std::move(out));
}


Result<PushRequest> PushAuthServer::begin_push_auth(
    const std::string& user_id,
    const std::string& target_device_id)
{
    if (user_id.empty())
        return Result<PushRequest>::failure("user_id required");

    std::lock_guard<std::mutex> lock(impl_->mu_);
    impl_->cleanup_expired();

    // Generate challenge
    auto challenge = impl_->generate_challenge();
    if (challenge.empty())
        return Result<PushRequest>::failure("failed to generate challenge");

    // Generate request ID
    auto request_id = generate_request_id();
    if (request_id.empty())
        return Result<PushRequest>::failure("failed to generate request ID");

    uint64_t ts = now_sec();

    // Build request
    PushRequest req;
    req.request_id = request_id;
    req.user_id = user_id;
    req.challenge = challenge;
    req.status = PushStatus::Pending;
    req.created_at = ts;
    req.expires_at = ts + impl_->push_ttl;
    req.target_device_id = target_device_id;

    // Store
    Impl::PushRequestState state;
    state.data = req;
    state.challenge = challenge;

    impl_->requests_[request_id] = std::move(state);

    // Send push notifications to target devices
    if (impl_->push_sender) {
        auto devices = impl_->storage->get_push_devices(user_id);
        if (devices.ok) {
            for (auto& rec : devices.value) {
                // If target specified, only send to that device
                if (!target_device_id.empty() && rec.device_id != target_device_id)
                    continue;

                auto send_result = impl_->push_sender(
                    to_device(rec), request_id, challenge);
                if (!send_result) {
                    fprintf(stderr, "[ezone] push notification failed for %s: %s\n",
                            rec.device_id.c_str(), send_result.error.c_str());
                }
            }
        }
    }

    return Result<PushRequest>::success(std::move(req));
}


Result<PushStatus> PushAuthServer::poll_push_status(const std::string& request_id) {
    std::lock_guard<std::mutex> lock(impl_->mu_);

    auto it = impl_->requests_.find(request_id);
    if (it == impl_->requests_.end())
        return Result<PushStatus>::failure("request not found");

    if (now_sec() > it->second.data.expires_at) {
        it->second.data.status = PushStatus::Expired;
        return Result<PushStatus>::success(PushStatus::Expired);
    }

    return Result<PushStatus>::success(it->second.data.status);
}


Result<PushDevice> PushAuthServer::complete_push_auth(
    const std::string& request_id)
{
    std::lock_guard<std::mutex> lock(impl_->mu_);

    auto it = impl_->requests_.find(request_id);
    if (it == impl_->requests_.end())
        return Result<PushDevice>::failure("request not found");

    auto& s = it->second;
    if (now_sec() > s.data.expires_at) {
        s.data.status = PushStatus::Expired;
        return Result<PushDevice>::failure("request expired");
    }
    if (s.data.status != PushStatus::Approved)
        return Result<PushDevice>::failure("request not yet approved");

    // Return the device that approved
    auto dev = impl_->storage->get_push_device(s.device_id);
    if (!dev) return Result<PushDevice>::failure("approving device not found");

    return Result<PushDevice>::success(to_device(dev.value));
}


Result<void> PushAuthServer::approve_push(const PushApproval& approval) {
    if (approval.request_id.empty())
        return Result<void>::failure("request_id required");
    if (approval.signature.empty())
        return Result<void>::failure("signature required");
    if (approval.device_id.empty())
        return Result<void>::failure("device_id required");

    std::lock_guard<std::mutex> lock(impl_->mu_);

    auto it = impl_->requests_.find(approval.request_id);
    if (it == impl_->requests_.end())
        return Result<void>::failure("request not found");

    auto& s = it->second;
    if (now_sec() > s.data.expires_at) {
        s.data.status = PushStatus::Expired;
        return Result<void>::failure("request expired");
    }
    if (s.data.status == PushStatus::Approved)
        return Result<void>::failure("request already approved");
    if (s.data.status == PushStatus::Denied)
        return Result<void>::failure("request was denied");

    // Verify the device is registered and active
    auto dev = impl_->storage->get_push_device(approval.device_id);
    if (!dev || !dev.value.active)
        return Result<void>::failure("device not registered or inactive");

    // Verify the device belongs to the same user as the request
    if (dev.value.user_id != s.data.user_id)
        return Result<void>::failure("device does not belong to this user");

    // Verify signature over the challenge
    auto ch = base64url_decode(s.data.challenge);
    if (ch.size() != 88)
        return Result<void>::failure("invalid challenge format");

    // Sign the raw challenge bytes (first 40 bytes — nonce + timestamp)
    std::vector<uint8_t> signed_data(ch.begin(), ch.begin() + 40);

    auto ok = impl_->engine.verify(
        signed_data, approval.signature, dev.value.public_key_der);
    if (!ok || !ok.value)
        return Result<void>::failure("invalid signature");

    // Mark as approved
    s.data.status = PushStatus::Approved;
    s.device_id = approval.device_id;
    s.public_key_der = dev.value.public_key_der;
    s.device_label = approval.device_label;

    return Result<void>::success();
}


Result<void> PushAuthServer::deny_push(const std::string& request_id) {
    if (request_id.empty())
        return Result<void>::failure("request_id required");

    std::lock_guard<std::mutex> lock(impl_->mu_);

    auto it = impl_->requests_.find(request_id);
    if (it == impl_->requests_.end())
        return Result<void>::failure("request not found");

    auto& s = it->second;
    if (now_sec() > s.data.expires_at) {
        s.data.status = PushStatus::Expired;
        return Result<void>::failure("request expired");
    }
    if (s.data.status == PushStatus::Approved)
        return Result<void>::failure("request already approved");

    s.data.status = PushStatus::Denied;
    return Result<void>::success();
}


void PushAuthServer::set_push_sender(PushNotificationCallback callback) {
    std::lock_guard<std::mutex> lock(impl_->mu_);
    impl_->push_sender = std::move(callback);
}

} // namespace ezone
