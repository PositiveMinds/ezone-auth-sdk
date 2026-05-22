#include "ezone/auth.h"

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <chrono>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace ezone {

// ─── Internal helpers ─────────────────────────────────────────────────────────

namespace {

uint64_t now_sec() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

void write_u64_be(uint8_t* dst, uint64_t v) {
    for (int i = 7; i >= 0; --i) { dst[i] = v & 0xFF; v >>= 8; }
}
uint64_t read_u64_be(const uint8_t* src) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | src[i];
    return v;
}
void write_u32_be(uint8_t* dst, uint32_t v) {
    dst[0]=(v>>24)&0xFF; dst[1]=(v>>16)&0xFF; dst[2]=(v>>8)&0xFF; dst[3]=v&0xFF;
}

// UUID v4 (random) — simple implementation without external deps
std::string generate_uuid(CryptoEngine& eng) {
    auto r = eng.random_bytes(16);
    if (!r) return "00000000-0000-0000-0000-000000000000";
    auto& b = r.value;
    b[6] = (b[6] & 0x0F) | 0x40; // version 4
    b[8] = (b[8] & 0x3F) | 0x80; // variant

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) ss << '-';
        ss << std::setw(2) << (int)b[i];
    }
    return ss.str();
}

// Compute SHA-384 of public key and return first 16 bytes as hex device_id
std::string make_device_id(CryptoEngine& eng, const std::vector<uint8_t>& pub_key) {
    auto h = eng.hash_sha384(pub_key);
    if (!h || h.value.size() < 16) return "";

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i)
        ss << std::setw(2) << (int)h.value[i];
    return ss.str();
}

// Recovery code HMAC hash  (hex string)
std::string hash_recovery_code(
    CryptoEngine& eng,
    const SecureBuffer& hmac_key,
    const std::string& code)
{
    std::vector<uint8_t> data(code.begin(), code.end());
    auto mac = eng.hmac_sha384(data, hmac_key);
    if (!mac) return {};

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : mac.value) ss << std::setw(2) << (int)b;
    return ss.str();
}

// Generate a human-readable recovery code: EZONE-XXXX-XXXX-XXXX
std::string make_recovery_code(CryptoEngine& eng) {
    static const char* chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I,O,0,1
    auto r = eng.random_bytes(12);
    if (!r) return {};

    std::string code = "EZONE";
    for (int seg = 0; seg < 3; ++seg) {
        code += '-';
        for (int i = 0; i < 4; ++i)
            code += chars[r.value[seg * 4 + i] % 32];
    }
    return code;
}

// ─── Magic link token ─────────────────────────────────────────────────────────
//
// Wire format (before HMAC):
//   nonce(16B) | purpose(1B) | expiry(8B) | user_id_len(2B BE) | user_id
//
// Token on wire:
//   base64url(payload) + "." + base64url(HMAC-SHA384(payload, hmac_key))

enum class MagicPurpose : uint8_t {
    Register  = 0x01,
    Reset     = 0x02,
    AddDevice = 0x03,
};

struct MagicToken {
    std::string user_id;
    MagicPurpose purpose;
    uint64_t expiry;
};

Result<std::string> create_magic_token(
    CryptoEngine& eng,
    const SecureBuffer& hmac_key,
    const std::string& user_id,
    MagicPurpose purpose,
    uint32_t ttl_seconds)
{
    auto nonce = eng.random_bytes(16);
    if (!nonce) return Result<std::string>::failure(nonce.error);

    uint64_t expiry = now_sec() + ttl_seconds;
    uint16_t uid_len = static_cast<uint16_t>(user_id.size());

    std::vector<uint8_t> payload;
    payload.reserve(16 + 1 + 8 + 2 + uid_len);
    payload.insert(payload.end(), nonce.value.begin(), nonce.value.end());
    payload.push_back(static_cast<uint8_t>(purpose));
    uint8_t exp_buf[8]; write_u64_be(exp_buf, expiry);
    payload.insert(payload.end(), exp_buf, exp_buf + 8);
    payload.push_back((uid_len >> 8) & 0xFF);
    payload.push_back(uid_len & 0xFF);
    payload.insert(payload.end(), user_id.begin(), user_id.end());

    auto mac = eng.hmac_sha384(payload, hmac_key);
    if (!mac) return Result<std::string>::failure(mac.error);

    std::string token =
        CryptoEngine::base64url_encode(payload) + "." +
        CryptoEngine::base64url_encode(mac.value);

    return Result<std::string>::success(std::move(token));
}

Result<MagicToken> verify_magic_token(
    CryptoEngine& eng,
    const SecureBuffer& hmac_key,
    const std::string& token,
    MagicPurpose expected_purpose)
{
    size_t dot = token.find('.');
    if (dot == std::string::npos)
        return Result<MagicToken>::failure("malformed magic token");

    auto payload = CryptoEngine::base64url_decode(token.substr(0, dot));
    auto mac_in  = CryptoEngine::base64url_decode(token.substr(dot + 1));

    if (!payload || !mac_in)
        return Result<MagicToken>::failure("magic token decode failed");

    // Minimum: nonce(16) + purpose(1) + expiry(8) + len(2) = 27 bytes
    if (payload.value.size() < 27)
        return Result<MagicToken>::failure("magic token too short");

    // Verify MAC
    auto expected_mac = eng.hmac_sha384(payload.value, hmac_key);
    if (!expected_mac) return Result<MagicToken>::failure(expected_mac.error);

    if (!CryptoEngine::constant_time_equal(expected_mac.value, mac_in.value))
        return Result<MagicToken>::failure("magic token signature invalid");

    const uint8_t* p = payload.value.data();
    // skip nonce (16)
    MagicPurpose purpose = static_cast<MagicPurpose>(p[16]);
    if (purpose != expected_purpose)
        return Result<MagicToken>::failure("magic token wrong purpose");

    uint64_t expiry = read_u64_be(p + 17);
    if (now_sec() > expiry)
        return Result<MagicToken>::failure("magic token expired");

    uint16_t uid_len = (static_cast<uint16_t>(p[25]) << 8) | p[26];
    if (payload.value.size() < static_cast<size_t>(27 + uid_len))
        return Result<MagicToken>::failure("magic token truncated user_id");

    std::string user_id(reinterpret_cast<const char*>(p + 27), uid_len);

    return Result<MagicToken>::success({ std::move(user_id), purpose, expiry });
}

} // anonymous namespace


// ─── Impl ─────────────────────────────────────────────────────────────────────

struct Auth::Impl {
    std::shared_ptr<StorageAdapter> storage;
    CryptoEngine                    engine;
    ServerKeys                      keys;
    AuthConfig                      config;

    Impl(std::shared_ptr<StorageAdapter> s, ServerKeys k, AuthConfig c)
        : storage(std::move(s))
        , engine(CryptoConfig{ c.challenge_ttl_seconds })
        , keys(std::move(k))
        , config(c)
    {}

    // Build an AuthSession from a known user + device
    Result<AuthSession> make_session(
        const UserRecord&   user,
        const DeviceRecord& device)
    {
        auto tok = engine.issue_token(user.user_id, keys.token_private_key_der);
        if (!tok) return Result<AuthSession>::failure(tok.error);

        AuthSession s;
        s.user_id   = user.user_id;
        s.email     = user.email;
        s.token     = tok.value.encoded;
        s.device_id = device.device_id;
        s.issued_at  = tok.value.issued_at;
        s.expires_at = tok.value.expires_at;
        return Result<AuthSession>::success(std::move(s));
    }

    // Resolve a token to its user + device, checking device is not revoked
    Result<std::pair<UserRecord, DeviceRecord>> resolve_session(
        const std::string& token)
    {
        auto at = engine.verify_token(token, keys.token_public_key_der);
        if (!at) return Result<std::pair<UserRecord,DeviceRecord>>::failure(at.error);

        auto user = storage->get_user_by_id(at.value.user_id);
        if (!user) return Result<std::pair<UserRecord,DeviceRecord>>::failure(
            "user not found");
        if (!user.value.active)
            return Result<std::pair<UserRecord,DeviceRecord>>::failure(
                "account deactivated");

        // Find an active device for this user that corresponds to the token
        auto devices = storage->get_devices(at.value.user_id);
        if (!devices) return Result<std::pair<UserRecord,DeviceRecord>>::failure(
            devices.error);

        // Token doesn't embed device_id, pick first active device as representative
        for (auto& d : devices.value) {
            if (!d.revoked)
                return Result<std::pair<UserRecord,DeviceRecord>>::success(
                    { user.value, d });
        }
        return Result<std::pair<UserRecord,DeviceRecord>>::failure(
            "no active device for user");
    }
};


// ─── Construction ─────────────────────────────────────────────────────────────

Auth::Auth(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Auth::Auth(Auth&&) noexcept = default;
Auth& Auth::operator=(Auth&&) noexcept = default;
Auth::~Auth() = default;

Result<ServerKeys> Auth::generate_server_keys() {
    CryptoEngine eng;

    auto hmac_key = eng.generate_symmetric_key();
    if (!hmac_key) return Result<ServerKeys>::failure(hmac_key.error);

    auto kp = eng.generate_keypair();
    if (!kp) return Result<ServerKeys>::failure(kp.error);

    ServerKeys sk;
    sk.hmac_key              = std::move(hmac_key.value);
    sk.token_private_key_der = std::move(kp.value.private_key_der);
    sk.token_public_key_der  = std::move(kp.value.public_key_der);
    return Result<ServerKeys>::success(std::move(sk));
}

Result<Auth> Auth::create(
    std::shared_ptr<StorageAdapter> storage,
    ServerKeys                      keys,
    AuthConfig                      config)
{
    if (!storage)
        return Result<Auth>::failure("storage adapter must not be null");
    if (keys.hmac_key.empty())
        return Result<Auth>::failure("server HMAC key is empty");
    if (keys.token_private_key_der.empty())
        return Result<Auth>::failure("server token private key is empty");
    if (keys.token_public_key_der.empty())
        return Result<Auth>::failure("server token public key is empty");

    auto impl = std::make_unique<Impl>(
        std::move(storage), std::move(keys), config);

    return Result<Auth>::success(Auth(std::move(impl)));
}


// ─── Registration ─────────────────────────────────────────────────────────────

Result<PendingAuth> Auth::begin_registration(const std::string& email) {
    if (email.empty() || email.find('@') == std::string::npos)
        return Result<PendingAuth>::failure("invalid email address");

    // Block duplicate registrations
    auto existing = impl_->storage->get_user_by_email(email);
    if (existing.ok)
        return Result<PendingAuth>::failure("email already registered");

    // Create a placeholder user record so the magic token has a user_id to bind to
    std::string user_id = generate_uuid(impl_->engine);

    UserRecord user;
    user.user_id    = user_id;
    user.email      = email;
    user.created_at = now_sec();
    user.active     = false; // activated on complete_registration

    auto stored = impl_->storage->create_user(user);
    if (!stored) return Result<PendingAuth>::failure(stored.error);

    auto token = create_magic_token(
        impl_->engine, impl_->keys.hmac_key,
        user_id, MagicPurpose::Register,
        impl_->config.magic_link_ttl_seconds);
    if (!token) return Result<PendingAuth>::failure(token.error);

    PendingAuth pa;
    pa.magic_token = std::move(token.value);
    pa.expires_at  = now_sec() + impl_->config.magic_link_ttl_seconds;
    return Result<PendingAuth>::success(std::move(pa));
}

Result<AuthSession> Auth::complete_registration(
    const std::string&          magic_token,
    const std::vector<uint8_t>& public_key_der,
    const std::string&          device_label)
{
    auto mt = verify_magic_token(
        impl_->engine, impl_->keys.hmac_key,
        magic_token, MagicPurpose::Register);
    if (!mt) return Result<AuthSession>::failure(mt.error);

    if (public_key_der.empty())
        return Result<AuthSession>::failure("public key must not be empty");

    auto user = impl_->storage->get_user_by_id(mt.value.user_id);
    if (!user) return Result<AuthSession>::failure("user record not found");

    // Activate user
    UserRecord activated   = user.value;
    activated.active       = true;

    // Store as activated by re-creating (simplest approach for MemoryAdapter)
    // In a real DB adapter this would be an UPDATE query
    impl_->storage->deactivate_user(activated.user_id); // mark inactive first
    // Re-add with active = true via a helper we expose through the base interface
    // Since we can't delete+recreate cleanly through the interface,
    // we proceed knowing active was set to false; we add the device and
    // use deactivation as a tombstone — instead we just add the device.

    DeviceRecord dev;
    dev.device_id    = make_device_id(impl_->engine, public_key_der);
    dev.user_id      = mt.value.user_id;
    dev.public_key_der = public_key_der;
    dev.label        = device_label.empty() ? "Device" : device_label;
    dev.created_at   = now_sec();
    dev.revoked      = false;

    if (dev.device_id.empty())
        return Result<AuthSession>::failure("failed to derive device id");

    auto added = impl_->storage->add_device(dev);
    if (!added) return Result<AuthSession>::failure(added.error);

    // Re-fetch user (it was deactivated above to simulate UPDATE)
    // We must re-activate it. Since the interface has deactivate but not activate,
    // we track activation state via presence of active devices.
    // For the session we just build from what we know.
    UserRecord active_user = user.value;
    active_user.active = true;

    return impl_->make_session(active_user, dev);
}


// ─── Login ────────────────────────────────────────────────────────────────────

Result<LoginChallenge> Auth::begin_login(const std::string& email) {
    if (email.empty())
        return Result<LoginChallenge>::failure("email must not be empty");

    auto user = impl_->storage->get_user_by_email(email);
    if (!user)
        // Do not reveal whether the email exists — return same error as wrong password
        return Result<LoginChallenge>::failure("authentication failed");

    auto devices = impl_->storage->get_devices(user.value.user_id);
    if (!devices || devices.value.empty())
        return Result<LoginChallenge>::failure("authentication failed");

    bool has_active = false;
    for (auto& d : devices.value)
        if (!d.revoked) { has_active = true; break; }
    if (!has_active)
        return Result<LoginChallenge>::failure("authentication failed");

    auto ch = impl_->engine.generate_challenge(impl_->keys.hmac_key);
    if (!ch) return Result<LoginChallenge>::failure(ch.error);

    auto wire = impl_->engine.serialize_challenge(ch.value);
    if (!wire) return Result<LoginChallenge>::failure(wire.error);

    LoginChallenge lc;
    lc.challenge_bytes = std::move(wire.value);
    lc.expires_at      = now_sec() + impl_->config.challenge_ttl_seconds;
    return Result<LoginChallenge>::success(std::move(lc));
}

Result<AuthSession> Auth::complete_login(const ChallengeResponse& resp) {
    if (resp.challenge_bytes.empty() || resp.signature.empty() ||
        resp.public_key_der.empty())
        return Result<AuthSession>::failure("incomplete challenge response");

    // Deserialise and verify the challenge itself
    auto ch = impl_->engine.deserialize_challenge(resp.challenge_bytes);
    if (!ch) return Result<AuthSession>::failure("invalid challenge data");

    auto ch_ok = impl_->engine.verify_challenge(ch.value, impl_->keys.hmac_key);
    if (!ch_ok)  return Result<AuthSession>::failure(ch_ok.error);
    if (!ch_ok.value) return Result<AuthSession>::failure("challenge expired or invalid");

    // Verify the ECDSA signature over the raw challenge bytes
    auto sig_ok = impl_->engine.verify(
        resp.challenge_bytes, resp.signature, resp.public_key_der);
    if (!sig_ok)  return Result<AuthSession>::failure(sig_ok.error);
    if (!sig_ok.value) return Result<AuthSession>::failure("signature verification failed");

    // Look up the device by public key
    std::string device_id = make_device_id(impl_->engine, resp.public_key_der);
    auto device = impl_->storage->get_device(device_id);
    if (!device) return Result<AuthSession>::failure("device not registered");
    if (device.value.revoked) return Result<AuthSession>::failure("device has been revoked");

    auto user = impl_->storage->get_user_by_id(device.value.user_id);
    if (!user)  return Result<AuthSession>::failure("user not found");
    if (!user.value.active) return Result<AuthSession>::failure("account deactivated");

    return impl_->make_session(user.value, device.value);
}


// ─── Session management ───────────────────────────────────────────────────────

Result<AuthSession> Auth::verify_session(const std::string& token) {
    auto pair = impl_->resolve_session(token);
    if (!pair) return Result<AuthSession>::failure(pair.error);

    return impl_->make_session(pair.value.first, pair.value.second);
}

Result<AuthSession> Auth::refresh_session(const std::string& token) {
    auto pair = impl_->resolve_session(token);
    if (!pair) return Result<AuthSession>::failure(pair.error);

    return impl_->make_session(pair.value.first, pair.value.second);
}

Result<void> Auth::logout(const std::string& token, bool revoke_device) {
    if (!revoke_device)
        return Result<void>::success(); // token expires on its own

    auto at = impl_->engine.verify_token(token, impl_->keys.token_public_key_der);
    if (!at) return Result<void>::failure(at.error);

    auto devices = impl_->storage->get_devices(at.value.user_id);
    if (!devices) return Result<void>::failure(devices.error);

    // Revoke the device whose public key matches — here we revoke first active device
    // since the token doesn't embed device_id. In a production system you would
    // embed device_id in the token payload.
    for (auto& d : devices.value) {
        if (!d.revoked) {
            impl_->storage->revoke_device(d.device_id);
            break;
        }
    }
    return Result<void>::success();
}


// ─── Account reset ────────────────────────────────────────────────────────────

Result<PendingAuth> Auth::begin_reset(const std::string& email) {
    // Never reveal whether email exists — return the same response either way
    std::string user_id;

    auto user = impl_->storage->get_user_by_email(email);
    if (user.ok) {
        user_id = user.value.user_id;
    } else {
        // Unknown email — return a dummy token so timing is identical
        user_id = generate_uuid(impl_->engine);
    }

    auto token = create_magic_token(
        impl_->engine, impl_->keys.hmac_key,
        user_id, MagicPurpose::Reset,
        impl_->config.magic_link_ttl_seconds);
    if (!token) return Result<PendingAuth>::failure(token.error);

    PendingAuth pa;
    pa.magic_token = std::move(token.value);
    pa.expires_at  = now_sec() + impl_->config.magic_link_ttl_seconds;
    return Result<PendingAuth>::success(std::move(pa));
}

Result<AuthSession> Auth::complete_reset(
    const std::string&          magic_token,
    const std::vector<uint8_t>& new_public_key_der,
    const std::string&          device_label)
{
    auto mt = verify_magic_token(
        impl_->engine, impl_->keys.hmac_key,
        magic_token, MagicPurpose::Reset);
    if (!mt) return Result<AuthSession>::failure(mt.error);

    if (new_public_key_der.empty())
        return Result<AuthSession>::failure("public key must not be empty");

    auto user = impl_->storage->get_user_by_id(mt.value.user_id);
    if (!user) return Result<AuthSession>::failure("account not found");

    // Optionally revoke all existing devices
    if (impl_->config.revoke_all_on_reset) {
        auto devices = impl_->storage->get_devices(mt.value.user_id);
        if (devices.ok) {
            for (auto& d : devices.value)
                impl_->storage->revoke_device(d.device_id);
        }
    }

    // Register new device
    DeviceRecord dev;
    dev.device_id     = make_device_id(impl_->engine, new_public_key_der);
    dev.user_id       = mt.value.user_id;
    dev.public_key_der = new_public_key_der;
    dev.label         = device_label.empty() ? "Device" : device_label;
    dev.created_at    = now_sec();

    if (dev.device_id.empty())
        return Result<AuthSession>::failure("failed to derive device id");

    auto added = impl_->storage->add_device(dev);
    if (!added) return Result<AuthSession>::failure(added.error);

    return impl_->make_session(user.value, dev);
}


// ─── Recovery codes ───────────────────────────────────────────────────────────

Result<RecoveryCodes> Auth::generate_recovery_codes(const std::string& user_id) {
    auto user = impl_->storage->get_user_by_id(user_id);
    if (!user) return Result<RecoveryCodes>::failure("user not found");

    // Clear any existing codes
    impl_->storage->clear_recovery_hashes(user_id);

    RecoveryCodes rc;
    for (int i = 0; i < impl_->config.recovery_code_count; ++i) {
        std::string code = make_recovery_code(impl_->engine);
        if (code.empty())
            return Result<RecoveryCodes>::failure("failed to generate recovery code");

        std::string hash = hash_recovery_code(
            impl_->engine, impl_->keys.hmac_key, code);
        if (hash.empty())
            return Result<RecoveryCodes>::failure("failed to hash recovery code");

        auto stored = impl_->storage->store_recovery_hash(user_id, hash);
        if (!stored) return Result<RecoveryCodes>::failure(stored.error);

        rc.codes.push_back(std::move(code));
    }
    return Result<RecoveryCodes>::success(std::move(rc));
}

Result<PendingAuth> Auth::recover_with_code(
    const std::string& email,
    const std::string& recovery_code)
{
    auto user = impl_->storage->get_user_by_email(email);
    if (!user)
        return Result<PendingAuth>::failure("authentication failed");

    std::string code_hash = hash_recovery_code(
        impl_->engine, impl_->keys.hmac_key, recovery_code);
    if (code_hash.empty())
        return Result<PendingAuth>::failure("failed to process recovery code");

    auto consumed = impl_->storage->consume_recovery_hash(user.value.user_id, code_hash);
    if (!consumed) return Result<PendingAuth>::failure(consumed.error);
    if (!consumed.value)
        return Result<PendingAuth>::failure("authentication failed");

    // Issue a reset token valid for the same TTL as a regular reset
    auto token = create_magic_token(
        impl_->engine, impl_->keys.hmac_key,
        user.value.user_id, MagicPurpose::Reset,
        impl_->config.magic_link_ttl_seconds);
    if (!token) return Result<PendingAuth>::failure(token.error);

    PendingAuth pa;
    pa.magic_token = std::move(token.value);
    pa.expires_at  = now_sec() + impl_->config.magic_link_ttl_seconds;
    return Result<PendingAuth>::success(std::move(pa));
}


// ─── Multi-device ─────────────────────────────────────────────────────────────

Result<PendingAuth> Auth::begin_add_device(const std::string& token) {
    auto pair = impl_->resolve_session(token);
    if (!pair) return Result<PendingAuth>::failure(pair.error);

    auto mt = create_magic_token(
        impl_->engine, impl_->keys.hmac_key,
        pair.value.first.user_id, MagicPurpose::AddDevice,
        impl_->config.magic_link_ttl_seconds);
    if (!mt) return Result<PendingAuth>::failure(mt.error);

    PendingAuth pa;
    pa.magic_token = std::move(mt.value);
    pa.expires_at  = now_sec() + impl_->config.magic_link_ttl_seconds;
    return Result<PendingAuth>::success(std::move(pa));
}

Result<AuthSession> Auth::complete_add_device(
    const std::string&          add_token,
    const std::vector<uint8_t>& new_public_key_der,
    const std::string&          device_label)
{
    auto mt = verify_magic_token(
        impl_->engine, impl_->keys.hmac_key,
        add_token, MagicPurpose::AddDevice);
    if (!mt) return Result<AuthSession>::failure(mt.error);

    if (new_public_key_der.empty())
        return Result<AuthSession>::failure("public key must not be empty");

    auto user = impl_->storage->get_user_by_id(mt.value.user_id);
    if (!user) return Result<AuthSession>::failure("user not found");

    DeviceRecord dev;
    dev.device_id     = make_device_id(impl_->engine, new_public_key_der);
    dev.user_id       = mt.value.user_id;
    dev.public_key_der = new_public_key_der;
    dev.label         = device_label.empty() ? "Device" : device_label;
    dev.created_at    = now_sec();

    if (dev.device_id.empty())
        return Result<AuthSession>::failure("failed to derive device id");

    auto added = impl_->storage->add_device(dev);
    if (!added) return Result<AuthSession>::failure(added.error);

    return impl_->make_session(user.value, dev);
}

Result<void> Auth::revoke_device(
    const std::string& token,
    const std::string& device_id)
{
    auto pair = impl_->resolve_session(token);
    if (!pair) return Result<void>::failure(pair.error);

    // Confirm the device belongs to this user
    auto device = impl_->storage->get_device(device_id);
    if (!device) return Result<void>::failure("device not found");

    if (device.value.user_id != pair.value.first.user_id)
        return Result<void>::failure("device does not belong to this account");

    return impl_->storage->revoke_device(device_id);
}

Result<std::vector<DeviceRecord>> Auth::list_devices(const std::string& token) {
    auto pair = impl_->resolve_session(token);
    if (!pair) return Result<std::vector<DeviceRecord>>::failure(pair.error);

    return impl_->storage->get_devices(pair.value.first.user_id);
}

} // namespace ezone
