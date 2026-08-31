#include "ezone/qr_auth.h"

#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstring>
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

// Generate a URL-safe session ID (16 bytes = 22 chars base64url)
std::string generate_session_id() {
    auto r = secure_random(16);
    if (r.empty()) return {};
    return base64url_encode(r);
}

} // anonymous namespace


// ─── QRStatus string ─────────────────────────────────────────────────────────

const char* qr_status_string(QRStatus s) noexcept {
    switch (s) {
        case QRStatus::Pending:  return "pending";
        case QRStatus::Scanned:  return "scanned";
        case QRStatus::Approved: return "approved";
        case QRStatus::Denied:   return "denied";
        case QRStatus::Expired:  return "expired";
        case QRStatus::Error:    return "error";
    }
    return "unknown";
}


// ─── QRAuthServer::Impl ──────────────────────────────────────────────────────

struct QRAuthServer::Impl {
    CryptoEngine& engine;
    SecureBuffer  hmac_key;
    uint32_t      qr_ttl;

    struct Session {
        QRSession              data;
        std::string            challenge;     // raw challenge bytes (base64url)
        std::string            device_id;     // approved device (filled on approve)
        std::vector<uint8_t>   public_key_der;
        std::string            device_label;
        std::string            desktop_ip;    // IP of the desktop (for IP binding)
        bool                   approved = false;
        bool                   denied   = false;
    };

    std::unordered_map<std::string, Session> sessions_;
    std::mutex mu_;

    Impl(CryptoEngine& e, const SecureBuffer& hk, uint32_t ttl)
        : engine(e), qr_ttl(ttl)
    {
        hmac_key.resize(hk.size());
        std::memcpy(hmac_key.data(), hk.data(), hk.size());
    }

    // Generate an HMAC-signed challenge for the QR code
    std::string generate_challenge() {
        auto nonce = secure_random(32);
        if (nonce.empty()) return {};

        uint64_t ts = now_sec();

        // Pack: nonce(32) + timestamp(8) = 40 bytes
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

    // Verify the challenge is valid and fresh
    bool verify_challenge(const std::string& challenge_b64) {
        auto full = base64url_decode(challenge_b64);
        if (full.size() != 88) return false;

        std::vector<uint8_t> payload(full.begin(), full.begin() + 40);
        std::vector<uint8_t> mac_received(full.begin() + 40, full.end());

        auto mac_expected = engine.hmac_sha384(payload, hmac_key);
        if (!mac_expected) return false;
        if (!CryptoEngine::constant_time_equal(mac_expected.value, mac_received))
            return false;

        // Check timestamp freshness
        uint64_t ts = 0;
        for (int i = 0; i < 8; ++i)
            ts = (ts << 8) | payload[32 + i];

        uint64_t current = now_sec();
        if (current > ts + qr_ttl) return false;
        if (ts > current + 30) return false; // future tolerance

        return true;
    }

    // Check if session is expired
    bool is_expired(const Session& s) {
        return now_sec() > s.data.expires_at;
    }

    // Clean up expired sessions (called periodically)
    void cleanup_expired() {
        for (auto it = sessions_.begin(); it != sessions_.end(); ) {
            if (is_expired(it->second))
                it = sessions_.erase(it);
            else
                ++it;
        }
    }
};


// ─── QRAuthServer public API ─────────────────────────────────────────────────

QRAuthServer::QRAuthServer(
    CryptoEngine& engine,
    const SecureBuffer& hmac_key,
    uint32_t qr_ttl_seconds)
    : impl_(std::make_unique<Impl>(engine, hmac_key, qr_ttl_seconds))
{}

QRAuthServer::~QRAuthServer() = default;


Result<QRSession> QRAuthServer::begin_qr_auth(const std::string& desktop_ip) {
    std::lock_guard<std::mutex> lock(impl_->mu_);
    impl_->cleanup_expired();

    // Generate session ID
    auto session_id = generate_session_id();
    if (session_id.empty())
        return Result<QRSession>::failure("failed to generate session ID");

    // Generate HMAC-signed challenge
    auto challenge = impl_->generate_challenge();
    if (challenge.empty())
        return Result<QRSession>::failure("failed to generate challenge");

    uint64_t ts = now_sec();

    // Build QR data payload (what gets encoded in the QR code)
    // Wire: version(1) | session_id_len(2) | session_id | challenge_len(2) | challenge | expires(8) | ip_len(2) | ip
    auto sid_bytes = std::vector<uint8_t>(session_id.begin(), session_id.end());
    auto ch_bytes = std::vector<uint8_t>(challenge.begin(), challenge.end());
    auto ip_bytes = std::vector<uint8_t>(desktop_ip.begin(), desktop_ip.end());

    std::vector<uint8_t> qr_plaintext;
    qr_plaintext.push_back(0x02); // version 2 (with IP binding + encryption)
    qr_plaintext.push_back((sid_bytes.size() >> 8) & 0xFF);
    qr_plaintext.push_back(sid_bytes.size() & 0xFF);
    qr_plaintext.insert(qr_plaintext.end(), sid_bytes.begin(), sid_bytes.end());
    qr_plaintext.push_back((ch_bytes.size() >> 8) & 0xFF);
    qr_plaintext.push_back(ch_bytes.size() & 0xFF);
    qr_plaintext.insert(qr_plaintext.end(), ch_bytes.begin(), ch_bytes.end());
    uint64_t expires = ts + impl_->qr_ttl;
    for (int i = 0; i < 8; ++i)
        qr_plaintext.push_back((expires >> (56 - 8 * i)) & 0xFF);
    // IP binding — embed desktop IP so mobile must match
    qr_plaintext.push_back((ip_bytes.size() >> 8) & 0xFF);
    qr_plaintext.push_back(ip_bytes.size() & 0xFF);
    qr_plaintext.insert(qr_plaintext.end(), ip_bytes.begin(), ip_bytes.end());

    // Derive encryption key from HMAC key
    std::vector<uint8_t> enc_key_input;
    enc_key_input.insert(enc_key_input.end(),
        reinterpret_cast<const uint8_t*>("ezone-qr-enc"),
        reinterpret_cast<const uint8_t*>("ezone-qr-enc") + 12);
    enc_key_input.insert(enc_key_input.end(),
        impl_->hmac_key.data(), impl_->hmac_key.data() + impl_->hmac_key.size());
    auto enc_key_hash = impl_->engine.hmac_sha384(enc_key_input, impl_->hmac_key);
    if (!enc_key_hash)
        return Result<QRSession>::failure("failed to derive encryption key");
    SecureBuffer enc_key(enc_key_hash.value.data(), 32);

    // Encrypt QR payload (screenshot-proof)
    // Use ChaCha20-Poly1305 if Libsodium available (faster on mobile), else AES-256-GCM
    std::vector<uint8_t> encrypted;
    if (CryptoEngine::has_libsodium()) {
        auto enc = impl_->engine.encrypt_chacha20poly1305(qr_plaintext, enc_key, {});
        if (!enc)
            return Result<QRSession>::failure("failed to encrypt QR payload (ChaCha20)");
        encrypted = std::move(enc.value);
    } else {
        auto enc = impl_->engine.encrypt_aes256gcm(qr_plaintext, enc_key, {});
        if (!enc)
            return Result<QRSession>::failure("failed to encrypt QR payload (AES-GCM)");
        encrypted = std::move(enc.value);
    }

    // HMAC the ciphertext for integrity (encrypt-then-MAC)
    auto qr_mac = impl_->engine.hmac_sha384(encrypted, impl_->hmac_key);
    if (!qr_mac)
        return Result<QRSession>::failure("failed to sign QR payload");

    // Wire: encrypted_data | hmac(48)
    std::vector<uint8_t> signed_qr;
    signed_qr.reserve(encrypted.size() + qr_mac.value.size());
    signed_qr.insert(signed_qr.end(), encrypted.begin(), encrypted.end());
    signed_qr.insert(signed_qr.end(), qr_mac.value.begin(), qr_mac.value.end());

    std::string qr_data = base64url_encode(signed_qr);

    // Store session
    Impl::Session session;
    session.data.session_id = session_id;
    session.data.qr_data = qr_data;
    session.data.status = QRStatus::Pending;
    session.data.created_at = ts;
    session.data.expires_at = expires;
    session.data.challenge = challenge;
    session.challenge = challenge;
    session.desktop_ip = desktop_ip;

    impl_->sessions_[session_id] = std::move(session);

    QRSession result;
    result.session_id = session_id;
    result.qr_data = qr_data;
    result.status = QRStatus::Pending;
    result.created_at = ts;
    result.expires_at = expires;
    result.challenge = challenge;

    return Result<QRSession>::success(std::move(result));
}


Result<QRStatus> QRAuthServer::poll_qr_status(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(impl_->mu_);

    auto it = impl_->sessions_.find(session_id);
    if (it == impl_->sessions_.end())
        return Result<QRStatus>::failure("session not found");

    if (impl_->is_expired(it->second)) {
        it->second.data.status = QRStatus::Expired;
        return Result<QRStatus>::success(QRStatus::Expired);
    }

    return Result<QRStatus>::success(it->second.data.status);
}


Result<std::pair<std::string, std::string>> QRAuthServer::complete_qr_auth(
    const std::string& session_id)
{
    std::lock_guard<std::mutex> lock(impl_->mu_);

    auto it = impl_->sessions_.find(session_id);
    if (it == impl_->sessions_.end())
        return Result<std::pair<std::string, std::string>>::failure("session not found");

    auto& s = it->second;
    if (impl_->is_expired(s)) {
        s.data.status = QRStatus::Expired;
        return Result<std::pair<std::string, std::string>>::failure("session expired");
    }
    if (s.data.status != QRStatus::Approved)
        return Result<std::pair<std::string, std::string>>::failure(
            "session not yet approved");

    // Return the device that approved (caller issues session token)
    return Result<std::pair<std::string, std::string>>::success(
        {s.device_id, ""});
}


Result<std::string> QRAuthServer::validate_qr(
    const std::string& qr_data, const std::string& mobile_ip)
{
    // Decode the QR payload
    auto signed_qr = base64url_decode(qr_data);
    if (signed_qr.size() < 48 + 28) // min: encrypted(28) + hmac(48) + overhead
        return Result<std::string>::failure("QR code too short");

    // Split ciphertext and HMAC (encrypt-then-MAC)
    size_t mac_start = signed_qr.size() - 48;
    std::vector<uint8_t> ciphertext(signed_qr.begin(), signed_qr.begin() + mac_start);
    std::vector<uint8_t> mac_received(signed_qr.begin() + mac_start, signed_qr.end());

    // Verify HMAC over ciphertext
    auto mac_expected = impl_->engine.hmac_sha384(ciphertext, impl_->hmac_key);
    if (!mac_expected)
        return Result<std::string>::failure("QR verification failed");
    if (!CryptoEngine::constant_time_equal(mac_expected.value, mac_received))
        return Result<std::string>::failure("QR code forged or tampered");

    // Derive decryption key (same as in begin_qr_auth)
    std::vector<uint8_t> enc_key_input;
    enc_key_input.insert(enc_key_input.end(),
        reinterpret_cast<const uint8_t*>("ezone-qr-enc"),
        reinterpret_cast<const uint8_t*>("ezone-qr-enc") + 12);
    enc_key_input.insert(enc_key_input.end(),
        impl_->hmac_key.data(), impl_->hmac_key.data() + impl_->hmac_key.size());
    auto enc_key_hash = impl_->engine.hmac_sha384(enc_key_input, impl_->hmac_key);
    if (!enc_key_hash)
        return Result<std::string>::failure("failed to derive decryption key");
    SecureBuffer enc_key(enc_key_hash.value.data(), 32);

    // Decrypt QR payload (try ChaCha20 first if Libsodium available, else AES-GCM)
    SecureBuffer decrypted;
    if (CryptoEngine::has_libsodium()) {
        auto dec = impl_->engine.decrypt_chacha20poly1305(ciphertext, enc_key, {});
        if (!dec)
            return Result<std::string>::failure("QR code decryption failed (ChaCha20)");
        decrypted = std::move(dec.value);
    } else {
        auto dec = impl_->engine.decrypt_aes256gcm(ciphertext, enc_key, {});
        if (!dec)
            return Result<std::string>::failure("QR code decryption failed (AES-GCM)");
        decrypted = std::move(dec.value);
    }

    std::vector<uint8_t> payload = decrypted.copy_out();

    // Check version
    if (payload.empty() || payload[0] < 0x01)
        return Result<std::string>::failure("unsupported QR version");

    // Parse the decrypted payload
    size_t offset = 1; // skip version byte
    if (offset + 2 > payload.size())
        return Result<std::string>::failure("malformed QR payload");
    uint16_t sid_len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;

    if (offset + sid_len > payload.size())
        return Result<std::string>::failure("malformed QR session ID");
    std::string session_id(payload.begin() + offset, payload.begin() + offset + sid_len);
    offset += sid_len;

    if (offset + 2 > payload.size())
        return Result<std::string>::failure("malformed QR challenge length");
    uint16_t ch_len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;

    if (offset + ch_len > payload.size())
        return Result<std::string>::failure("malformed QR challenge");
    std::string challenge(payload.begin() + offset, payload.begin() + offset + ch_len);
    offset += ch_len;

    if (offset + 8 > payload.size())
        return Result<std::string>::failure("malformed QR expiry");
    uint64_t expires = 0;
    for (int i = 0; i < 8; ++i)
        expires = (expires << 8) | payload[offset + i];
    offset += 8;

    // Check expiry
    if (now_sec() > expires)
        return Result<std::string>::failure("QR code expired");

    // Parse IP binding (version >= 0x02)
    std::string embedded_ip;
    const uint8_t* pd = payload.data();
    if (pd[0] >= 0x02 && offset + 2 <= payload.size()) {
        uint16_t ip_len = (pd[offset] << 8) | pd[offset + 1];
        offset += 2;
        if (offset + ip_len <= payload.size()) {
            embedded_ip.assign(reinterpret_cast<const char*>(pd + offset),
                               reinterpret_cast<const char*>(pd + offset + ip_len));
        }
    }

    // Verify session exists and challenge matches
    std::lock_guard<std::mutex> lock(impl_->mu_);
    auto it = impl_->sessions_.find(session_id);
    if (it == impl_->sessions_.end())
        return Result<std::string>::failure("QR session not found");

    if (it->second.data.challenge != challenge)
        return Result<std::string>::failure("QR challenge mismatch");

    if (impl_->is_expired(it->second))
        return Result<std::string>::failure("QR session expired");

    // IP binding verification — mobile must be on same network as desktop
    if (!embedded_ip.empty() && !mobile_ip.empty()) {
        // Compare first 3 octets (same /24 subnet) for NAT compatibility
        auto get_subnet = [](const std::string& ip) -> std::string {
            auto last_dot = ip.rfind('.');
            if (last_dot == std::string::npos) return ip;
            auto second_last = ip.rfind('.', last_dot - 1);
            if (second_last == std::string::npos) return ip;
            return ip.substr(0, second_last);
        };
        if (get_subnet(embedded_ip) != get_subnet(mobile_ip))
            return Result<std::string>::failure(
                "IP mismatch — mobile device must be on the same network as the desktop");
    }

    // Mark as scanned
    it->second.data.status = QRStatus::Scanned;

    return Result<std::string>::success(challenge);
}


Result<void> QRAuthServer::approve_qr(const QRApproval& approval) {
    if (approval.session_id.empty())
        return Result<void>::failure("session_id required");
    if (approval.signature.empty())
        return Result<void>::failure("signature required");
    if (approval.public_key_der.empty())
        return Result<void>::failure("public_key_der required");

    std::lock_guard<std::mutex> lock(impl_->mu_);

    auto it = impl_->sessions_.find(approval.session_id);
    if (it == impl_->sessions_.end())
        return Result<void>::failure("session not found");

    auto& s = it->second;
    if (impl_->is_expired(s)) {
        s.data.status = QRStatus::Expired;
        return Result<void>::failure("session expired");
    }
    if (s.data.status == QRStatus::Approved)
        return Result<void>::failure("session already approved");
    if (s.data.status == QRStatus::Denied)
        return Result<void>::failure("session was denied");

    // Verify the signature over the challenge using the mobile device's key
    auto ch = base64url_decode(s.data.challenge);
    if (ch.size() != 88)
        return Result<void>::failure("invalid challenge format");

    // Sign the raw challenge bytes (first 40 bytes — nonce + timestamp)
    std::vector<uint8_t> signed_data(ch.begin(), ch.begin() + 40);

    auto ok = impl_->engine.verify(signed_data, approval.signature, approval.public_key_der);
    if (!ok || !ok.value)
        return Result<void>::failure("invalid signature — device not authorized");

    // Mark as approved
    s.data.status = QRStatus::Approved;
    s.approved = true;
    s.device_id = approval.device_id;
    s.public_key_der = approval.public_key_der;
    s.device_label = approval.device_label;

    return Result<void>::success();
}


Result<void> QRAuthServer::deny_qr(const std::string& session_id) {
    if (session_id.empty())
        return Result<void>::failure("session_id required");

    std::lock_guard<std::mutex> lock(impl_->mu_);

    auto it = impl_->sessions_.find(session_id);
    if (it == impl_->sessions_.end())
        return Result<void>::failure("session not found");

    auto& s = it->second;
    if (impl_->is_expired(s)) {
        s.data.status = QRStatus::Expired;
        return Result<void>::failure("session expired");
    }
    if (s.data.status == QRStatus::Approved)
        return Result<void>::failure("session already approved");

    s.data.status = QRStatus::Denied;
    s.denied = true;

    return Result<void>::success();
}

} // namespace ezone
