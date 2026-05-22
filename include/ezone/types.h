#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// Forward declare so types.h has no OpenSSL dependency
extern "C" void OPENSSL_cleanse(void*, size_t);

namespace ezone {

// ─── SecureBuffer ────────────────────────────────────────────────────────────
// Heap buffer that zeroes its memory on destruction.
// Non-copyable to prevent accidental key duplication.
class SecureBuffer {
public:
    SecureBuffer() = default;

    explicit SecureBuffer(size_t size) : data_(size, 0) {}

    SecureBuffer(const uint8_t* data, size_t size)
        : data_(data, data + size) {}

    ~SecureBuffer() {
        wipe();
    }

    SecureBuffer(const SecureBuffer&)            = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& o) noexcept : data_(std::move(o.data_)) {}

    SecureBuffer& operator=(SecureBuffer&& o) noexcept {
        if (this != &o) {
            wipe();
            data_ = std::move(o.data_);
        }
        return *this;
    }

    uint8_t*       data()       { return data_.data(); }
    const uint8_t* data() const { return data_.data(); }
    size_t         size() const { return data_.size(); }
    bool           empty() const { return data_.empty(); }

    void resize(size_t n) { data_.resize(n, 0); }

    // Safe copy-out when you explicitly need the bytes elsewhere
    std::vector<uint8_t> copy_out() const { return data_; }

private:
    void wipe() {
        if (!data_.empty())
            OPENSSL_cleanse(data_.data(), data_.size());
    }

    std::vector<uint8_t> data_;
};


// ─── Result<T> ───────────────────────────────────────────────────────────────
// Lightweight error-or-value type. No exceptions cross the API boundary.
template<typename T>
struct Result {
    T           value;
    std::string error;
    bool        ok;

    static Result success(T v)           { return { std::move(v), {}, true  }; }
    static Result failure(std::string e) { return { T{},  std::move(e), false }; }

    explicit operator bool() const { return ok; }
};

template<>
struct Result<void> {
    std::string error;
    bool        ok;

    static Result success()              { return { {},            true  }; }
    static Result failure(std::string e) { return { std::move(e), false }; }

    explicit operator bool() const { return ok; }
};


// ─── Key types ───────────────────────────────────────────────────────────────

struct KeyPair {
    SecureBuffer         private_key_der;  // PKCS#8 DER — never transmitted
    std::vector<uint8_t> public_key_der;   // SubjectPublicKeyInfo DER
};


// ─── Challenge ───────────────────────────────────────────────────────────────

struct Challenge {
    std::vector<uint8_t> nonce;      // 32 CSPRNG bytes
    uint64_t             issued_at;  // Unix epoch seconds
    uint32_t             ttl;        // Seconds until expiry
    std::vector<uint8_t> mac;        // HMAC-SHA384 over nonce‖issued_at‖ttl
};


// ─── Credential (public data only — stored by the application) ───────────────

struct Credential {
    std::string          user_id;
    std::vector<uint8_t> public_key_der;
    uint64_t             created_at;
    uint64_t             expires_at;  // 0 = never
};


// ─── Token ───────────────────────────────────────────────────────────────────

struct AuthToken {
    std::string user_id;
    uint64_t    issued_at;
    uint64_t    expires_at;
    std::string encoded;   // base64url(header).base64url(payload).base64url(sig)
};


// ─── Error codes ─────────────────────────────────────────────────────────────

enum class CryptoError {
    Ok = 0,
    InvalidKey,
    InvalidSignature,
    InvalidChallenge,
    ChallengeExpired,
    EncryptionFailed,
    DecryptionFailed,
    InvalidInput,
    InternalError,
};

const char* crypto_error_string(CryptoError err) noexcept;

} // namespace ezone
