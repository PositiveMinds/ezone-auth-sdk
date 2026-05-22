#include "ezone/crypto_engine.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <array>
#include <cassert>
#include <chrono>
#include <cstring>
#include <sstream>

namespace ezone {

// ─── Helpers ─────────────────────────────────────────────────────────────────

namespace {

// Drain and return the latest OpenSSL error string
std::string openssl_last_error() {
    char buf[256];
    unsigned long code = ERR_get_error();
    if (code == 0) return "unknown OpenSSL error";
    ERR_error_string_n(code, buf, sizeof(buf));
    ERR_clear_error();
    return std::string(buf);
}

// Clear the OpenSSL error queue without returning it
void clear_openssl_errors() {
    ERR_clear_error();
}

uint64_t unix_now() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count()
    );
}

// Write uint64 big-endian into dest[0..7]
void write_u64_be(uint8_t* dest, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        dest[i] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }
}

// Write uint32 big-endian into dest[0..3]
void write_u32_be(uint8_t* dest, uint32_t v) {
    dest[0] = (v >> 24) & 0xFF;
    dest[1] = (v >> 16) & 0xFF;
    dest[2] = (v >>  8) & 0xFF;
    dest[3] = (v >>  0) & 0xFF;
}

uint64_t read_u64_be(const uint8_t* src) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | src[i];
    return v;
}

uint32_t read_u32_be(const uint8_t* src) {
    return (static_cast<uint32_t>(src[0]) << 24)
         | (static_cast<uint32_t>(src[1]) << 16)
         | (static_cast<uint32_t>(src[2]) <<  8)
         | (static_cast<uint32_t>(src[3]));
}

// RAII wrapper for EVP_PKEY
struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) { EVP_PKEY_free(p); } };
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) { EVP_PKEY_CTX_free(p); } };
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

struct EvpMdCtxDeleter { void operator()(EVP_MD_CTX* p) { EVP_MD_CTX_free(p); } };
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

struct EvpCipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) { EVP_CIPHER_CTX_free(p); } };
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

struct BioDeleter { void operator()(BIO* b) { BIO_free_all(b); } };
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

// Decode DER bytes into an EVP_PKEY (auto-detects public / private)
EvpPkeyPtr der_to_evp_public(const std::vector<uint8_t>& der) {
    const uint8_t* p = der.data();
    EVP_PKEY* key = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
    return EvpPkeyPtr(key);
}

EvpPkeyPtr der_to_evp_private(const SecureBuffer& der) {
    const uint8_t* p = der.data();
    EVP_PKEY* key = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p,
                                    static_cast<long>(der.size()));
    return EvpPkeyPtr(key);
}

// base64url alphabet (RFC 4648 §5)
static const char B64URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

} // anonymous namespace


// ─── Impl (private state) ─────────────────────────────────────────────────────

struct CryptoEngine::Impl {
    CryptoConfig cfg;
};


// ─── Construction ─────────────────────────────────────────────────────────────

CryptoEngine::CryptoEngine(const CryptoConfig& cfg)
    : impl_(std::make_unique<Impl>()) {
    impl_->cfg = cfg;

    if (cfg.require_fips && !is_fips_mode()) {
        throw std::runtime_error(
            "ezone: FIPS mode required but OpenSSL is not in FIPS mode"
        );
    }
}

CryptoEngine::~CryptoEngine() = default;


// ─── crypto_error_string ──────────────────────────────────────────────────────

const char* crypto_error_string(CryptoError err) noexcept {
    switch (err) {
        case CryptoError::Ok:               return "ok";
        case CryptoError::InvalidKey:       return "invalid key";
        case CryptoError::InvalidSignature: return "invalid signature";
        case CryptoError::InvalidChallenge: return "invalid challenge";
        case CryptoError::ChallengeExpired: return "challenge expired";
        case CryptoError::EncryptionFailed: return "encryption failed";
        case CryptoError::DecryptionFailed: return "decryption failed (tampered?)";
        case CryptoError::InvalidInput:     return "invalid input";
        case CryptoError::InternalError:    return "internal crypto error";
    }
    return "unknown";
}


// ─── Key operations ───────────────────────────────────────────────────────────

Result<KeyPair> CryptoEngine::generate_keypair() const {
    clear_openssl_errors();

    // Create P-384 key generation context
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx)
        return Result<KeyPair>::failure("EVP_PKEY_CTX_new_from_name: " + openssl_last_error());

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
        return Result<KeyPair>::failure("EVP_PKEY_keygen_init: " + openssl_last_error());

    // Set curve to P-384 (NIST / NSA Suite B)
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_secp384r1) <= 0)
        return Result<KeyPair>::failure("set curve P-384: " + openssl_last_error());

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0)
        return Result<KeyPair>::failure("EVP_PKEY_keygen: " + openssl_last_error());
    EvpPkeyPtr pkey(raw);

    // Encode private key as PKCS#8 DER
    uint8_t* priv_buf = nullptr;
    int priv_len = i2d_PrivateKey(pkey.get(), &priv_buf);
    if (priv_len <= 0)
        return Result<KeyPair>::failure("i2d_PrivateKey: " + openssl_last_error());

    SecureBuffer priv_der(priv_buf, static_cast<size_t>(priv_len));
    OPENSSL_free(priv_buf);

    // Encode public key as SubjectPublicKeyInfo DER
    uint8_t* pub_buf = nullptr;
    int pub_len = i2d_PUBKEY(pkey.get(), &pub_buf);
    if (pub_len <= 0)
        return Result<KeyPair>::failure("i2d_PUBKEY: " + openssl_last_error());

    std::vector<uint8_t> pub_der(pub_buf, pub_buf + pub_len);
    OPENSSL_free(pub_buf);

    KeyPair kp;
    kp.private_key_der = std::move(priv_der);
    kp.public_key_der  = std::move(pub_der);

    return Result<KeyPair>::success(std::move(kp));
}

Result<std::string> CryptoEngine::public_key_to_pem(
    const std::vector<uint8_t>& der) const
{
    clear_openssl_errors();
    EvpPkeyPtr pkey = der_to_evp_public(der);
    if (!pkey)
        return Result<std::string>::failure("invalid public key DER: " + openssl_last_error());

    BioPtr bio(BIO_new(BIO_s_mem()));
    if (PEM_write_bio_PUBKEY(bio.get(), pkey.get()) != 1)
        return Result<std::string>::failure("PEM_write_bio_PUBKEY: " + openssl_last_error());

    char* pem_data = nullptr;
    long pem_len   = BIO_get_mem_data(bio.get(), &pem_data);
    return Result<std::string>::success(std::string(pem_data, static_cast<size_t>(pem_len)));
}

Result<std::vector<uint8_t>> CryptoEngine::public_key_from_pem(
    const std::string& pem) const
{
    clear_openssl_errors();
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    EVP_PKEY* raw = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!raw)
        return Result<std::vector<uint8_t>>::failure(
            "PEM_read_bio_PUBKEY: " + openssl_last_error());
    EvpPkeyPtr pkey(raw);

    uint8_t* buf = nullptr;
    int len = i2d_PUBKEY(pkey.get(), &buf);
    if (len <= 0)
        return Result<std::vector<uint8_t>>::failure(
            "i2d_PUBKEY: " + openssl_last_error());

    std::vector<uint8_t> der(buf, buf + len);
    OPENSSL_free(buf);
    return Result<std::vector<uint8_t>>::success(std::move(der));
}


// ─── Signing ──────────────────────────────────────────────────────────────────

Result<std::vector<uint8_t>> CryptoEngine::sign(
    const std::vector<uint8_t>& data,
    const SecureBuffer&         private_key_der) const
{
    clear_openssl_errors();

    EvpPkeyPtr pkey = der_to_evp_private(private_key_der);
    if (!pkey)
        return Result<std::vector<uint8_t>>::failure(
            "invalid private key: " + openssl_last_error());

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha384(), nullptr, pkey.get()) != 1)
        return Result<std::vector<uint8_t>>::failure(
            "DigestSignInit: " + openssl_last_error());

    if (EVP_DigestSignUpdate(ctx.get(), data.data(), data.size()) != 1)
        return Result<std::vector<uint8_t>>::failure(
            "DigestSignUpdate: " + openssl_last_error());

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len) != 1)
        return Result<std::vector<uint8_t>>::failure(
            "DigestSignFinal (size): " + openssl_last_error());

    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSignFinal(ctx.get(), sig.data(), &sig_len) != 1)
        return Result<std::vector<uint8_t>>::failure(
            "DigestSignFinal: " + openssl_last_error());

    sig.resize(sig_len);
    return Result<std::vector<uint8_t>>::success(std::move(sig));
}

Result<bool> CryptoEngine::verify(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& signature_der,
    const std::vector<uint8_t>& public_key_der) const
{
    clear_openssl_errors();

    EvpPkeyPtr pkey = der_to_evp_public(public_key_der);
    if (!pkey)
        return Result<bool>::failure("invalid public key: " + openssl_last_error());

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha384(), nullptr, pkey.get()) != 1)
        return Result<bool>::failure("DigestVerifyInit: " + openssl_last_error());

    if (EVP_DigestVerifyUpdate(ctx.get(), data.data(), data.size()) != 1)
        return Result<bool>::failure("DigestVerifyUpdate: " + openssl_last_error());

    int rc = EVP_DigestVerifyFinal(
        ctx.get(), signature_der.data(), signature_der.size());

    clear_openssl_errors();

    if (rc == 1)  return Result<bool>::success(true);
    if (rc == 0)  return Result<bool>::success(false);  // invalid sig — not an error
    return Result<bool>::failure("DigestVerifyFinal: internal error");
}


// ─── Hashing ──────────────────────────────────────────────────────────────────

Result<std::vector<uint8_t>> CryptoEngine::hash_sha384(
    const std::vector<uint8_t>& data) const
{
    clear_openssl_errors();
    std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
    unsigned int len = 0;

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha384(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), out.data(), &len) != 1)
    {
        return Result<std::vector<uint8_t>>::failure(
            "SHA-384: " + openssl_last_error());
    }
    out.resize(len);
    return Result<std::vector<uint8_t>>::success(std::move(out));
}

Result<std::vector<uint8_t>> CryptoEngine::hash_sha512(
    const std::vector<uint8_t>& data) const
{
    clear_openssl_errors();
    std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
    unsigned int len = 0;

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), out.data(), &len) != 1)
    {
        return Result<std::vector<uint8_t>>::failure(
            "SHA-512: " + openssl_last_error());
    }
    out.resize(len);
    return Result<std::vector<uint8_t>>::success(std::move(out));
}

Result<std::vector<uint8_t>> CryptoEngine::hmac_sha384(
    const std::vector<uint8_t>& data,
    const SecureBuffer&         key) const
{
    clear_openssl_errors();

    std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
    unsigned int len = 0;

    uint8_t* result = HMAC(
        EVP_sha384(),
        key.data(), static_cast<int>(key.size()),
        data.data(), data.size(),
        out.data(), &len
    );

    if (!result)
        return Result<std::vector<uint8_t>>::failure(
            "HMAC-SHA384: " + openssl_last_error());

    out.resize(len);
    return Result<std::vector<uint8_t>>::success(std::move(out));
}


// ─── Symmetric encryption ─────────────────────────────────────────────────────

static constexpr size_t AES_GCM_IV_LEN  = 12;  // 96-bit IV (NIST recommended)
static constexpr size_t AES_GCM_TAG_LEN = 16;  // 128-bit authentication tag
static constexpr size_t AES_256_KEY_LEN = 32;  // 256-bit key

Result<std::vector<uint8_t>> CryptoEngine::encrypt_aes256gcm(
    const std::vector<uint8_t>& plaintext,
    const SecureBuffer&         key,
    const std::vector<uint8_t>& aad) const
{
    clear_openssl_errors();

    if (key.size() != AES_256_KEY_LEN)
        return Result<std::vector<uint8_t>>::failure(
            "AES-256 key must be exactly 32 bytes");

    // Generate random IV
    std::vector<uint8_t> iv(AES_GCM_IV_LEN);
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1)
        return Result<std::vector<uint8_t>>::failure(
            "RAND_bytes (IV): " + openssl_last_error());

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return Result<std::vector<uint8_t>>::failure(
            "EncryptInit (cipher): " + openssl_last_error());

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(AES_GCM_IV_LEN), nullptr) != 1)
        return Result<std::vector<uint8_t>>::failure("set IV len: " + openssl_last_error());

    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1)
        return Result<std::vector<uint8_t>>::failure(
            "EncryptInit (key/iv): " + openssl_last_error());

    // Authenticate additional data without encrypting it
    if (!aad.empty()) {
        int aad_len = 0;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &aad_len,
                              aad.data(), static_cast<int>(aad.size())) != 1)
            return Result<std::vector<uint8_t>>::failure(
                "EncryptUpdate (aad): " + openssl_last_error());
    }

    // Encrypt plaintext
    std::vector<uint8_t> ciphertext(plaintext.size() + AES_GCM_TAG_LEN);
    int out_len = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len,
                              plaintext.data(), static_cast<int>(plaintext.size())) != 1)
            return Result<std::vector<uint8_t>>::failure(
                "EncryptUpdate: " + openssl_last_error());
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + out_len, &final_len) != 1)
        return Result<std::vector<uint8_t>>::failure(
            "EncryptFinal: " + openssl_last_error());

    ciphertext.resize(static_cast<size_t>(out_len + final_len));

    // Extract GCM authentication tag
    std::vector<uint8_t> tag(AES_GCM_TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                             static_cast<int>(AES_GCM_TAG_LEN), tag.data()) != 1)
        return Result<std::vector<uint8_t>>::failure(
            "get GCM tag: " + openssl_last_error());

    // Output: IV | ciphertext | tag
    std::vector<uint8_t> bundle;
    bundle.reserve(AES_GCM_IV_LEN + ciphertext.size() + AES_GCM_TAG_LEN);
    bundle.insert(bundle.end(), iv.begin(), iv.end());
    bundle.insert(bundle.end(), ciphertext.begin(), ciphertext.end());
    bundle.insert(bundle.end(), tag.begin(), tag.end());

    return Result<std::vector<uint8_t>>::success(std::move(bundle));
}

Result<SecureBuffer> CryptoEngine::decrypt_aes256gcm(
    const std::vector<uint8_t>& bundle,
    const SecureBuffer&         key,
    const std::vector<uint8_t>& aad) const
{
    clear_openssl_errors();

    const size_t min_len = AES_GCM_IV_LEN + AES_GCM_TAG_LEN;
    if (bundle.size() < min_len)
        return Result<SecureBuffer>::failure("ciphertext bundle too short");

    if (key.size() != AES_256_KEY_LEN)
        return Result<SecureBuffer>::failure("AES-256 key must be exactly 32 bytes");

    const uint8_t* iv         = bundle.data();
    const uint8_t* ciphertext = bundle.data() + AES_GCM_IV_LEN;
    size_t         ct_len     = bundle.size() - AES_GCM_IV_LEN - AES_GCM_TAG_LEN;
    const uint8_t* tag        = bundle.data() + AES_GCM_IV_LEN + ct_len;

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return Result<SecureBuffer>::failure(
            "DecryptInit (cipher): " + openssl_last_error());

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(AES_GCM_IV_LEN), nullptr) != 1)
        return Result<SecureBuffer>::failure("set IV len: " + openssl_last_error());

    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv) != 1)
        return Result<SecureBuffer>::failure(
            "DecryptInit (key/iv): " + openssl_last_error());

    if (!aad.empty()) {
        int aad_out = 0;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &aad_out,
                              aad.data(), static_cast<int>(aad.size())) != 1)
            return Result<SecureBuffer>::failure(
                "DecryptUpdate (aad): " + openssl_last_error());
    }

    SecureBuffer plaintext(ct_len);
    int out_len = 0;
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len,
                              ciphertext, static_cast<int>(ct_len)) != 1)
            return Result<SecureBuffer>::failure(
                "DecryptUpdate: " + openssl_last_error());
    }

    // Set expected tag before finalising
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                             static_cast<int>(AES_GCM_TAG_LEN),
                             const_cast<uint8_t*>(tag)) != 1)
        return Result<SecureBuffer>::failure("set GCM tag: " + openssl_last_error());

    int final_len = 0;
    int rc = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len, &final_len);
    clear_openssl_errors();

    if (rc <= 0)
        return Result<SecureBuffer>::failure(
            crypto_error_string(CryptoError::DecryptionFailed));

    plaintext.resize(static_cast<size_t>(out_len + final_len));
    return Result<SecureBuffer>::success(std::move(plaintext));
}


// ─── Randomness ───────────────────────────────────────────────────────────────

Result<std::vector<uint8_t>> CryptoEngine::random_bytes(size_t count) const {
    std::vector<uint8_t> out(count);
    if (RAND_bytes(out.data(), static_cast<int>(count)) != 1)
        return Result<std::vector<uint8_t>>::failure(
            "RAND_bytes: " + openssl_last_error());
    return Result<std::vector<uint8_t>>::success(std::move(out));
}

Result<SecureBuffer> CryptoEngine::generate_symmetric_key() const {
    SecureBuffer key(AES_256_KEY_LEN);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1)
        return Result<SecureBuffer>::failure(
            "RAND_bytes (key): " + openssl_last_error());
    return Result<SecureBuffer>::success(std::move(key));
}


// ─── Challenge / Response ─────────────────────────────────────────────────────

// MAC input: nonce (32 B) | issued_at (8 B BE) | ttl (4 B BE)
static std::vector<uint8_t> challenge_mac_input(const Challenge& ch) {
    std::vector<uint8_t> buf;
    buf.reserve(ch.nonce.size() + 8 + 4);
    buf.insert(buf.end(), ch.nonce.begin(), ch.nonce.end());

    uint8_t ts[8], ttl[4];
    write_u64_be(ts, ch.issued_at);
    write_u32_be(ttl, ch.ttl);
    buf.insert(buf.end(), ts, ts + 8);
    buf.insert(buf.end(), ttl, ttl + 4);
    return buf;
}

Result<Challenge> CryptoEngine::generate_challenge(
    const SecureBuffer& signing_key) const
{
    auto nonce_result = random_bytes(impl_->cfg.challenge_nonce_bytes);
    if (!nonce_result) return Result<Challenge>::failure(nonce_result.error);

    Challenge ch;
    ch.nonce     = std::move(nonce_result.value);
    ch.issued_at = unix_now();
    ch.ttl       = impl_->cfg.challenge_ttl_seconds;

    auto mac_input = challenge_mac_input(ch);
    auto mac = hmac_sha384(mac_input, signing_key);
    if (!mac) return Result<Challenge>::failure(mac.error);

    ch.mac = std::move(mac.value);
    return Result<Challenge>::success(std::move(ch));
}

Result<bool> CryptoEngine::verify_challenge(
    const Challenge&    challenge,
    const SecureBuffer& signing_key) const
{
    // Time check first
    uint64_t now = unix_now();
    if (now < challenge.issued_at ||
        (now - challenge.issued_at) > challenge.ttl)
        return Result<bool>::success(false);  // expired — not an error

    // Recompute MAC
    auto mac_input    = challenge_mac_input(challenge);
    auto expected_mac = hmac_sha384(mac_input, signing_key);
    if (!expected_mac) return Result<bool>::failure(expected_mac.error);

    bool valid = constant_time_equal(expected_mac.value, challenge.mac);
    return Result<bool>::success(valid);
}

Result<std::vector<uint8_t>> CryptoEngine::serialize_challenge(
    const Challenge& ch) const
{
    // Layout: nonce_len(2B BE) | nonce | issued_at(8B) | ttl(4B) | mac
    uint16_t nl = static_cast<uint16_t>(ch.nonce.size());
    std::vector<uint8_t> out;
    out.reserve(2 + nl + 8 + 4 + ch.mac.size());

    out.push_back((nl >> 8) & 0xFF);
    out.push_back(nl & 0xFF);
    out.insert(out.end(), ch.nonce.begin(), ch.nonce.end());

    uint8_t ts[8], ttl[4];
    write_u64_be(ts, ch.issued_at);
    write_u32_be(ttl, ch.ttl);
    out.insert(out.end(), ts, ts + 8);
    out.insert(out.end(), ttl, ttl + 4);
    out.insert(out.end(), ch.mac.begin(), ch.mac.end());

    return Result<std::vector<uint8_t>>::success(std::move(out));
}

Result<Challenge> CryptoEngine::deserialize_challenge(
    const std::vector<uint8_t>& data) const
{
    if (data.size() < 2 + 8 + 4 + 1)
        return Result<Challenge>::failure("challenge data too short");

    size_t offset = 0;
    uint16_t nl = (static_cast<uint16_t>(data[0]) << 8) | data[1];
    offset += 2;

    if (data.size() < offset + nl + 8 + 4)
        return Result<Challenge>::failure("challenge data truncated");

    Challenge ch;
    ch.nonce.assign(data.begin() + offset, data.begin() + offset + nl);
    offset += nl;

    ch.issued_at = read_u64_be(data.data() + offset); offset += 8;
    ch.ttl       = read_u32_be(data.data() + offset); offset += 4;

    ch.mac.assign(data.begin() + offset, data.end());
    if (ch.mac.empty())
        return Result<Challenge>::failure("challenge missing MAC");

    return Result<Challenge>::success(std::move(ch));
}


// ─── Token ────────────────────────────────────────────────────────────────────

Result<AuthToken> CryptoEngine::issue_token(
    const std::string&  user_id,
    const SecureBuffer& private_key_der) const
{
    uint64_t now     = unix_now();
    uint64_t expires = now + impl_->cfg.token_ttl_seconds;

    // Minimal header.payload (not full JWT — no base64 padding, '.' separated)
    std::string header  = R"({"alg":"ES384","typ":"AT"})";
    std::ostringstream payload_ss;
    payload_ss << R"({"sub":")" << user_id
               << R"(","iat":)"  << now
               << R"(,"exp":)"   << expires
               << "}";
    std::string payload = payload_ss.str();

    std::string h_enc = base64url_encode(
        std::vector<uint8_t>(header.begin(), header.end()));
    std::string p_enc = base64url_encode(
        std::vector<uint8_t>(payload.begin(), payload.end()));

    std::string signing_input = h_enc + "." + p_enc;
    std::vector<uint8_t> si_bytes(signing_input.begin(), signing_input.end());

    auto sig = sign(si_bytes, private_key_der);
    if (!sig) return Result<AuthToken>::failure(sig.error);

    AuthToken tok;
    tok.user_id    = user_id;
    tok.issued_at  = now;
    tok.expires_at = expires;
    tok.encoded    = signing_input + "." + base64url_encode(sig.value);

    return Result<AuthToken>::success(std::move(tok));
}

Result<AuthToken> CryptoEngine::verify_token(
    const std::string&          encoded,
    const std::vector<uint8_t>& public_key_der) const
{
    // Split header.payload.signature
    size_t dot1 = encoded.find('.');
    size_t dot2 = encoded.find('.', dot1 + 1);
    if (dot1 == std::string::npos || dot2 == std::string::npos)
        return Result<AuthToken>::failure("malformed token");

    std::string signing_input = encoded.substr(0, dot2);
    std::string sig_enc       = encoded.substr(dot2 + 1);

    auto sig = base64url_decode(sig_enc);
    if (!sig) return Result<AuthToken>::failure("bad signature encoding");

    std::vector<uint8_t> si_bytes(signing_input.begin(), signing_input.end());
    auto ok = verify(si_bytes, sig.value, public_key_der);
    if (!ok)  return Result<AuthToken>::failure(ok.error);
    if (!ok.value) return Result<AuthToken>::failure("token signature invalid");

    // Decode payload (we only need sub/iat/exp — simple manual parse)
    auto payload_bytes = base64url_decode(
        encoded.substr(dot1 + 1, dot2 - dot1 - 1));
    if (!payload_bytes)
        return Result<AuthToken>::failure("bad payload encoding");

    std::string payload(payload_bytes.value.begin(), payload_bytes.value.end());

    // Extract "sub"
    auto extract = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\":";
        size_t pos = payload.find(search);
        if (pos == std::string::npos) return {};
        pos += search.size();
        bool is_str = payload[pos] == '"';
        if (is_str) ++pos;
        size_t end = payload.find(is_str ? '"' : ',', pos);
        if (end == std::string::npos) end = payload.rfind('}');
        return payload.substr(pos, end - pos);
    };

    AuthToken tok;
    tok.user_id    = extract("sub");
    tok.issued_at  = static_cast<uint64_t>(std::stoull(extract("iat")));
    tok.expires_at = static_cast<uint64_t>(std::stoull(extract("exp")));
    tok.encoded    = encoded;

    if (unix_now() > tok.expires_at)
        return Result<AuthToken>::failure("token expired");

    return Result<AuthToken>::success(std::move(tok));
}


// ─── Utilities ────────────────────────────────────────────────────────────────

bool CryptoEngine::constant_time_equal(
    const std::vector<uint8_t>& a,
    const std::vector<uint8_t>& b) noexcept
{
    if (a.size() != b.size()) {
        // Still consume time proportional to a.size() to avoid length oracle
        volatile uint8_t dummy = 0;
        for (size_t i = 0; i < a.size(); ++i) dummy |= a[i];
        (void)dummy;
        return false;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string CryptoEngine::base64url_encode(const std::vector<uint8_t>& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    for (; i + 2 < data.size(); i += 3) {
        uint32_t v = (data[i] << 16) | (data[i+1] << 8) | data[i+2];
        out += B64URL_CHARS[(v >> 18) & 0x3F];
        out += B64URL_CHARS[(v >> 12) & 0x3F];
        out += B64URL_CHARS[(v >>  6) & 0x3F];
        out += B64URL_CHARS[(v >>  0) & 0x3F];
    }
    if (i + 1 == data.size()) {
        uint32_t v = data[i] << 16;
        out += B64URL_CHARS[(v >> 18) & 0x3F];
        out += B64URL_CHARS[(v >> 12) & 0x3F];
        // no padding in base64url
    } else if (i + 2 == data.size()) {
        uint32_t v = (data[i] << 16) | (data[i+1] << 8);
        out += B64URL_CHARS[(v >> 18) & 0x3F];
        out += B64URL_CHARS[(v >> 12) & 0x3F];
        out += B64URL_CHARS[(v >>  6) & 0x3F];
    }
    return out;
}

Result<std::vector<uint8_t>> CryptoEngine::base64url_decode(
    const std::string& encoded)
{
    // Build decode table
    static const int8_t tbl[256] = []() {
        int8_t t[256];
        std::memset(t, -1, sizeof(t));
        for (int i = 0; i < 64; ++i)
            t[static_cast<uint8_t>(B64URL_CHARS[i])] = static_cast<int8_t>(i);
        return std::array<int8_t,256>(reinterpret_cast<int8_t(&)[256]>(t));
    }().data();  // initialised once

    std::vector<uint8_t> out;
    out.reserve((encoded.size() * 3) / 4 + 1);

    uint32_t acc = 0;
    int      bits = 0;
    for (char c : encoded) {
        int v = tbl[static_cast<uint8_t>(c)];
        if (v < 0 && c != '=')
            return Result<std::vector<uint8_t>>::failure("invalid base64url character");
        if (c == '=') break;
        acc  = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return Result<std::vector<uint8_t>>::success(std::move(out));
}

bool CryptoEngine::is_fips_mode() noexcept {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return EVP_default_properties_is_fips_enabled(nullptr) == 1;
#else
    return FIPS_mode() != 0;
#endif
}

} // namespace ezone
