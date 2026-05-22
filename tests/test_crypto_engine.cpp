#include "ezone/crypto_engine.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

using namespace ezone;

// Minimal test harness — no external dependencies
static int tests_run    = 0;
static int tests_passed = 0;

#define TEST(name) \
    void name(); \
    struct _Reg_##name { _Reg_##name() { \
        std::cout << "  [ RUN ] " #name "\n"; \
        ++tests_run; \
        name(); \
        ++tests_passed; \
        std::cout << "  [ OK  ] " #name "\n"; \
    }} _reg_##name; \
    void name()

#define ASSERT_TRUE(expr)  do { if (!(expr)) { \
    std::cerr << "FAIL: " #expr " at " __FILE__ ":" << __LINE__ << "\n"; \
    std::abort(); } } while(0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a,b)     ASSERT_TRUE((a)==(b))


// ─── Keypair tests ────────────────────────────────────────────────────────────

TEST(test_generate_keypair) {
    CryptoEngine eng;
    auto kp = eng.generate_keypair();
    ASSERT_TRUE(kp.ok);
    ASSERT_FALSE(kp.value.private_key_der.empty());
    ASSERT_FALSE(kp.value.public_key_der.empty());
}

TEST(test_keypair_different_each_call) {
    CryptoEngine eng;
    auto kp1 = eng.generate_keypair();
    auto kp2 = eng.generate_keypair();
    ASSERT_TRUE(kp1.ok && kp2.ok);
    // Public keys must differ
    ASSERT_FALSE(kp1.value.public_key_der == kp2.value.public_key_der);
}

TEST(test_public_key_pem_roundtrip) {
    CryptoEngine eng;
    auto kp  = eng.generate_keypair();
    ASSERT_TRUE(kp.ok);

    auto pem = eng.public_key_to_pem(kp.value.public_key_der);
    ASSERT_TRUE(pem.ok);
    ASSERT_FALSE(pem.value.empty());

    auto der = eng.public_key_from_pem(pem.value);
    ASSERT_TRUE(der.ok);
    ASSERT_EQ(der.value, kp.value.public_key_der);
}


// ─── Sign / Verify tests ──────────────────────────────────────────────────────

TEST(test_sign_and_verify) {
    CryptoEngine eng;
    auto kp = eng.generate_keypair();
    ASSERT_TRUE(kp.ok);

    std::vector<uint8_t> msg = { 'h','e','l','l','o' };
    auto sig = eng.sign(msg, kp.value.private_key_der);
    ASSERT_TRUE(sig.ok);
    ASSERT_FALSE(sig.value.empty());

    auto ok = eng.verify(msg, sig.value, kp.value.public_key_der);
    ASSERT_TRUE(ok.ok);
    ASSERT_TRUE(ok.value);
}

TEST(test_verify_wrong_message_fails) {
    CryptoEngine eng;
    auto kp = eng.generate_keypair();
    ASSERT_TRUE(kp.ok);

    std::vector<uint8_t> msg     = { 'h','e','l','l','o' };
    std::vector<uint8_t> bad_msg = { 'w','o','r','l','d' };

    auto sig = eng.sign(msg, kp.value.private_key_der);
    ASSERT_TRUE(sig.ok);

    auto ok = eng.verify(bad_msg, sig.value, kp.value.public_key_der);
    ASSERT_TRUE(ok.ok);       // not an error — just invalid
    ASSERT_FALSE(ok.value);   // must return false
}

TEST(test_verify_tampered_signature_fails) {
    CryptoEngine eng;
    auto kp = eng.generate_keypair();
    ASSERT_TRUE(kp.ok);

    std::vector<uint8_t> msg = { 't','e','s','t' };
    auto sig = eng.sign(msg, kp.value.private_key_der);
    ASSERT_TRUE(sig.ok);

    // Flip a byte in the middle of the signature
    auto bad_sig = sig.value;
    bad_sig[bad_sig.size() / 2] ^= 0xFF;

    auto ok = eng.verify(msg, bad_sig, kp.value.public_key_der);
    ASSERT_TRUE(ok.ok);
    ASSERT_FALSE(ok.value);
}

TEST(test_verify_wrong_key_fails) {
    CryptoEngine eng;
    auto kp1 = eng.generate_keypair();
    auto kp2 = eng.generate_keypair();
    ASSERT_TRUE(kp1.ok && kp2.ok);

    std::vector<uint8_t> msg = { 'd','a','t','a' };
    auto sig = eng.sign(msg, kp1.value.private_key_der);
    ASSERT_TRUE(sig.ok);

    auto ok = eng.verify(msg, sig.value, kp2.value.public_key_der);
    ASSERT_TRUE(ok.ok);
    ASSERT_FALSE(ok.value);
}


// ─── Hash tests ───────────────────────────────────────────────────────────────

TEST(test_sha384_deterministic) {
    CryptoEngine eng;
    std::vector<uint8_t> data = { 1,2,3,4,5 };
    auto h1 = eng.hash_sha384(data);
    auto h2 = eng.hash_sha384(data);
    ASSERT_TRUE(h1.ok && h2.ok);
    ASSERT_EQ(h1.value.size(), 48u);   // SHA-384 = 48 bytes
    ASSERT_EQ(h1.value, h2.value);
}

TEST(test_sha384_different_inputs_differ) {
    CryptoEngine eng;
    std::vector<uint8_t> a = { 1,2,3 };
    std::vector<uint8_t> b = { 1,2,4 };
    auto ha = eng.hash_sha384(a);
    auto hb = eng.hash_sha384(b);
    ASSERT_TRUE(ha.ok && hb.ok);
    ASSERT_FALSE(ha.value == hb.value);
}

TEST(test_sha512_output_size) {
    CryptoEngine eng;
    std::vector<uint8_t> data = { 0xAB, 0xCD };
    auto h = eng.hash_sha512(data);
    ASSERT_TRUE(h.ok);
    ASSERT_EQ(h.value.size(), 64u);    // SHA-512 = 64 bytes
}

TEST(test_hmac_sha384) {
    CryptoEngine eng;
    SecureBuffer key(32);
    std::memset(key.data(), 0x42, 32);

    std::vector<uint8_t> msg = { 'a','u','t','h' };
    auto mac1 = eng.hmac_sha384(msg, key);
    auto mac2 = eng.hmac_sha384(msg, key);
    ASSERT_TRUE(mac1.ok && mac2.ok);
    ASSERT_EQ(mac1.value.size(), 48u);
    ASSERT_EQ(mac1.value, mac2.value);  // deterministic
}

TEST(test_hmac_different_key_differs) {
    CryptoEngine eng;
    SecureBuffer k1(32), k2(32);
    std::memset(k1.data(), 0x01, 32);
    std::memset(k2.data(), 0x02, 32);

    std::vector<uint8_t> msg = { 'm','s','g' };
    auto mac1 = eng.hmac_sha384(msg, k1);
    auto mac2 = eng.hmac_sha384(msg, k2);
    ASSERT_TRUE(mac1.ok && mac2.ok);
    ASSERT_FALSE(mac1.value == mac2.value);
}


// ─── AES-256-GCM tests ────────────────────────────────────────────────────────

TEST(test_encrypt_decrypt_roundtrip) {
    CryptoEngine eng;
    auto key_result = eng.generate_symmetric_key();
    ASSERT_TRUE(key_result.ok);

    std::vector<uint8_t> plaintext = { 's','e','c','r','e','t' };
    auto bundle = eng.encrypt_aes256gcm(plaintext, key_result.value);
    ASSERT_TRUE(bundle.ok);
    ASSERT_FALSE(bundle.value.empty());

    auto recovered = eng.decrypt_aes256gcm(bundle.value, key_result.value);
    ASSERT_TRUE(recovered.ok);
    ASSERT_EQ(recovered.value.copy_out(), plaintext);
}

TEST(test_encrypt_with_aad) {
    CryptoEngine eng;
    auto key = eng.generate_symmetric_key();
    ASSERT_TRUE(key.ok);

    std::vector<uint8_t> pt  = { 'd','a','t','a' };
    std::vector<uint8_t> aad = { 'u','s','e','r','1' };

    auto bundle = eng.encrypt_aes256gcm(pt, key.value, aad);
    ASSERT_TRUE(bundle.ok);

    // Correct AAD — should decrypt
    auto ok = eng.decrypt_aes256gcm(bundle.value, key.value, aad);
    ASSERT_TRUE(ok.ok);

    // Wrong AAD — tag mismatch, must fail
    std::vector<uint8_t> bad_aad = { 'u','s','e','r','2' };
    auto fail = eng.decrypt_aes256gcm(bundle.value, key.value, bad_aad);
    ASSERT_FALSE(fail.ok);
}

TEST(test_decrypt_tampered_ciphertext_fails) {
    CryptoEngine eng;
    auto key = eng.generate_symmetric_key();
    ASSERT_TRUE(key.ok);

    std::vector<uint8_t> pt = { 1,2,3,4,5,6,7,8 };
    auto bundle = eng.encrypt_aes256gcm(pt, key.value);
    ASSERT_TRUE(bundle.ok);

    // Flip a byte in the ciphertext region (after IV)
    auto tampered = bundle.value;
    tampered[13] ^= 0xFF;

    auto fail = eng.decrypt_aes256gcm(tampered, key.value);
    ASSERT_FALSE(fail.ok);
}

TEST(test_different_iv_each_encryption) {
    CryptoEngine eng;
    auto key = eng.generate_symmetric_key();
    ASSERT_TRUE(key.ok);

    std::vector<uint8_t> pt = { 1,2,3 };
    auto b1 = eng.encrypt_aes256gcm(pt, key.value);
    auto b2 = eng.encrypt_aes256gcm(pt, key.value);
    ASSERT_TRUE(b1.ok && b2.ok);

    // IV is first 12 bytes — must differ
    bool same_iv = std::equal(b1.value.begin(), b1.value.begin()+12,
                              b2.value.begin());
    ASSERT_FALSE(same_iv);
}


// ─── Randomness tests ─────────────────────────────────────────────────────────

TEST(test_random_bytes_length) {
    CryptoEngine eng;
    for (size_t n : {8u, 16u, 32u, 64u}) {
        auto r = eng.random_bytes(n);
        ASSERT_TRUE(r.ok);
        ASSERT_EQ(r.value.size(), n);
    }
}

TEST(test_random_bytes_not_zero) {
    CryptoEngine eng;
    auto r = eng.random_bytes(32);
    ASSERT_TRUE(r.ok);
    // It would be astronomically unlikely for 32 random bytes to all be zero
    bool all_zero = true;
    for (uint8_t b : r.value) if (b) { all_zero = false; break; }
    ASSERT_FALSE(all_zero);
}


// ─── Challenge tests ──────────────────────────────────────────────────────────

TEST(test_challenge_generate_and_verify) {
    CryptoEngine eng;
    SecureBuffer signing_key(32);
    std::memset(signing_key.data(), 0x77, 32);

    auto ch = eng.generate_challenge(signing_key);
    ASSERT_TRUE(ch.ok);
    ASSERT_FALSE(ch.value.nonce.empty());
    ASSERT_FALSE(ch.value.mac.empty());

    auto ok = eng.verify_challenge(ch.value, signing_key);
    ASSERT_TRUE(ok.ok);
    ASSERT_TRUE(ok.value);
}

TEST(test_challenge_wrong_key_fails) {
    CryptoEngine eng;
    SecureBuffer k1(32), k2(32);
    std::memset(k1.data(), 0x01, 32);
    std::memset(k2.data(), 0x02, 32);

    auto ch = eng.generate_challenge(k1);
    ASSERT_TRUE(ch.ok);

    auto ok = eng.verify_challenge(ch.value, k2);
    ASSERT_TRUE(ok.ok);
    ASSERT_FALSE(ok.value);
}

TEST(test_challenge_tampered_nonce_fails) {
    CryptoEngine eng;
    SecureBuffer signing_key(32);
    std::memset(signing_key.data(), 0x55, 32);

    auto ch = eng.generate_challenge(signing_key);
    ASSERT_TRUE(ch.ok);

    // Flip a byte in the nonce
    ch.value.nonce[0] ^= 0xFF;

    auto ok = eng.verify_challenge(ch.value, signing_key);
    ASSERT_TRUE(ok.ok);
    ASSERT_FALSE(ok.value);
}

TEST(test_challenge_serialise_roundtrip) {
    CryptoEngine eng;
    SecureBuffer signing_key(32);
    std::memset(signing_key.data(), 0xAA, 32);

    auto ch = eng.generate_challenge(signing_key);
    ASSERT_TRUE(ch.ok);

    auto wire = eng.serialize_challenge(ch.value);
    ASSERT_TRUE(wire.ok);

    auto ch2 = eng.deserialize_challenge(wire.value);
    ASSERT_TRUE(ch2.ok);

    ASSERT_EQ(ch.value.nonce,     ch2.value.nonce);
    ASSERT_EQ(ch.value.issued_at, ch2.value.issued_at);
    ASSERT_EQ(ch.value.ttl,       ch2.value.ttl);
    ASSERT_EQ(ch.value.mac,       ch2.value.mac);

    // Should still verify after roundtrip
    auto ok = eng.verify_challenge(ch2.value, signing_key);
    ASSERT_TRUE(ok.ok);
    ASSERT_TRUE(ok.value);
}


// ─── Token tests ──────────────────────────────────────────────────────────────

TEST(test_issue_and_verify_token) {
    CryptoEngine eng;
    auto kp = eng.generate_keypair();
    ASSERT_TRUE(kp.ok);

    auto tok = eng.issue_token("user-123", kp.value.private_key_der);
    ASSERT_TRUE(tok.ok);
    ASSERT_FALSE(tok.value.encoded.empty());
    ASSERT_EQ(tok.value.user_id, "user-123");

    auto decoded = eng.verify_token(tok.value.encoded, kp.value.public_key_der);
    ASSERT_TRUE(decoded.ok);
    ASSERT_EQ(decoded.value.user_id, "user-123");
}

TEST(test_token_wrong_key_fails) {
    CryptoEngine eng;
    auto kp1 = eng.generate_keypair();
    auto kp2 = eng.generate_keypair();
    ASSERT_TRUE(kp1.ok && kp2.ok);

    auto tok = eng.issue_token("alice", kp1.value.private_key_der);
    ASSERT_TRUE(tok.ok);

    auto bad = eng.verify_token(tok.value.encoded, kp2.value.public_key_der);
    ASSERT_FALSE(bad.ok);
}

TEST(test_token_tampered_payload_fails) {
    CryptoEngine eng;
    auto kp = eng.generate_keypair();
    ASSERT_TRUE(kp.ok);

    auto tok = eng.issue_token("victim", kp.value.private_key_der);
    ASSERT_TRUE(tok.ok);

    // Replace the payload segment with an attacker-crafted one
    std::string tampered = tok.value.encoded;
    size_t dot1 = tampered.find('.');
    size_t dot2 = tampered.find('.', dot1 + 1);
    std::string fake_payload = CryptoEngine::base64url_encode(
        std::vector<uint8_t>({'{',' ','"','s','u','b','"',':',' ','"','a','d','m','i','n','"','}'})
    );
    tampered = tampered.substr(0, dot1+1) + fake_payload
             + tampered.substr(dot2);

    auto bad = eng.verify_token(tampered, kp.value.public_key_der);
    ASSERT_FALSE(bad.ok);
}


// ─── Constant-time equal ──────────────────────────────────────────────────────

TEST(test_constant_time_equal) {
    std::vector<uint8_t> a = {1,2,3,4};
    std::vector<uint8_t> b = {1,2,3,4};
    std::vector<uint8_t> c = {1,2,3,5};
    std::vector<uint8_t> d = {1,2,3};

    ASSERT_TRUE (CryptoEngine::constant_time_equal(a, b));
    ASSERT_FALSE(CryptoEngine::constant_time_equal(a, c));
    ASSERT_FALSE(CryptoEngine::constant_time_equal(a, d));
}


// ─── Base64url ────────────────────────────────────────────────────────────────

TEST(test_base64url_roundtrip) {
    for (auto& s : std::vector<std::string>{"", "a", "ab", "abc", "abcd"}) {
        std::vector<uint8_t> in(s.begin(), s.end());
        auto enc = CryptoEngine::base64url_encode(in);
        auto dec = CryptoEngine::base64url_decode(enc);
        ASSERT_TRUE(dec.ok);
        ASSERT_EQ(dec.value, in);
    }
}

TEST(test_base64url_no_padding) {
    std::vector<uint8_t> data = {0xFF, 0xFE};
    auto enc = CryptoEngine::base64url_encode(data);
    // base64url must not contain '+', '/', or '='
    ASSERT_EQ(enc.find('+'), std::string::npos);
    ASSERT_EQ(enc.find('/'), std::string::npos);
    ASSERT_EQ(enc.find('='), std::string::npos);
}


// ─── Runner ───────────────────────────────────────────────────────────────────

int main() {
    std::cout << "\n=== ezone crypto engine tests ===\n\n";
    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed.\n";
    return (tests_passed == tests_run) ? 0 : 1;
}
