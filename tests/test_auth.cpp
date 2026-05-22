#include "ezone/auth.h"
#include "ezone/crypto_engine.h"
#include <cassert>
#include <iostream>

using namespace ezone;

// ─── Minimal test harness ─────────────────────────────────────────────────────

static int tests_run = 0, tests_passed = 0;

#define TEST(name) \
    void name(); \
    struct _R_##name { _R_##name() { \
        std::cout << "  [ RUN ] " #name "\n"; \
        ++tests_run; name(); ++tests_passed; \
        std::cout << "  [ OK  ] " #name "\n"; \
    }} _r_##name; \
    void name()

#define ASSERT_TRUE(e)  do { if(!(e)) { \
    std::cerr<<"FAIL: "#e" at line "<<__LINE__<<"\n"; std::abort(); } } while(0)
#define ASSERT_FALSE(e) ASSERT_TRUE(!(e))
#define ASSERT_EQ(a,b)  ASSERT_TRUE((a)==(b))
#define ASSERT_OK(r)    ASSERT_TRUE((r).ok)
#define ASSERT_ERR(r)   ASSERT_TRUE(!(r).ok)


// ─── Fixtures ─────────────────────────────────────────────────────────────────

// Simulates a client device: holds a P-384 keypair
struct FakeDevice {
    CryptoEngine          engine;
    KeyPair               kp;
    std::vector<uint8_t>  public_key_der;

    FakeDevice() {
        auto r = engine.generate_keypair();
        assert(r.ok);
        public_key_der = r.value.public_key_der;
        kp = std::move(r.value);
    }

    // Sign challenge bytes as the device would
    ChallengeResponse sign_challenge(const LoginChallenge& lc) {
        auto sig = engine.sign(lc.challenge_bytes, kp.private_key_der);
        assert(sig.ok);
        return { lc.challenge_bytes, sig.value, public_key_der };
    }
};

// Build a ready-to-use Auth instance
Auth make_auth(
    std::shared_ptr<StorageAdapter> storage = nullptr,
    AuthConfig cfg = {})
{
    if (!storage) storage = std::make_shared<MemoryStorageAdapter>();
    auto keys = Auth::generate_server_keys();
    assert(keys.ok);
    auto auth = Auth::create(storage, std::move(keys.value), cfg);
    assert(auth.ok);
    return std::move(auth.value);
}


// ─── generate_server_keys ─────────────────────────────────────────────────────

TEST(test_generate_server_keys) {
    auto keys = Auth::generate_server_keys();
    ASSERT_OK(keys);
    ASSERT_FALSE(keys.value.hmac_key.empty());
    ASSERT_FALSE(keys.value.token_private_key_der.empty());
    ASSERT_FALSE(keys.value.token_public_key_der.empty());
}

TEST(test_server_keys_unique_each_call) {
    auto k1 = Auth::generate_server_keys();
    auto k2 = Auth::generate_server_keys();
    ASSERT_OK(k1); ASSERT_OK(k2);
    ASSERT_FALSE(k1.value.token_public_key_der == k2.value.token_public_key_der);
}


// ─── Registration ─────────────────────────────────────────────────────────────

TEST(test_begin_registration_returns_token) {
    auto auth = make_auth();
    auto r = auth.begin_registration("alice@example.com");
    ASSERT_OK(r);
    ASSERT_FALSE(r.value.magic_token.empty());
    ASSERT_TRUE(r.value.expires_at > 0);
}

TEST(test_duplicate_email_rejected) {
    auto auth = make_auth();
    auto r1 = auth.begin_registration("bob@example.com");
    ASSERT_OK(r1);
    auto r2 = auth.begin_registration("bob@example.com");
    ASSERT_ERR(r2);
}

TEST(test_invalid_email_rejected) {
    auto auth = make_auth();
    ASSERT_ERR(auth.begin_registration(""));
    ASSERT_ERR(auth.begin_registration("notanemail"));
}

TEST(test_complete_registration_returns_session) {
    auto auth = make_auth();
    FakeDevice dev;

    auto pending = auth.begin_registration("carol@example.com");
    ASSERT_OK(pending);

    auto session = auth.complete_registration(
        pending.value.magic_token, dev.public_key_der, "Laptop");
    ASSERT_OK(session);
    ASSERT_FALSE(session.value.user_id.empty());
    ASSERT_FALSE(session.value.token.empty());
    ASSERT_FALSE(session.value.device_id.empty());
}

TEST(test_wrong_magic_token_rejected) {
    auto auth = make_auth();
    FakeDevice dev;
    ASSERT_ERR(auth.complete_registration("bad.token", dev.public_key_der));
}

TEST(test_empty_public_key_rejected) {
    auto auth = make_auth();
    auto pending = auth.begin_registration("dave@example.com");
    ASSERT_OK(pending);
    ASSERT_ERR(auth.complete_registration(pending.value.magic_token, {}));
}


// ─── Login ────────────────────────────────────────────────────────────────────

// Helper: register a user and return their session
AuthSession register_user(Auth& auth, const std::string& email, FakeDevice& dev) {
    auto pending = auth.begin_registration(email);
    assert(pending.ok);
    auto session = auth.complete_registration(
        pending.value.magic_token, dev.public_key_der, "Test Device");
    assert(session.ok);
    return session.value;
}

TEST(test_login_full_flow) {
    auto auth = make_auth();
    FakeDevice dev;
    register_user(auth, "eve@example.com", dev);

    auto challenge = auth.begin_login("eve@example.com");
    ASSERT_OK(challenge);
    ASSERT_FALSE(challenge.value.challenge_bytes.empty());

    auto response  = dev.sign_challenge(challenge.value);
    auto session   = auth.complete_login(response);
    ASSERT_OK(session);
    ASSERT_FALSE(session.value.token.empty());
}

TEST(test_login_unknown_email_gives_generic_error) {
    auto auth = make_auth();
    auto r = auth.begin_login("nobody@example.com");
    // Must fail but with a generic message (no email enumeration)
    ASSERT_ERR(r);
    ASSERT_EQ(r.error, "authentication failed");
}

TEST(test_login_wrong_signature_rejected) {
    auto auth = make_auth();
    FakeDevice dev, attacker;
    register_user(auth, "frank@example.com", dev);

    auto challenge = auth.begin_login("frank@example.com");
    ASSERT_OK(challenge);

    // Attacker signs with their own key
    auto bad_response = attacker.sign_challenge(challenge.value);
    ASSERT_ERR(auth.complete_login(bad_response));
}

TEST(test_login_tampered_challenge_rejected) {
    auto auth = make_auth();
    FakeDevice dev;
    register_user(auth, "grace@example.com", dev);

    auto challenge = auth.begin_login("grace@example.com");
    ASSERT_OK(challenge);

    // Flip a byte in the challenge
    auto bad = challenge;
    bad.value.challenge_bytes[5] ^= 0xFF;
    auto resp = dev.sign_challenge(bad.value);
    ASSERT_ERR(auth.complete_login(resp));
}


// ─── Session management ───────────────────────────────────────────────────────

TEST(test_verify_session_valid_token) {
    auto auth = make_auth();
    FakeDevice dev;
    auto session = register_user(auth, "helen@example.com", dev);

    auto verified = auth.verify_session(session.token);
    ASSERT_OK(verified);
    ASSERT_EQ(verified.value.user_id, session.user_id);
}

TEST(test_verify_session_garbage_token) {
    auto auth = make_auth();
    ASSERT_ERR(auth.verify_session("not.a.real.token"));
}

TEST(test_refresh_session_returns_new_token) {
    auto auth = make_auth();
    FakeDevice dev;
    auto s1 = register_user(auth, "ivan@example.com", dev);
    auto s2 = auth.refresh_session(s1.token);
    ASSERT_OK(s2);
    ASSERT_EQ(s2.value.user_id, s1.user_id);
    ASSERT_FALSE(s2.value.token.empty());
}

TEST(test_logout_without_revoke_succeeds) {
    auto auth = make_auth();
    FakeDevice dev;
    auto session = register_user(auth, "julia@example.com", dev);
    ASSERT_OK(auth.logout(session.token, false));
}

TEST(test_logout_with_revoke_blocks_device) {
    auto auth = make_auth();
    FakeDevice dev;
    register_user(auth, "kate@example.com", dev);

    // Login to get a token
    auto ch   = auth.begin_login("kate@example.com");
    ASSERT_OK(ch);
    auto resp = dev.sign_challenge(ch.value);
    auto sess = auth.complete_login(resp);
    ASSERT_OK(sess);

    // Revoke the device
    ASSERT_OK(auth.logout(sess.value.token, true));

    // Device should no longer be able to log in
    auto ch2   = auth.begin_login("kate@example.com");
    // begin_login still works (email exists), but complete_login must fail
    if (ch2.ok) {
        auto resp2 = dev.sign_challenge(ch2.value);
        ASSERT_ERR(auth.complete_login(resp2));
    }
}


// ─── Account reset ────────────────────────────────────────────────────────────

TEST(test_begin_reset_known_email) {
    auto auth = make_auth();
    FakeDevice dev;
    register_user(auth, "liam@example.com", dev);

    auto r = auth.begin_reset("liam@example.com");
    ASSERT_OK(r);
    ASSERT_FALSE(r.value.magic_token.empty());
}

TEST(test_begin_reset_unknown_email_still_returns_token) {
    // Prevents user enumeration — should not error
    auto auth = make_auth();
    auto r = auth.begin_reset("ghost@example.com");
    ASSERT_OK(r);
    ASSERT_FALSE(r.value.magic_token.empty());
}

TEST(test_complete_reset_registers_new_device) {
    auto auth = make_auth();
    FakeDevice old_dev, new_dev;
    register_user(auth, "mia@example.com", old_dev);

    auto reset = auth.begin_reset("mia@example.com");
    ASSERT_OK(reset);

    auto session = auth.complete_reset(
        reset.value.magic_token, new_dev.public_key_der, "New Laptop");
    ASSERT_OK(session);
    ASSERT_FALSE(session.value.token.empty());
}

TEST(test_reset_wrong_token_rejected) {
    auto auth = make_auth();
    FakeDevice dev;
    ASSERT_ERR(auth.complete_reset("bad.token", dev.public_key_der));
}

TEST(test_reset_with_revoke_all) {
    AuthConfig cfg;
    cfg.revoke_all_on_reset = true;
    auto auth = make_auth(nullptr, cfg);

    FakeDevice old_dev, new_dev;
    register_user(auth, "noah@example.com", old_dev);

    auto reset = auth.begin_reset("noah@example.com");
    ASSERT_OK(reset);

    auto session = auth.complete_reset(
        reset.value.magic_token, new_dev.public_key_der);
    ASSERT_OK(session);

    // Old device login must fail after revoke_all
    auto ch = auth.begin_login("noah@example.com");
    if (ch.ok) {
        auto resp = old_dev.sign_challenge(ch.value);
        ASSERT_ERR(auth.complete_login(resp));
    }
}


// ─── Recovery codes ───────────────────────────────────────────────────────────

TEST(test_generate_recovery_codes) {
    auto auth = make_auth();
    FakeDevice dev;
    auto sess = register_user(auth, "olivia@example.com", dev);

    auto rc = auth.generate_recovery_codes(sess.user_id);
    ASSERT_OK(rc);
    ASSERT_EQ(rc.value.codes.size(), 8u);
    // Each code must start with "EZONE-"
    for (auto& c : rc.value.codes)
        ASSERT_TRUE(c.substr(0,6) == "EZONE-");
}

TEST(test_recover_with_valid_code) {
    auto auth = make_auth();
    FakeDevice dev, new_dev;
    auto sess = register_user(auth, "peter@example.com", dev);

    auto rc = auth.generate_recovery_codes(sess.user_id);
    ASSERT_OK(rc);

    auto pending = auth.recover_with_code("peter@example.com", rc.value.codes[0]);
    ASSERT_OK(pending);

    auto session = auth.complete_reset(
        pending.value.magic_token, new_dev.public_key_der);
    ASSERT_OK(session);
}

TEST(test_recovery_code_single_use) {
    auto auth = make_auth();
    FakeDevice dev;
    auto sess = register_user(auth, "quinn@example.com", dev);

    auto rc = auth.generate_recovery_codes(sess.user_id);
    ASSERT_OK(rc);

    // First use — must succeed
    ASSERT_OK(auth.recover_with_code("quinn@example.com", rc.value.codes[0]));

    // Second use — same code must fail
    ASSERT_ERR(auth.recover_with_code("quinn@example.com", rc.value.codes[0]));
}

TEST(test_wrong_recovery_code_rejected) {
    auto auth = make_auth();
    FakeDevice dev;
    register_user(auth, "rose@example.com", dev);

    ASSERT_ERR(auth.recover_with_code("rose@example.com", "EZONE-FAKE-FAKE-FAKE"));
}


// ─── Multi-device ─────────────────────────────────────────────────────────────

TEST(test_add_second_device) {
    auto auth = make_auth();
    FakeDevice dev1, dev2;
    auto sess1 = register_user(auth, "sam@example.com", dev1);

    auto pending = auth.begin_add_device(sess1.token);
    ASSERT_OK(pending);

    auto sess2 = auth.complete_add_device(
        pending.value.magic_token, dev2.public_key_der, "Phone");
    ASSERT_OK(sess2);
    ASSERT_EQ(sess2.value.user_id, sess1.user_id);
}

TEST(test_second_device_can_login) {
    auto auth = make_auth();
    FakeDevice dev1, dev2;
    auto sess1 = register_user(auth, "tina@example.com", dev1);

    auto pending = auth.begin_add_device(sess1.token);
    ASSERT_OK(pending);
    ASSERT_OK(auth.complete_add_device(
        pending.value.magic_token, dev2.public_key_der));

    // dev2 should now be able to complete login
    auto ch   = auth.begin_login("tina@example.com");
    ASSERT_OK(ch);
    auto resp = dev2.sign_challenge(ch.value);
    ASSERT_OK(auth.complete_login(resp));
}

TEST(test_list_devices) {
    auto auth = make_auth();
    FakeDevice dev1, dev2;
    auto sess1 = register_user(auth, "uma@example.com", dev1);

    auto pending = auth.begin_add_device(sess1.token);
    ASSERT_OK(pending);
    ASSERT_OK(auth.complete_add_device(
        pending.value.magic_token, dev2.public_key_der, "Tablet"));

    auto devices = auth.list_devices(sess1.token);
    ASSERT_OK(devices);
    ASSERT_TRUE(devices.value.size() >= 2);
}

TEST(test_revoke_device) {
    auto auth = make_auth();
    FakeDevice dev1, dev2;
    auto sess1 = register_user(auth, "victor@example.com", dev1);

    auto pending = auth.begin_add_device(sess1.token);
    ASSERT_OK(pending);
    auto sess2 = auth.complete_add_device(
        pending.value.magic_token, dev2.public_key_der);
    ASSERT_OK(sess2);

    // Revoke dev2 using dev1's session
    ASSERT_OK(auth.revoke_device(sess1.token, sess2.value.device_id));

    // dev2 can no longer log in
    auto ch   = auth.begin_login("victor@example.com");
    ASSERT_OK(ch);
    auto resp = dev2.sign_challenge(ch.value);
    ASSERT_ERR(auth.complete_login(resp));
}

TEST(test_cannot_revoke_another_users_device) {
    auto auth = make_auth();
    FakeDevice dev1, dev2;
    auto sess1 = register_user(auth, "wendy@example.com", dev1);
    auto sess2 = register_user(auth, "xavier@example.com", dev2);

    // wendy tries to revoke xavier's device — must fail
    ASSERT_ERR(auth.revoke_device(sess1.token, sess2.device_id));
}


// ─── Runner ───────────────────────────────────────────────────────────────────

int main() {
    std::cout << "\n=== ezone auth flow tests ===\n\n";
    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed.\n";
    return (tests_passed == tests_run) ? 0 : 1;
}
