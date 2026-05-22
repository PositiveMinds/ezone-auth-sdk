#include "ezone/ezone_c.h"
#include "ezone/auth.h"
#include "ezone/storage_adapter.h"

#include <cstring>
#include <memory>
#include <sstream>
#include <string>

// ─── Thread-local last error ──────────────────────────────────────────────────

static thread_local std::string tl_last_error;

static void set_last_error(const std::string& msg) {
    tl_last_error = msg;
}

static ezone_err_t result_to_err(const std::string& msg) {
    set_last_error(msg);
    if (msg.find("not found")         != std::string::npos) return EZONE_ERR_NOT_FOUND;
    if (msg.find("already")           != std::string::npos) return EZONE_ERR_ALREADY_EXISTS;
    if (msg.find("expired")           != std::string::npos) return EZONE_ERR_EXPIRED;
    if (msg.find("signature")         != std::string::npos) return EZONE_ERR_INVALID_SIGNATURE;
    if (msg.find("invalid")           != std::string::npos) return EZONE_ERR_INVALID_ARG;
    if (msg.find("empty")             != std::string::npos) return EZONE_ERR_INVALID_ARG;
    if (msg.find("storage")           != std::string::npos) return EZONE_ERR_STORAGE;
    if (msg.find("crypto")            != std::string::npos) return EZONE_ERR_CRYPTO;
    return EZONE_ERR_INTERNAL;
}


// ─── Opaque handle structs ────────────────────────────────────────────────────

struct ezone_keys_s {
    ezone::ServerKeys keys;
};

struct ezone_auth_s {
    std::shared_ptr<ezone::StorageAdapter> storage;
    ezone::Auth                            auth;
    ezone::AuthConfig                      config;
};


// ─── Helpers ──────────────────────────────────────────────────────────────────

static char* dup_str(const std::string& s) {
    char* p = static_cast<char*>(malloc(s.size() + 1));
    if (p) memcpy(p, s.c_str(), s.size() + 1);
    return p;
}

static uint8_t* dup_bytes(const std::vector<uint8_t>& v) {
    uint8_t* p = static_cast<uint8_t*>(malloc(v.size()));
    if (p) memcpy(p, v.data(), v.size());
    return p;
}

static void set_session_outputs(
    const ezone::AuthSession& s,
    char**    session_token_out,
    char**    user_id_out,
    char**    device_id_out,
    uint64_t* expires_at_out)
{
    if (session_token_out) *session_token_out = dup_str(s.token);
    if (user_id_out)       *user_id_out       = dup_str(s.user_id);
    if (device_id_out)     *device_id_out     = dup_str(s.device_id);
    if (expires_at_out)    *expires_at_out    = s.expires_at;
}


// ─── Public API ───────────────────────────────────────────────────────────────

const char* ezone_err_string(ezone_err_t err) {
    switch (err) {
        case EZONE_OK:                    return "ok";
        case EZONE_ERR_INVALID_ARG:       return "invalid argument";
        case EZONE_ERR_NOT_FOUND:         return "not found";
        case EZONE_ERR_ALREADY_EXISTS:    return "already exists";
        case EZONE_ERR_EXPIRED:           return "expired";
        case EZONE_ERR_INVALID_SIGNATURE: return "invalid signature";
        case EZONE_ERR_STORAGE:           return "storage error";
        case EZONE_ERR_CRYPTO:            return "crypto error";
        case EZONE_ERR_INTERNAL:          return "internal error";
    }
    return "unknown";
}

const char* ezone_last_error(void) {
    return tl_last_error.empty() ? "ok" : tl_last_error.c_str();
}

void ezone_free_string(char* s)   { free(s); }
void ezone_free_bytes(uint8_t* b) { free(b); }

void ezone_free_string_array(char** arr, size_t count) {
    if (!arr) return;
    for (size_t i = 0; i < count; ++i) free(arr[i]);
    free(arr);
}


// ── Server keys ───────────────────────────────────────────────────────────────

ezone_err_t ezone_keys_generate(ezone_keys_t* out) {
    if (!out) return EZONE_ERR_INVALID_ARG;
    auto r = ezone::Auth::generate_server_keys();
    if (!r) return result_to_err(r.error);
    *out = new ezone_keys_s{ std::move(r.value) };
    return EZONE_OK;
}

void ezone_keys_destroy(ezone_keys_t keys) { delete keys; }

ezone_err_t ezone_keys_export(
    ezone_keys_t keys,
    uint8_t** hmac_out, size_t* hmac_len,
    uint8_t** priv_out, size_t* priv_len,
    uint8_t** pub_out,  size_t* pub_len)
{
    if (!keys) return EZONE_ERR_INVALID_ARG;

    auto& k = keys->keys;
    auto hmac_copy = k.hmac_key.copy_out();
    auto priv_copy = k.token_private_key_der.copy_out();

    if (hmac_out)  { *hmac_out = dup_bytes(hmac_copy);              if (hmac_len) *hmac_len = hmac_copy.size(); }
    if (priv_out)  { *priv_out = dup_bytes(priv_copy);              if (priv_len) *priv_len = priv_copy.size(); }
    if (pub_out)   { *pub_out  = dup_bytes(k.token_public_key_der); if (pub_len)  *pub_len  = k.token_public_key_der.size(); }
    return EZONE_OK;
}

ezone_err_t ezone_keys_import(
    ezone_keys_t*  out,
    const uint8_t* hmac_key, size_t hmac_len,
    const uint8_t* priv_key, size_t priv_len,
    const uint8_t* pub_key,  size_t pub_len)
{
    if (!out || !hmac_key || !priv_key || !pub_key) return EZONE_ERR_INVALID_ARG;

    ezone::ServerKeys sk;
    sk.hmac_key             = ezone::SecureBuffer(hmac_key, hmac_len);
    sk.token_private_key_der = ezone::SecureBuffer(priv_key, priv_len);
    sk.token_public_key_der  = std::vector<uint8_t>(pub_key, pub_key + pub_len);

    *out = new ezone_keys_s{ std::move(sk) };
    return EZONE_OK;
}


// ── Auth instance ─────────────────────────────────────────────────────────────

ezone_err_t ezone_auth_create(ezone_auth_t* out, ezone_keys_t keys) {
    if (!out || !keys) return EZONE_ERR_INVALID_ARG;

    // Clone the keys into a new ServerKeys (copy public key, move-construct SecureBuffers)
    ezone::ServerKeys sk;
    sk.hmac_key              = ezone::SecureBuffer(
        keys->keys.hmac_key.data(), keys->keys.hmac_key.size());
    sk.token_private_key_der = ezone::SecureBuffer(
        keys->keys.token_private_key_der.data(),
        keys->keys.token_private_key_der.size());
    sk.token_public_key_der  = keys->keys.token_public_key_der;

    auto storage = std::make_shared<ezone::MemoryStorageAdapter>();
    auto r = ezone::Auth::create(storage, std::move(sk));
    if (!r) return result_to_err(r.error);

    auto* h = new ezone_auth_s{
        storage,
        std::move(r.value),
        {}
    };
    *out = h;
    return EZONE_OK;
}

void ezone_auth_destroy(ezone_auth_t auth) { delete auth; }

ezone_err_t ezone_auth_set_magic_link_ttl(ezone_auth_t a, uint32_t s) {
    if (!a) return EZONE_ERR_INVALID_ARG;
    a->config.magic_link_ttl_seconds = s;
    return EZONE_OK;
}
ezone_err_t ezone_auth_set_session_ttl(ezone_auth_t a, uint32_t s) {
    if (!a) return EZONE_ERR_INVALID_ARG;
    a->config.session_ttl_seconds = s;
    return EZONE_OK;
}
ezone_err_t ezone_auth_set_challenge_ttl(ezone_auth_t a, uint32_t s) {
    if (!a) return EZONE_ERR_INVALID_ARG;
    a->config.challenge_ttl_seconds = s;
    return EZONE_OK;
}
ezone_err_t ezone_auth_set_recovery_code_count(ezone_auth_t a, uint8_t n) {
    if (!a) return EZONE_ERR_INVALID_ARG;
    a->config.recovery_code_count = n;
    return EZONE_OK;
}
ezone_err_t ezone_auth_set_revoke_all_on_reset(ezone_auth_t a, int en) {
    if (!a) return EZONE_ERR_INVALID_ARG;
    a->config.revoke_all_on_reset = (en != 0);
    return EZONE_OK;
}


// ── Registration ──────────────────────────────────────────────────────────────

ezone_err_t ezone_begin_registration(
    ezone_auth_t auth, const char* email,
    char** magic_token_out, uint64_t* expires_at_out)
{
    if (!auth || !email || !magic_token_out) return EZONE_ERR_INVALID_ARG;
    auto r = auth->auth.begin_registration(email);
    if (!r) return result_to_err(r.error);
    *magic_token_out = dup_str(r.value.magic_token);
    if (expires_at_out) *expires_at_out = r.value.expires_at;
    return EZONE_OK;
}

ezone_err_t ezone_complete_registration(
    ezone_auth_t auth, const char* token,
    const uint8_t* pk, size_t pk_len, const char* label,
    char** sess_out, char** uid_out, char** did_out, uint64_t* exp_out)
{
    if (!auth || !token || !pk || !sess_out) return EZONE_ERR_INVALID_ARG;
    std::vector<uint8_t> pubkey(pk, pk + pk_len);
    auto r = auth->auth.complete_registration(
        token, pubkey, label ? label : "Device");
    if (!r) return result_to_err(r.error);
    set_session_outputs(r.value, sess_out, uid_out, did_out, exp_out);
    return EZONE_OK;
}


// ── Login ─────────────────────────────────────────────────────────────────────

ezone_err_t ezone_begin_login(
    ezone_auth_t auth, const char* email,
    uint8_t** ch_out, size_t* ch_len, uint64_t* exp_out)
{
    if (!auth || !email || !ch_out || !ch_len) return EZONE_ERR_INVALID_ARG;
    auto r = auth->auth.begin_login(email);
    if (!r) return result_to_err(r.error);
    *ch_out  = dup_bytes(r.value.challenge_bytes);
    *ch_len  = r.value.challenge_bytes.size();
    if (exp_out) *exp_out = r.value.expires_at;
    return EZONE_OK;
}

ezone_err_t ezone_complete_login(
    ezone_auth_t auth,
    const uint8_t* ch, size_t ch_len,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* pk, size_t pk_len,
    char** sess_out, char** uid_out, char** did_out, uint64_t* exp_out)
{
    if (!auth || !ch || !sig || !pk || !sess_out) return EZONE_ERR_INVALID_ARG;
    ezone::ChallengeResponse resp{
        std::vector<uint8_t>(ch, ch + ch_len),
        std::vector<uint8_t>(sig, sig + sig_len),
        std::vector<uint8_t>(pk, pk + pk_len)
    };
    auto r = auth->auth.complete_login(resp);
    if (!r) return result_to_err(r.error);
    set_session_outputs(r.value, sess_out, uid_out, did_out, exp_out);
    return EZONE_OK;
}


// ── Session ───────────────────────────────────────────────────────────────────

ezone_err_t ezone_verify_session(
    ezone_auth_t auth, const char* token,
    char** uid_out, char** email_out, char** did_out, uint64_t* exp_out)
{
    if (!auth || !token) return EZONE_ERR_INVALID_ARG;
    auto r = auth->auth.verify_session(token);
    if (!r) return result_to_err(r.error);
    if (uid_out)   *uid_out   = dup_str(r.value.user_id);
    if (email_out) *email_out = dup_str(r.value.email);
    if (did_out)   *did_out   = dup_str(r.value.device_id);
    if (exp_out)   *exp_out   = r.value.expires_at;
    return EZONE_OK;
}

ezone_err_t ezone_refresh_session(
    ezone_auth_t auth, const char* token,
    char** new_tok_out, uint64_t* exp_out)
{
    if (!auth || !token || !new_tok_out) return EZONE_ERR_INVALID_ARG;
    auto r = auth->auth.refresh_session(token);
    if (!r) return result_to_err(r.error);
    *new_tok_out = dup_str(r.value.token);
    if (exp_out) *exp_out = r.value.expires_at;
    return EZONE_OK;
}

ezone_err_t ezone_logout(ezone_auth_t auth, const char* token, int revoke) {
    if (!auth || !token) return EZONE_ERR_INVALID_ARG;
    auto r = auth->auth.logout(token, revoke != 0);
    if (!r) return result_to_err(r.error);
    return EZONE_OK;
}


// ── Reset ─────────────────────────────────────────────────────────────────────

ezone_err_t ezone_begin_reset(
    ezone_auth_t auth, const char* email,
    char** tok_out, uint64_t* exp_out)
{
    if (!auth || !email || !tok_out) return EZONE_ERR_INVALID_ARG;
    auto r = auth->auth.begin_reset(email);
    if (!r) return result_to_err(r.error);
    *tok_out = dup_str(r.value.magic_token);
    if (exp_out) *exp_out = r.value.expires_at;
    return EZONE_OK;
}

ezone_err_t ezone_complete_reset(
    ezone_auth_t auth, const char* token,
    const uint8_t* pk, size_t pk_len, const char* label,
    char** sess_out, char** uid_out, uint64_t* exp_out)
{
    if (!auth || !token || !pk || !sess_out) return EZONE_ERR_INVALID_ARG;
    std::vector<uint8_t> pubkey(pk, pk + pk_len);
    auto r = auth->auth.complete_reset(token, pubkey, label ? label : "Device");
    if (!r) return result_to_err(r.error);
    if (sess_out) *sess_out = dup_str(r.value.token);
    if (uid_out)  *uid_out  = dup_str(r.value.user_id);
    if (exp_out)  *exp_out  = r.value.expires_at;
    return EZONE_OK;
}


// ── Recovery codes ────────────────────────────────────────────────────────────

ezone_err_t ezone_generate_recovery_codes(
    ezone_auth_t auth, const char* user_id,
    char*** codes_out, size_t* count_out)
{
    if (!auth || !user_id || !codes_out || !count_out) return EZONE_ERR_INVALID_ARG;
    auto r = auth->auth.generate_recovery_codes(user_id);
    if (!r) return result_to_err(r.error);

    size_t n = r.value.codes.size();
    char** arr = static_cast<char**>(malloc(n * sizeof(char*)));
    for (size_t i = 0; i < n; ++i) arr[i] = dup_str(r.value.codes[i]);
    *codes_out = arr;
    *count_out = n;
    return EZONE_OK;
}

ezone_err_t ezone_recover_with_code(
    ezone_auth_t auth, const char* email, const char* code,
    char** tok_out, uint64_t* exp_out)
{
    if (!auth || !email || !code || !tok_out) return EZONE_ERR_INVALID_ARG;
    auto r = auth->auth.recover_with_code(email, code);
    if (!r) return result_to_err(r.error);
    *tok_out = dup_str(r.value.magic_token);
    if (exp_out) *exp_out = r.value.expires_at;
    return EZONE_OK;
}


// ── Multi-device ──────────────────────────────────────────────────────────────

ezone_err_t ezone_begin_add_device(
    ezone_auth_t auth, const char* token,
    char** add_tok_out, uint64_t* exp_out)
{
    if (!auth || !token || !add_tok_out) return EZONE_ERR_INVALID_ARG;
    auto r = auth->auth.begin_add_device(token);
    if (!r) return result_to_err(r.error);
    *add_tok_out = dup_str(r.value.magic_token);
    if (exp_out) *exp_out = r.value.expires_at;
    return EZONE_OK;
}

ezone_err_t ezone_complete_add_device(
    ezone_auth_t auth, const char* add_token,
    const uint8_t* pk, size_t pk_len, const char* label,
    char** sess_out, char** did_out, uint64_t* exp_out)
{
    if (!auth || !add_token || !pk || !sess_out) return EZONE_ERR_INVALID_ARG;
    std::vector<uint8_t> pubkey(pk, pk + pk_len);
    auto r = auth->auth.complete_add_device(add_token, pubkey, label ? label : "Device");
    if (!r) return result_to_err(r.error);
    *sess_out = dup_str(r.value.token);
    if (did_out) *did_out = dup_str(r.value.device_id);
    if (exp_out) *exp_out = r.value.expires_at;
    return EZONE_OK;
}

ezone_err_t ezone_revoke_device(
    ezone_auth_t auth, const char* token, const char* device_id)
{
    if (!auth || !token || !device_id) return EZONE_ERR_INVALID_ARG;
    auto r = auth->auth.revoke_device(token, device_id);
    if (!r) return result_to_err(r.error);
    return EZONE_OK;
}

ezone_err_t ezone_list_devices(
    ezone_auth_t auth, const char* token, char** json_out)
{
    if (!auth || !token || !json_out) return EZONE_ERR_INVALID_ARG;
    auto r = auth->auth.list_devices(token);
    if (!r) return result_to_err(r.error);

    std::ostringstream ss;
    ss << "[";
    for (size_t i = 0; i < r.value.size(); ++i) {
        const auto& d = r.value[i];
        if (i) ss << ",";
        ss << "{\"device_id\":\"" << d.device_id << "\","
           << "\"label\":\""      << d.label     << "\","
           << "\"created_at\":"   << d.created_at << ","
           << "\"revoked\":"      << (d.revoked ? "true" : "false") << "}";
    }
    ss << "]";

    *json_out = dup_str(ss.str());
    return EZONE_OK;
}
