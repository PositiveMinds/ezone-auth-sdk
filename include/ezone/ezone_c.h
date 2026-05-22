/**
 * ezone_c.h  —  C API for the ezone passwordless authentication SDK
 *
 * This is the FFI-stable interface. Language bindings (Python, Ruby, Go,
 * Rust, etc.) and the REST server all build on this header.
 *
 * Memory contract:
 *   - Every char* / uint8_t* output parameter is heap-allocated.
 *     Free strings with ezone_free_string(), bytes with ezone_free_bytes(),
 *     and string arrays with ezone_free_string_array().
 *   - NULL may be passed for output parameters you don't need.
 *   - Opaque handles must be destroyed with their ezone_*_destroy() call.
 */

#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ─── Error codes ──────────────────────────────────────────────────────────────

typedef enum {
    EZONE_OK                    = 0,
    EZONE_ERR_INVALID_ARG       = 1,
    EZONE_ERR_NOT_FOUND         = 2,
    EZONE_ERR_ALREADY_EXISTS    = 3,
    EZONE_ERR_EXPIRED           = 4,
    EZONE_ERR_INVALID_SIGNATURE = 5,
    EZONE_ERR_STORAGE           = 6,
    EZONE_ERR_CRYPTO            = 7,
    EZONE_ERR_INTERNAL          = 8,
} ezone_err_t;

const char* ezone_err_string(ezone_err_t err);

// After any non-OK return, call this for a human-readable description
// of the most recent error on the current thread.
const char* ezone_last_error(void);


// ─── Memory management ────────────────────────────────────────────────────────

void ezone_free_string(char* s);
void ezone_free_bytes(uint8_t* b);
void ezone_free_string_array(char** arr, size_t count);


// ─── Opaque handles ───────────────────────────────────────────────────────────

typedef struct ezone_keys_s* ezone_keys_t;
typedef struct ezone_auth_s* ezone_auth_t;


// ─── Server keys ──────────────────────────────────────────────────────────────

// Generate server keys. Call once at first startup, then persist the
// exported bytes in a secrets manager and import on subsequent restarts.
ezone_err_t ezone_keys_generate(ezone_keys_t* out);
void        ezone_keys_destroy(ezone_keys_t keys);

// Export key material for persistent storage (all outputs heap-allocated).
ezone_err_t ezone_keys_export(
    ezone_keys_t keys,
    uint8_t** hmac_key_out,  size_t* hmac_len_out,
    uint8_t** priv_key_out,  size_t* priv_len_out,
    uint8_t** pub_key_out,   size_t* pub_len_out
);

// Reconstruct keys from previously exported bytes.
ezone_err_t ezone_keys_import(
    ezone_keys_t*  out,
    const uint8_t* hmac_key, size_t hmac_len,
    const uint8_t* priv_key, size_t priv_len,
    const uint8_t* pub_key,  size_t pub_len
);


// ─── Auth instance ────────────────────────────────────────────────────────────

// Create an Auth instance backed by the built-in in-memory storage adapter.
// For production, use ezone_auth_create_with_storage() (see extended API).
ezone_err_t ezone_auth_create(ezone_auth_t* out, ezone_keys_t keys);
void        ezone_auth_destroy(ezone_auth_t auth);

// Configuration (call before first use, optional — defaults are safe)
ezone_err_t ezone_auth_set_magic_link_ttl(ezone_auth_t auth, uint32_t seconds);
ezone_err_t ezone_auth_set_session_ttl(ezone_auth_t auth, uint32_t seconds);
ezone_err_t ezone_auth_set_challenge_ttl(ezone_auth_t auth, uint32_t seconds);
ezone_err_t ezone_auth_set_recovery_code_count(ezone_auth_t auth, uint8_t count);
ezone_err_t ezone_auth_set_revoke_all_on_reset(ezone_auth_t auth, int enabled);


// ─── Registration ─────────────────────────────────────────────────────────────

// Step 1: initiate registration for an email address.
// Embed magic_token in an email link: https://yourapp.com/verify?token=<magic_token>
ezone_err_t ezone_begin_registration(
    ezone_auth_t auth,
    const char*  email,
    char**       magic_token_out,   // free with ezone_free_string
    uint64_t*    expires_at_out     // may be NULL
);

// Step 2: user clicks the link. Device supplies its P-384 public key (DER).
ezone_err_t ezone_complete_registration(
    ezone_auth_t   auth,
    const char*    magic_token,
    const uint8_t* pubkey_der,    size_t pubkey_len,
    const char*    device_label,  // may be NULL → "Device"
    char**         session_token_out,  // free with ezone_free_string
    char**         user_id_out,        // free with ezone_free_string; may be NULL
    char**         device_id_out,      // free with ezone_free_string; may be NULL
    uint64_t*      expires_at_out      // may be NULL
);


// ─── Login ────────────────────────────────────────────────────────────────────

// Step 1: generate a challenge for the device to sign.
ezone_err_t ezone_begin_login(
    ezone_auth_t auth,
    const char*  email,
    uint8_t**    challenge_out,     // free with ezone_free_bytes
    size_t*      challenge_len_out,
    uint64_t*    expires_at_out     // may be NULL
);

// Step 2: device signed the challenge bytes; provide signature + public key.
ezone_err_t ezone_complete_login(
    ezone_auth_t   auth,
    const uint8_t* challenge,     size_t challenge_len,
    const uint8_t* signature,     size_t sig_len,
    const uint8_t* pubkey_der,    size_t pubkey_len,
    char**         session_token_out,
    char**         user_id_out,        // may be NULL
    char**         device_id_out,      // may be NULL
    uint64_t*      expires_at_out      // may be NULL
);


// ─── Session ──────────────────────────────────────────────────────────────────

// Verify a token. Use in request middleware / guards.
ezone_err_t ezone_verify_session(
    ezone_auth_t auth,
    const char*  token,
    char**       user_id_out,     // may be NULL
    char**       email_out,       // may be NULL
    char**       device_id_out,   // may be NULL
    uint64_t*    expires_at_out   // may be NULL
);

// Issue a fresh token for an already-valid session (silent renewal).
ezone_err_t ezone_refresh_session(
    ezone_auth_t auth,
    const char*  token,
    char**       new_token_out,
    uint64_t*    expires_at_out   // may be NULL
);

// Log out. Pass revoke_device=1 to permanently revoke the signing device.
ezone_err_t ezone_logout(
    ezone_auth_t auth,
    const char*  token,
    int          revoke_device
);


// ─── Account reset ────────────────────────────────────────────────────────────

// Step 1: user requests a reset link. Never errors on unknown email
// (prevents user enumeration) — always returns a token.
ezone_err_t ezone_begin_reset(
    ezone_auth_t auth,
    const char*  email,
    char**       magic_token_out,
    uint64_t*    expires_at_out
);

// Step 2: user clicked reset link, registers new device.
ezone_err_t ezone_complete_reset(
    ezone_auth_t   auth,
    const char*    magic_token,
    const uint8_t* pubkey_der,   size_t pubkey_len,
    const char*    device_label,
    char**         session_token_out,
    char**         user_id_out,
    uint64_t*      expires_at_out
);


// ─── Recovery codes ───────────────────────────────────────────────────────────

// Generate recovery codes for a user (call once after registration).
// Show codes to the user exactly once — only HMAC hashes are stored.
ezone_err_t ezone_generate_recovery_codes(
    ezone_auth_t auth,
    const char*  user_id,
    char***      codes_out,   // array of count strings; free with ezone_free_string_array
    size_t*      count_out
);

// Use one recovery code. Returns a reset magic_token on success.
// The code is permanently consumed.
ezone_err_t ezone_recover_with_code(
    ezone_auth_t auth,
    const char*  email,
    const char*  recovery_code,
    char**       magic_token_out,
    uint64_t*    expires_at_out
);


// ─── Multi-device ─────────────────────────────────────────────────────────────

// Step 1: authenticated user wants to enrol a new device.
// Send add_token to the new device (e.g. via QR code or link).
ezone_err_t ezone_begin_add_device(
    ezone_auth_t auth,
    const char*  session_token,
    char**       add_token_out,
    uint64_t*    expires_at_out
);

// Step 2: new device supplies its public key.
ezone_err_t ezone_complete_add_device(
    ezone_auth_t   auth,
    const char*    add_token,
    const uint8_t* pubkey_der,   size_t pubkey_len,
    const char*    device_label,
    char**         session_token_out,
    char**         device_id_out,
    uint64_t*      expires_at_out
);

// Revoke a specific device (must be authenticated with a different device).
ezone_err_t ezone_revoke_device(
    ezone_auth_t auth,
    const char*  session_token,
    const char*  device_id
);

// List devices for the authenticated user.
// Returns JSON array string: [{"device_id":"...","label":"...","revoked":false}, ...]
ezone_err_t ezone_list_devices(
    ezone_auth_t auth,
    const char*  session_token,
    char**       json_out    // free with ezone_free_string
);

#ifdef __cplusplus
}
#endif
