#pragma once

#include "crypto_engine.h"
#include "types.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ezone {

// ─── WebAuthn Types ──────────────────────────────────────────────────────────

// Stored credential from a successful WebAuthn registration
struct WebAuthnCredential {
    std::string          credential_id;     // base64url-encoded credential identifier
    std::vector<uint8_t> public_key_der;    // COSE public key (raw bytes)
    std::string          user_id;           // owner user_id
    uint64_t             sign_count = 0;    // signature counter (clone detection)
    uint64_t             created_at = 0;    // unix epoch seconds
    std::string          aaguid;            // authenticator AAGUID (identifies the device model)
    std::string          label;             // user-friendly label (e.g. "FaceID", "YubiKey")
    bool                 backed_up = false; // whether credential is backed up
    bool                 uv_required = false; // user verification required
};

// Registration options sent to the client (Relying Party)
struct WebAuthnRegistrationOptions {
    std::string          challenge;         // base64url-encoded challenge
    std::string          rp_id;             // Relying Party ID (e.g. "example.com")
    std::string          rp_name;           // Relying Party name (e.g. "My App")
    std::string          user_id;           // base64url-encoded user ID
    std::string          user_name;         // user's email or username
    std::string          user_display_name; // user's display name
    std::vector<uint8_t> exclude_credential_ids; // credentials to exclude (already registered)
};

// Authentication options sent to the client
struct WebAuthnAuthenticationOptions {
    std::string          challenge;         // base64url-encoded challenge
    std::string          rp_id;             // Relying Party ID
    std::vector<std::string> allow_credential_ids; // accepted credential IDs (empty = any)
};

// ClientDataJSON — parsed from the browser's navigator.credentials response
struct WebAuthnClientData {
    std::string type;             // "webauthn.create" or "webauthn.get"
    std::string challenge;        // base64url challenge
    std::string origin;           // origin URL
    bool        cross_origin = false;
};

// Attestation object from navigator.credentials.create()
// Simplified: handles packed/self-attestation and none attestation
struct WebAuthnAttestationObject {
    std::vector<uint8_t> auth_data;   // authenticator data
    std::string          fmt;         // attestation format ("packed", "none", "fido-u2f")
    std::vector<uint8_t> att_stmt;   // attestation statement (CBOR)
};

// Assertion response from navigator.credentials.get()
struct WebAuthnAssertion {
    std::string          credential_id;    // base64url-encoded
    std::vector<uint8_t> authenticator_data;
    std::vector<uint8_t> signature;        // over authenticator_data || client_data_hash
    std::vector<uint8_t> client_data_json; // raw ClientDataJSON bytes
};

// ─── WebAuthn Server ─────────────────────────────────────────────────────────
//
// Server-side WebAuthn/FIDO2 implementation.
// Handles registration and authentication ceremony, attestation/ assertion
// verification, and credential management.

class WebAuthnServer {
public:
    // Construct with a crypto engine reference and relying party config
    WebAuthnServer(
        CryptoEngine& engine,
        const SecureBuffer& hmac_key,
        const std::string& rp_id = "localhost",
        const std::string& rp_name = "ezone App"
    );
    ~WebAuthnServer();

    WebAuthnServer(const WebAuthnServer&) = delete;
    WebAuthnServer& operator=(const WebAuthnServer&) = delete;

    // ── Registration ─────────────────────────────────────────────────────────

    // Begin registration — generates options for navigator.credentials.create()
    // exclude_ids: credential IDs the user already has (prevents re-registration)
    Result<WebAuthnRegistrationOptions> begin_registration(
        const std::string& user_id,
        const std::string& user_name,
        const std::string& display_name,
        const std::vector<std::string>& exclude_ids = {}
    );

    // Complete registration — verifies the attestation and returns the credential
    // attestation_b64: base64url-encoded AttestationObject from the browser
    // client_data_json: raw ClientDataJSON bytes from the browser
    Result<WebAuthnCredential> complete_registration(
        const WebAuthnRegistrationOptions& options,
        const std::string& attestation_b64,
        const std::string& client_data_json,
        const std::string& credential_label = "WebAuthn"
    );

    // ── Authentication ───────────────────────────────────────────────────────

    // Begin authentication — generates options for navigator.credentials.get()
    // allow_ids: optional list of credential IDs to accept (empty = any)
    Result<WebAuthnAuthenticationOptions> begin_authentication(
        const std::string& rp_id,
        const std::vector<std::string>& allow_ids = {}
    );

    // Complete authentication — verifies the assertion and returns the credential
    // assertion: parsed assertion from the browser
    // stored_credentials: credentials fetched from storage for this user
    Result<WebAuthnCredential> complete_authentication(
        const WebAuthnAuthenticationOptions& options,
        const WebAuthnAssertion& assertion,
        const std::vector<WebAuthnCredential>& stored_credentials
    );

    // ── Utilities ────────────────────────────────────────────────────────────

    // Verify that a challenge (as returned in challenge/rp_id options) was
    // genuinely issued by this server and is still fresh — HMAC + timestamp
    // bound, same as the registration/authentication ceremonies check
    // internally.
    bool verify_challenge(const std::string& challenge_b64);

    // Parse a ClientDataJSON string into a structured form
    Result<WebAuthnClientData> parse_client_data(const std::string& json_str);

    // Verify that clientDataJSON matches the expected challenge and origin
    bool verify_client_data(
        const WebAuthnClientData& client_data,
        const std::string& expected_challenge,
        const std::string& expected_origin,
        const std::string& expected_type
    );

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ezone
