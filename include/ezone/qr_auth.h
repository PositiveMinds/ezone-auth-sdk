#pragma once

#include "crypto_engine.h"
#include "types.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ezone {

// ─── QR Auth Types ───────────────────────────────────────────────────────────

// Status of a QR auth session
enum class QRStatus : uint8_t {
    Pending  = 0,  // QR code generated, waiting for scan
    Scanned  = 1,  // QR code scanned, waiting for approval
    Approved = 2,  // User approved on mobile
    Denied   = 3,  // User denied on mobile
    Expired  = 4,  // QR session expired
    Error    = 5   // An error occurred
};

const char* qr_status_string(QRStatus s) noexcept;

// A QR auth session — created when the desktop client requests a QR code
struct QRSession {
    std::string session_id;    // unique session identifier
    std::string qr_data;       // data to encode in the QR code (URL or JSON)
    QRStatus    status = QRStatus::Pending;
    uint64_t    created_at = 0;
    uint64_t    expires_at = 0;
    std::string challenge;     // base64url-encoded challenge for the phone to sign
};

// Information embedded in the QR code
struct QRCodePayload {
    std::string session_id;    // session to poll
    std::string challenge;     // challenge the phone must sign
    std::string server_url;    // base URL of the auth server
    uint64_t    expires_at = 0;
};

// The mobile client's response when approving a QR login
struct QRApproval {
    std::string session_id;    // which session this approval is for
    std::string device_id;     // mobile device's public key ID
    std::vector<uint8_t> public_key_der; // mobile device's public key
    std::vector<uint8_t> signature;      // signature over the challenge
    std::string device_label;  // e.g. "Alice's iPhone"
};

// ─── QR Auth Server ──────────────────────────────────────────────────────────
//
// Server-side QR code authentication.
// Desktop generates a QR code, user scans with phone, approves, desktop gets
// authenticated.

class QRAuthServer {
public:
    QRAuthServer(
        CryptoEngine& engine,
        const SecureBuffer& hmac_key,
        uint32_t qr_ttl_seconds = 300 // 5 min default
    );
    ~QRAuthServer();

    QRAuthServer(const QRAuthServer&) = delete;
    QRAuthServer& operator=(const QRAuthServer&) = delete;

    // ── Desktop flow ─────────────────────────────────────────────────────────

    // Begin QR auth — generates a QR code for the desktop to display.
    // desktop_ip: IP of the desktop (for IP binding — prevents QR phishing)
    // Returns the QR data (encode as QR code) and session_id for polling.
    Result<QRSession> begin_qr_auth(const std::string& desktop_ip = "");

    // Poll QR status — desktop calls this repeatedly to check if the user has
    // scanned/approved the QR code.
    Result<QRStatus> poll_qr_status(const std::string& session_id);

    // Complete QR auth — once status is Approved, call this to get the session.
    // Returns the authenticated user's session token.
    Result<std::pair<std::string, std::string>> complete_qr_auth(
        const std::string& session_id
    );

    // ── Mobile flow ──────────────────────────────────────────────────────────

    // Validate a QR code — mobile calls this after scanning to verify the QR
    // code is legitimate and not expired. Returns the challenge to sign.
    // mobile_ip: IP of the mobile device (for IP verification)
    Result<std::string> validate_qr(const std::string& qr_data,
                                     const std::string& mobile_ip = "");

    // Approve QR login — mobile signs the challenge and sends approval.
    Result<void> approve_qr(const QRApproval& approval);

    // Deny QR login — mobile user declines the login.
    Result<void> deny_qr(const std::string& session_id);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ezone
