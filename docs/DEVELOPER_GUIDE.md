# ezone Auth SDK — Developer Guide

## How Passwordless Authentication Works

### The Two-Step Model

Every authentication is a two-step process:

```
┌──────────────────────────────────────────────────────────────────┐
│  STEP 1: IDENTIFICATION — "Who are you?"                        │
│                                                                  │
│  The user claims an identity:                                    │
│    • Email: "alice@example.com"                                  │
│    • Username: "alice_j"                                         │
│    • Phone: "+1234567890"                                        │
│                                                                  │
│  This is just a claim — NOT proof. Anyone can say they're Alice. │
├──────────────────────────────────────────────────────────────────┤
│  STEP 2: AUTHENTICATION — "Prove it"                            │
│                                                                  │
│  The user proves they own that identity:                         │
│    • Signs a challenge with their device key                     │
│    • Enters a 6-digit OTP code                                   │
│    • Uses FaceID/TouchID (WebAuthn)                              │
│    • Scans a QR code with their phone                            │
│    • Approves a push notification                                │
│                                                                  │
│  The server verifies the proof → issues a session token.         │
└──────────────────────────────────────────────────────────────────┘
```

**Key insight:** Email/username identifies the account. The device key/biometric/code proves ownership.

---

## Choosing Your Auth Methods

```cpp
#include "ezone/auth.h"

ezone::AuthConfig cfg;

// Enable ONLY what your app needs:
cfg.enabled_methods =
    ezone::AuthMethod::Challenge |   // Device key login (always recommended)
    ezone::AuthMethod::MagicLink |   // Email registration
    ezone::AuthMethod::Recovery;     // Backup codes

// Or enable everything:
cfg.enabled_methods = ezone::AUTH_METHOD_ALL;
```

### Method Selection Guide

| Your App Needs | Enable |
|----------------|--------|
| Basic passwordless login | `Challenge + MagicLink` |
| Mobile app with biometrics | `+ WebAuthn` |
| Desktop ↔ Phone login | `+ QRCode` |
| Push notification approval | `+ Push` |
| Email fallback for non-tech users | `+ OTP` |
| Everything | `AUTH_METHOD_ALL` |

---

## Registration Flow

New users create an account via magic link (no password):

```
Client                          Server
  │                               │
  │  POST /auth/register/begin    │
  │  { "email": "alice@..." }     │
  │──────────────────────────────>│
  │                               │── Create placeholder user (active=false)
  │                               │── Generate HMAC-signed magic token
  │                               │── Send magic link to email
  │  { "magic_token": "..." }     │
  │<──────────────────────────────│
  │                               │
  │  [User clicks email link]     │
  │                               │
  │  POST /auth/register/complete │
  │  { "magic_token": "...",      │
  │    "public_key": "base64..." }│
  │──────────────────────────────>│
  │                               │── Verify magic token (HMAC + expiry)
  │                               │── Store device public key
  │                               │── Activate user account
  │                               │── Issue session token
  │  { "token": "...",            │
  │    "user_id": "..." }         │
  │<──────────────────────────────│
```

### With Username Support

```cpp
// During registration, include a username:
UserRecord user;
user.user_id = "...";
user.email = "alice@example.com";
user.username = "alice_j";        // optional
user.display_name = "Alice Johnson"; // optional
storage->create_user(user);

// Now users can log in with EITHER email OR username:
auto challenge = auth->begin_login("alice_j");      // username
auto challenge = auth->begin_login("alice@...");    // email — both work
```

---

## Login Flows

### 1. Challenge-Response (Device Key)

```
Client                          Server
  │                               │
  │  POST /auth/login/begin       │
  │  { "email": "alice@..." }     │
  │──────────────────────────────>│
  │                               │── Look up user by email OR username
  │                               │── Generate HMAC-signed challenge
  │  { "challenge": "base64..." } │
  │<──────────────────────────────│
  │                               │
  │  [Client signs challenge      │
  │   with device private key]    │
  │                               │
  │  POST /auth/login/complete    │
  │  { "challenge": "...",        │
  │    "signature": "...",        │
  │    "public_key": "..." }      │
  │──────────────────────────────>│
  │                               │── Verify challenge (HMAC + freshness)
  │                               │── Verify ECDSA signature
  │                               │── Look up device by public key
  │                               │── Issue session token
  │  { "token": "...",            │
  │    "user_id": "..." }         │
  │<──────────────────────────────│
```

### 2. OTP (Email/SMS)

```
Client                          Server
  │                               │
  │  POST /auth/otp/request       │
  │  { "email": "alice@..." }     │
  │──────────────────────────────>│
  │                               │── Generate 6-digit code
  │                               │── Hash with HMAC-SHA384
  │                               │── Send code via email
  │  { "token_id": "...",         │
  │    "expires_at": 1234567890 } │
  │<──────────────────────────────│
  │                               │
  │  [User enters code from email]│
  │                               │
  │  POST /auth/otp/verify        │
  │  { "token_id": "...",         │
  │    "code": "482917" }         │
  │──────────────────────────────>│
  │                               │── Hash provided code
  │                               │── Constant-time compare with stored hash
  │                               │── Check: not expired, not locked, attempts OK
  │  { "status": "verified",      │
  │    "code_hash": "..." }       │
  │<──────────────────────────────│
```

**Security features:**
- 3 failed attempts → 15 minute lockout
- 5 requests per email per 15 minutes
- 10 requests per IP per 15 minutes
- Codes expire after 5 minutes

### 3. WebAuthn (Biometric)

```
Client (Browser)                Server
  │                               │
  │  POST /auth/webauthn/         │
  │       register/begin          │
  │──────────────────────────────>│
  │  { "challenge": "...",        │
  │    "rp_id": "example.com" }   │
  │<──────────────────────────────│
  │                               │
  │  [navigator.credentials.create│
  │   → FaceID/TouchID prompt]    │
  │                               │
  │  POST /auth/webauthn/         │
  │       register/complete       │
  │  { "attestation": "...",      │
  │    "client_data_json": "..." }│
  │──────────────────────────────>│
  │                               │── Parse CBOR attestation
  │                               │── Verify RP ID hash
  │                               │── Verify user presence flag
  │                               │── Extract COSE public key
  │                               │── Store credential
  │  { "credential_id": "..." }   │
  │<──────────────────────────────│
```

### 4. QR Code (Cross-Device)

```
Desktop (Browser)               Server                    Mobile (App)
  │                               │                          │
  │  POST /auth/qr/begin          │                          │
  │──────────────────────────────>│                          │
  │  { "qr_data": "base64...",    │                          │
  │    "session_id": "..." }      │                          │
  │<──────────────────────────────│                          │
  │                               │                          │
  │  [Shows QR code]              │                          │
  │                               │                          │
  │                               │  [User scans QR]         │
  │                               │<─────────────────────────│
  │                               │                          │
  │                               │  POST /auth/qr/validate  │
  │                               │<─────────────────────────│
  │                               │── Decrypt QR (AES-256-GCM)│
  │                               │── Verify HMAC signature   │
  │                               │── Verify IP binding       │
  │                               │  { "challenge": "..." }   │
  │                               │─────────────────────────>│
  │                               │                          │
  │                               │  [User approves]         │
  │                               │                          │
  │                               │  POST /auth/qr/approve   │
  │                               │<─────────────────────────│
  │                               │── Verify device signature │
  │                               │── Mark session approved   │
  │                               │                          │
  │  GET /auth/qr/status          │                          │
  │──────────────────────────────>│                          │
  │  { "status": "approved" }     │                          │
  │<──────────────────────────────│                          │
```

**QR Security:**
- AES-256-GCM encrypted (screenshot-proof)
- HMAC-signed (tamper-proof)
- IP-bound (same network required)
- 5 minute expiry
- One-time use

### 5. Push Notification

```
Desktop                         Server                    Mobile
  │                               │                          │
  │  POST /auth/push/begin        │                          │
  │  { "email": "alice@..." }     │                          │
  │──────────────────────────────>│                          │
  │                               │── Send push to devices   │
  │  { "request_id": "..." }      │─────────────────────────>│
  │<──────────────────────────────│                          │
  │                               │                          │
  │                               │  [User approves]         │
  │                               │                          │
  │                               │  POST /auth/push/approve │
  │                               │<─────────────────────────│
  │                               │── Verify device signature │
  │                               │                          │
  │  GET /auth/push/status        │                          │
  │──────────────────────────────>│                          │
  │  { "status": "approved" }     │                          │
  │<──────────────────────────────│                          │
```

---

## Session Management

```cpp
// Verify a session (use in middleware)
auto session = auth->verify_session(token);
if (!session) {
    // Invalid/expired token — reject request
    return 401;
}
// session.value.user_id — who is this user?
// session.value.email — their email
// session.value.username — their username (if set)
// session.value.device_id — which device authenticated

// Refresh before expiry
auto refreshed = auth->refresh_session(token);

// Logout (optionally revoke device)
auth->logout(token, true); // true = revoke device key
```

---

## Account Reset (No Password to Reset!)

Since there's no password, "reset" means replacing a lost device key:

```
1. User loses device → goes to reset page
2. Enters email → POST /auth/reset/begin
   → Server sends magic link (same response even for unknown emails)
3. User clicks link → registers NEW device key
4. Optionally: all old devices revoked (config: revoke_all_on_reset)
```

### Recovery Codes (The Safety Net)

```
After registration, generate 8 recovery codes:
  POST /auth/recovery/generate
  → ["EZONE-ABCD-EFGH-IJKL", "EZONE-MNOP-QRST-UVWX", ...]

User stores these offline (printed, password manager).

If ALL devices are lost:
  POST /auth/recovery/use
  { "email": "alice@...", "code": "EZONE-ABCD-EFGH-IJKL" }
  → Returns reset magic token → register new device
```

**Recovery codes are HMAC-hashed server-side — only hashes stored.**

---

## Security Properties

| Property | How |
|----------|-----|
| **No passwords stored** | Device keys are the authenticator |
| **No credential database** | Public keys only — private keys stay on device |
| **Phishing resistant** | WebAuthn binds to origin; QR is IP-bound |
| **Replay proof** | Challenges are HMAC-signed + time-limited |
| **Clone detection** | WebAuthn sign count enforcement |
| **Timing attack safe** | Constant-time comparison on all secrets |
| **Brute-force protected** | OTP: 3 attempts + 15 min lockout |
| **Forward secrecy** | Session tokens are stateless, verified per-request |
