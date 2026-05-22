---
id: api-reference
title: API Reference
---

# API Reference

Base URL: `http(s)://<host>/v1`

All requests and responses use `Content-Type: application/json`. Authenticated endpoints require:

```
Authorization: Bearer <session_token>
```

---

## Health

### `GET /health`

Returns server status.

**Response 200**
```json
{ "status": "ok", "fips": false }
```

---

## Registration

### `POST /auth/register/begin`

Request a registration magic link for an email address.

**Body**
```json
{ "email": "alice@example.com" }
```

**Response 200**
```json
{ "magic_token": "EZONE-..." }
```

The `magic_token` is opaque — deliver it out-of-band (email link, SMS, etc.) to the user. It expires after 15 minutes by default.

---

### `POST /auth/register/complete`

Complete registration by providing the device's public key.

**Body**
```json
{
  "magic_token": "EZONE-...",
  "device_public_key": "<base64url SPKI DER>",
  "device_name": "Alice's MacBook"
}
```

**Response 200**
```json
{
  "token": "eyJhbGci.....",
  "expires_at": 1716003600,
  "user_id": "usr_abc123",
  "device_id": "a1b2c3d4..."
}
```

---

## Login

### `POST /auth/login/begin`

Get a challenge for a registered email.

**Body**
```json
{ "email": "alice@example.com" }
```

**Response 200**
```json
{ "challenge": "<base64url>" }
```

The challenge includes a nonce, timestamp, and TTL; it is valid for 30 seconds.

---

### `POST /auth/login/complete`

Submit the device signature over the challenge.

**Body**
```json
{
  "email": "alice@example.com",
  "challenge": "<base64url>",
  "signature": "<base64url ECDSA-P384 signature>",
  "device_public_key": "<base64url SPKI DER>"
}
```

**Response 200**
```json
{
  "token": "eyJhbGci.....",
  "expires_at": 1716003600,
  "user_id": "usr_abc123"
}
```

**Error 401** — invalid signature, expired challenge, or unregistered device.

---

## Session

### `GET /auth/session`

Verify the current session and retrieve user info.

**Headers**: `Authorization: Bearer <token>`

**Response 200**
```json
{
  "user_id": "usr_abc123",
  "email": "alice@example.com",
  "expires_at": 1716003600
}
```

---

### `POST /auth/session/refresh`

Issue a new session token, extending the expiry.

**Headers**: `Authorization: Bearer <token>`

**Response 200**
```json
{
  "token": "eyJhbGci.....",
  "expires_at": 1716007200
}
```

---

### `POST /auth/session/logout`

Client-side logout hook. The token is not invalidated server-side (stateless); the client must discard it.

**Headers**: `Authorization: Bearer <token>`

**Response 200**
```json
{ "ok": true }
```

---

## Password Reset (Account Recovery)

### `POST /auth/reset/begin`

Request a reset magic link. Always returns 200, even for unknown emails, to prevent user enumeration.

**Body**
```json
{ "email": "alice@example.com" }
```

**Response 200**
```json
{ "magic_token": "EZONE-..." }
```

---

### `POST /auth/reset/complete`

Complete account reset by registering a new device key.

**Body**
```json
{
  "magic_token": "EZONE-...",
  "device_public_key": "<base64url SPKI DER>",
  "device_name": "Alice's new device"
}
```

**Response 200**
```json
{
  "token": "eyJhbGci.....",
  "expires_at": 1716003600,
  "user_id": "usr_abc123"
}
```

---

## Recovery Codes

### `POST /auth/recovery/generate`

Generate a set of single-use recovery codes (default 8 codes).

**Headers**: `Authorization: Bearer <token>`

**Response 200**
```json
{
  "codes": [
    "EZONE-A1B2-C3D4-E5F6",
    "EZONE-G7H8-I9J0-K1L2",
    "..."
  ]
}
```

Store these securely. Each code can only be used once.

---

### `POST /auth/recovery/use`

Authenticate using a recovery code when all devices are lost.

**Body**
```json
{
  "email": "alice@example.com",
  "code": "EZONE-A1B2-C3D4-E5F6",
  "device_public_key": "<base64url SPKI DER>",
  "device_name": "Recovery device"
}
```

**Response 200**
```json
{
  "token": "eyJhbGci.....",
  "expires_at": 1716003600
}
```

---

## Devices

### `GET /auth/devices`

List all registered devices for the authenticated user.

**Headers**: `Authorization: Bearer <token>`

**Response 200**
```json
{
  "devices": [
    {
      "device_id": "a1b2c3d4...",
      "device_name": "Alice's MacBook",
      "registered_at": 1716000000
    }
  ]
}
```

---

### `POST /auth/devices/add/begin`

Start adding a new device to an existing account.

**Headers**: `Authorization: Bearer <token>`

**Response 200**
```json
{ "magic_token": "EZONE-..." }
```

---

### `POST /auth/devices/add/complete`

Complete adding a new device.

**Body**
```json
{
  "magic_token": "EZONE-...",
  "device_public_key": "<base64url SPKI DER>",
  "device_name": "Alice's iPhone"
}
```

**Response 200**
```json
{
  "device_id": "e5f6g7h8...",
  "device_name": "Alice's iPhone"
}
```

---

### `DELETE /auth/devices/:device_id`

Revoke a device. After revocation, login attempts from that device are rejected.

**Headers**: `Authorization: Bearer <token>`

**Response 200**
```json
{ "ok": true }
```

---

## Error responses

All errors follow this shape:

```json
{ "error": "human-readable message" }
```

| HTTP status | Meaning |
|---|---|
| 400 | Missing or malformed request body |
| 401 | Invalid token, expired challenge, or bad signature |
| 404 | Resource not found (user, device) |
| 500 | Internal server error |
