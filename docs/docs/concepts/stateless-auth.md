---
id: stateless-auth
title: Stateless Authentication
---

# Stateless Authentication

ezone sessions require no server-side storage. This page explains exactly how that works.

## Session tokens

When a user completes login, ezone issues a compact signed token:

```
base64url(header) . base64url(payload) . base64url(signature)
```

**Header**
```json
{ "alg": "ES384", "typ": "EZONE-AT" }
```

**Payload**
```json
{
  "sub": "user_abc123",
  "iat": 1716000000,
  "exp": 1716003600,
  "jti": "4f9a2b..."
}
```

The signature is ECDSA P-384 over `header.payload` using the server's signing key. Any server instance that holds the server's public key can verify any token without contacting a central store.

## Verification flow

On every authenticated request:

```
Client                          Server
  │                               │
  │  GET /api/resource            │
  │  Authorization: Bearer <tok>  │
  │ ─────────────────────────────►│
  │                               │  1. Split token at dots
  │                               │  2. Verify ECDSA P-384 signature
  │                               │  3. Check exp > now
  │                               │  4. Extract sub (user_id)
  │                               │  5. Handle request
  │◄─────────────────────────────-│
```

Steps 1–4 are pure in-memory computation. No network call, no database query.

## Token refresh

Tokens have a configurable TTL (default 3600 seconds). Before expiry, the client calls `POST /v1/auth/session/refresh`:

1. Server verifies the existing token (same as above)
2. Issues a new token with a fresh `exp`
3. Returns the new token

The old token remains valid until its original `exp`. This is acceptable because:
- TTLs are short (default 1 hour)
- Tokens are opaque to the client — they contain no extractable secrets
- Device keys are the long-lived credential; tokens are ephemeral

## Logout

Because sessions are stateless, `POST /v1/auth/session/logout` is a **client-side operation** — the server endpoint exists as a hook for your application logic (audit logging, analytics) but does not invalidate anything on the server.

The client must discard the token and all copies of it. On the browser:

```typescript
// Clear token from memory and storage
localStorage.removeItem('ezone_token');
sessionStorage.removeItem('ezone_token');
```

## Revocation

For applications that require immediate revocation (e.g., compromised device), ezone's `StorageAdapter` interface can be extended to maintain a token blocklist. The built-in server does not implement a blocklist by default to preserve the stateless property.

Alternatively, revoking a device via `DELETE /v1/auth/devices/:id` prevents future logins from that device. Existing tokens issued to that device remain valid until their TTL expires (worst case: 1 hour with default settings).

## Challenge tokens

Login challenges also use HMAC-based stateless verification. The challenge wire format is:

```
nonce(16B) | issued_at(8B) | ttl(8B) | hmac(48B)
```

All packed as a single base64url string. The server re-computes the HMAC on verification — no challenge storage needed.

## Magic link tokens

Registration and password-reset magic links use the same stateless design:

```
nonce(16B) | purpose(1B) | expiry(8B) | user_id_len(2B) | user_id | hmac(48B)
```

The `purpose` byte prevents cross-purpose replay (a registration token cannot be used for reset). The HMAC binds the entire payload to the server's HMAC key.
