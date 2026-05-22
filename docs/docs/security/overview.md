---
id: overview
title: Security Overview
---

# Security Overview

## What ezone protects against

| Threat | How ezone addresses it |
|---|---|
| **Credential stuffing** | No passwords exist — there is nothing to stuff |
| **Phishing** | Device keys are origin-bound; a fake site cannot extract them |
| **Database breach** | No password hashes stored; public keys are non-secret |
| **Replay attacks** | Challenges are single-use with 30s TTL and a nonce |
| **MITM token theft** | Tokens are short-lived (1h default); require TLS |
| **Brute force** | Challenge–response requires a valid private key |
| **User enumeration** | `beginReset` always returns success for any email |
| **Cross-purpose token misuse** | Magic link `purpose` byte prevents registration token reuse for reset |

## Trust model

- **The server** holds the HMAC key and token signing key. These are the only secrets. Protect them as you would a private key.
- **The client device** holds the P-384 private key. Only the user's device can authenticate as that device.
- **The server never learns the user's private key.** Even in a full server compromise, an attacker cannot impersonate a user on a device they don't control.

## Token security properties

Session tokens are ES384-signed JWTs:
- Short-lived (default 1 hour)
- Include a `jti` nonce to prevent trivial forgery detection bypass
- Cannot be extended without the server's signing key
- Verification is stateless — no DB lookup needed

## What ezone does NOT provide

- **Rate limiting** — implement at your reverse proxy or API gateway
- **IP allowlisting** — implement at your infrastructure layer
- **Audit logging** — hook into server request logs
- **Token revocation list** — the stateless design trades revocation for scalability; extend `StorageAdapter` for a blocklist if needed

## Reporting vulnerabilities

Please report security issues to security@ezone.dev or via [GitHub private advisory](https://github.com/ezone-sdk/ezone-sdk/security/advisories/new).
