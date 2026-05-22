---
id: getting-started
title: Getting Started
sidebar_position: 2
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Getting Started

This guide gets you from zero to a working passwordless auth flow in under 5 minutes.

## 1 — Start the server

The fastest way to run ezone is via Docker:

```bash
docker run -p 8080:8080 \
  -e EZONE_SESSION_TTL=3600 \
  -e EZONE_CHALLENGE_TTL=30 \
  ghcr.io/ezone-sdk/ezone-server:latest
```

Verify it's running:

```bash
curl http://localhost:8080/v1/health
# {"status":"ok","fips":false}
```

:::info Self-hosting
For production deployments with TLS, custom storage adapters, and environment configuration see the [Self-Hosting guide](/docs/self-hosting/server).
:::

## 2 — Install the client SDK

<Tabs>
<TabItem value="nodejs" label="Node.js">

```bash
npm install ezone-sdk
```

</TabItem>
<TabItem value="python" label="Python">

```bash
pip install ezone-sdk
```

</TabItem>
<TabItem value="go" label="Go">

```bash
go get github.com/ezone-sdk/ezone-go
```

</TabItem>
<TabItem value="rust" label="Rust">

```toml title="Cargo.toml"
[dependencies]
ezone = "0.1"
```

</TabItem>
</Tabs>

## 3 — Registration flow

Registration works in two steps: request a magic link, then complete registration with the device's public key.

<Tabs>
<TabItem value="nodejs" label="Node.js">

```typescript
import { EzoneClient } from 'ezone-sdk';

const ezone = new EzoneClient({ baseUrl: 'http://localhost:8080' });

// Step 1: Request magic link (you email this token to the user)
const { magic_token } = await ezone.beginRegistration({ email: 'alice@example.com' });

// Step 2: User clicks link → your app completes registration
//         The device public key is generated client-side and sent once
const session = await ezone.completeRegistration({
  magic_token,
  device_public_key: '<base64url-SPKI-DER>',
  device_name: 'Alice's MacBook',
});

console.log(session.token); // ES384-signed session token
```

</TabItem>
<TabItem value="python" label="Python">

```python
from ezone import EzoneClient

client = EzoneClient(base_url='http://localhost:8080')

# Step 1: Request magic link
result = client.begin_registration(email='alice@example.com')
magic_token = result['magic_token']

# Step 2: Complete registration
session = client.complete_registration(
    magic_token=magic_token,
    device_public_key='<base64url-SPKI-DER>',
    device_name="Alice's Laptop",
)
print(session['token'])
```

</TabItem>
<TabItem value="go" label="Go">

```go
package main

import (
    "context"
    "fmt"
    ezone "github.com/ezone-sdk/ezone-go"
)

func main() {
    client := ezone.NewClient("http://localhost:8080")

    // Step 1: Request magic link
    reg, err := client.BeginRegistration(context.Background(), ezone.BeginRegistrationRequest{
        Email: "alice@example.com",
    })
    if err != nil { panic(err) }

    // Step 2: Complete registration
    session, err := client.CompleteRegistration(context.Background(), ezone.CompleteRegistrationRequest{
        MagicToken:      reg.MagicToken,
        DevicePublicKey: "<base64url-SPKI-DER>",
        DeviceName:      "Alice's MacBook",
    })
    fmt.Println(session.Token)
}
```

</TabItem>
</Tabs>

## 4 — Login flow

After registration, login is a cryptographic challenge–response:

<Tabs>
<TabItem value="nodejs" label="Node.js">

```typescript
// Step 1: Get a challenge for the user's email
const { challenge } = await ezone.beginLogin({ email: 'alice@example.com' });

// Step 2: Sign the challenge with the device's private key (client-side)
const signature = await deviceKey.sign(challenge); // your crypto layer

// Step 3: Submit the signed challenge
const session = await ezone.completeLogin({
  email: 'alice@example.com',
  challenge,
  signature,
  device_public_key: '<base64url-SPKI-DER>',
});

// session.token is your bearer token for subsequent API calls
```

</TabItem>
<TabItem value="python" label="Python">

```python
# Step 1: Get a challenge
result = client.begin_login(email='alice@example.com')
challenge = result['challenge']

# Step 2: Sign challenge with device key (your code)
signature = device_key.sign(challenge)

# Step 3: Submit
session = client.complete_login(
    email='alice@example.com',
    challenge=challenge,
    signature=signature,
    device_public_key='<base64url-SPKI-DER>',
)
```

</TabItem>
</Tabs>

## 5 — Verify sessions

Pass the session token as a bearer header on protected routes. Verify server-side:

<Tabs>
<TabItem value="nodejs" label="Node.js">

```typescript
// Middleware / route handler
const info = await ezone.verifySession(req.headers.authorization?.replace('Bearer ', ''));
console.log(info.user_id, info.expires_at);
```

</TabItem>
<TabItem value="python" label="Python">

```python
token = request.headers.get('Authorization', '').removeprefix('Bearer ')
info = client.verify_session(token)
print(info['user_id'], info['expires_at'])
```

</TabItem>
</Tabs>

## Session lifecycle

| Action | Endpoint | Effect |
|---|---|---|
| Issue session | `POST /v1/auth/login/complete` | Returns signed token (default 1h TTL) |
| Verify | `GET /v1/auth/session` | Validates signature + expiry, returns user info |
| Refresh | `POST /v1/auth/session/refresh` | Issues new token, extends expiry |
| Logout | `POST /v1/auth/session/logout` | Client discards token (stateless — no server action needed) |

Sessions are **stateless**: the token itself carries all the information needed for verification. The server checks the ECDSA signature and expiry on every request without any database lookup. For details see [Core Concepts: Stateless Auth](/docs/concepts/stateless-auth).

## Next steps

- [API Reference](/docs/api-reference) — all endpoint signatures
- [SDK guides](/docs/sdks) — platform-specific integration patterns
- [Security overview](/docs/security/overview) — threat model and security properties
