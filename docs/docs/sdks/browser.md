---
id: browser
title: Browser (WebCrypto + WebAuthn)
---

# Browser SDK

The Browser SDK runs entirely client-side. It manages device key generation, secure storage in IndexedDB, and WebAuthn/passkey flows.

## Installation

```bash
npm install @ezone/browser
```

Or via CDN:
```html
<script type="module">
  import { EzoneDevice } from 'https://cdn.jsdelivr.net/npm/@ezone/browser/dist/index.esm.js';
</script>
```

## Device keys (WebCrypto)

```typescript
import { EzoneDevice } from '@ezone/browser';

// Gets or creates a non-extractable P-384 key pair, stored in IndexedDB
const device = await EzoneDevice.getOrCreate('user_abc123');

// Export the public key (safe to send to server)
const publicKey = await device.getPublicKey(); // base64url SPKI DER

// Sign a challenge from the server
const signature = await device.signChallenge(challenge); // base64url
```

## Full login flow (React example)

```tsx
import { EzoneDevice } from '@ezone/browser';

async function login(email: string) {
  // 1. Get challenge from your server
  const { challenge } = await fetch('/api/auth/login/begin', {
    method: 'POST',
    body: JSON.stringify({ email }),
  }).then(r => r.json());

  // 2. Sign with device key (private key never leaves IndexedDB)
  const device = await EzoneDevice.getOrCreate(email);
  const signature = await device.signChallenge(challenge);
  const publicKey = await device.getPublicKey();

  // 3. Complete login on your server
  const { token } = await fetch('/api/auth/login/complete', {
    method: 'POST',
    body: JSON.stringify({ email, challenge, signature, device_public_key: publicKey }),
  }).then(r => r.json());

  // 4. Store token (memory or sessionStorage — never localStorage for high-security apps)
  sessionStorage.setItem('token', token);
}
```

## WebAuthn / Passkeys

For hardware-backed keys (TouchID, FaceID, Windows Hello):

```typescript
import { EzonePasskey } from '@ezone/browser';

// Registration
const { credential_id, public_key } = await EzonePasskey.register({
  challenge: '<base64url from server>',
  userId: 'user_abc123',
  userName: 'alice@example.com',
});

// Authentication
const { credential_id, signature, authenticator_data, client_data } =
  await EzonePasskey.authenticate({
    challenge: '<base64url from server>',
  });
```

Check platform support:
```typescript
const webAuthnAvailable = EzonePasskey.isSupported();
const platformKey = await EzonePasskey.isPlatformAuthenticatorAvailable();
```

## React integration

```tsx
import React, { useState } from 'react';
import { EzoneDevice } from '@ezone/browser';

export function LoginForm() {
  const [email, setEmail] = useState('');

  async function handleLogin() {
    const res = await fetch('/api/auth/login/begin', {
      method: 'POST', body: JSON.stringify({ email }),
      headers: { 'Content-Type': 'application/json' },
    });
    const { challenge } = await res.json();

    const device = await EzoneDevice.getOrCreate(email);
    const [signature, publicKey] = await Promise.all([
      device.signChallenge(challenge),
      device.getPublicKey(),
    ]);

    const loginRes = await fetch('/api/auth/login/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, challenge, signature, device_public_key: publicKey }),
    });
    const { token } = await loginRes.json();
    // store token and redirect
  }

  return (
    <form onSubmit={e => { e.preventDefault(); handleLogin(); }}>
      <input value={email} onChange={e => setEmail(e.target.value)} type="email" />
      <button type="submit">Sign in</button>
    </form>
  );
}
```

## Security notes

- Private keys are generated with `extractable: false` — they cannot be read by any JavaScript code
- Keys are stored in IndexedDB, scoped to your origin — other origins cannot access them
- For maximum security, use WebAuthn passkeys which store keys in hardware secure enclave
