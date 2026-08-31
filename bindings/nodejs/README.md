# ezone-sdk

Node.js / TypeScript client for [ezone](https://github.com/ezone-sdk/ezone-sdk) —
a passwordless authentication server built on P-384 ECDSA device keys,
stateless signed tokens, and no stored passwords.

This package is a thin HTTP client. It talks to a running `ezone-server`
instance (self-hosted, via Docker, or embedded via the C API) — it does not
run any auth logic itself.

## Install

```bash
npm install ezone-sdk
```

## Usage

```ts
import { EzoneClient } from 'ezone-sdk';

const ezone = new EzoneClient({ baseUrl: 'http://localhost:8080' });

// Registration — sends a magic link to the user's email
const { magic_token } = await ezone.beginRegistration('alice@example.com');

// After the user clicks the link and their device generates a P-384 keypair:
const session = await ezone.completeRegistration(magic_token, devicePublicKeyB64);

// Login — challenge/response, no password
const { challenge } = await ezone.beginLogin('alice@example.com');
// ... client signs `challenge` with the device's private key (never transmitted) ...
const loggedIn = await ezone.completeLogin(challenge, signature, devicePublicKeyB64);

// Verify a session in middleware
const info = await ezone.verifySession(loggedIn.token);
```

## What's covered

This client currently wraps the core challenge-response flow: registration,
login, session verification/refresh, logout, account reset, recovery codes,
and multi-device management.

It does **not** yet wrap the newer server-side auth methods — WebAuthn/passkeys,
QR cross-device login, push approval, OTP, or biometric login. Those are
reachable directly over the server's REST API (see the
[Developer Guide](https://github.com/ezone-sdk/ezone-sdk/blob/main/docs/DEVELOPER_GUIDE.md))
but don't yet have a typed method on `EzoneClient`. Contributions welcome.

## License

MIT — see [LICENSE](./LICENSE).
