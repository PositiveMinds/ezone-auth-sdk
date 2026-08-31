# @ezone/browser

Browser client for [ezone](https://github.com/ezone-sdk/ezone-sdk) — device-key
generation and signing for passwordless authentication, using WebAuthn passkeys
(hardware-backed) with a WebCrypto + IndexedDB fallback.

This package only handles the client-side device key. Pair it with a server
SDK (or raw REST calls) to talk to your `ezone-server` instance.

## Install

```bash
npm install @ezone/browser
```

## Usage (recommended)

`getSecureDevice()` automatically uses a WebAuthn passkey when the browser/
platform supports one, and falls back to a non-extractable WebCrypto key in
IndexedDB otherwise.

```ts
import { getSecureDevice, storeCredentialId } from '@ezone/browser';

// Registration
const device = await getSecureDevice(userId, email, /* isRegistration */ true, {
  passkeyOpts: { rpId: 'yourapp.com', rpName: 'Your App' },
});
if (device.credentialId) storeCredentialId(userId, device.credentialId);
// device.publicKey → send to your ezone server

// Login
const device = await getSecureDevice(userId, email, /* isRegistration */ false, {
  passkeyOpts: { rpId: 'yourapp.com', rpName: 'Your App' },
});
const signature = await device.sign(challengeBytes);
```

## Lower-level APIs

- `EzonePasskey` — WebAuthn/FIDO2 passkeys directly
- `EzoneDevice` — WebCrypto + IndexedDB (non-extractable key, no biometric prompt)
- `base64urlEncode` / `base64urlDecode` / `bufToB64url` / `exportPublicKeyDer` — utilities

## License

MIT — see [LICENSE](./LICENSE).
