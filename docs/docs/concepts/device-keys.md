---
id: device-keys
title: Device Keys
---

# Device Keys

ezone's security model is built on **device-bound cryptographic keys**. Every device a user registers gets its own P-384 ECDSA keypair. The private key never leaves the device.

## Key lifecycle

```
Device                            Server
  │                                  │
  │  generate_keypair()              │
  │  → { private_key, public_key }   │
  │                                  │
  │  POST /auth/register/complete    │
  │  { magic_token, public_key }────►│ stores public_key
  │◄─────────────────────────────────│ { token }
  │                                  │
  │  (login later)                   │
  │  sign(challenge, private_key)    │
  │  POST /auth/login/complete       │
  │  { signature, public_key }──────►│ verify(signature, public_key)
  │◄─────────────────────────────────│ { token }
```

The server only ever sees the **public key**. The private key is generated on-device and stored in platform-specific secure storage.

## Platform storage

### Browser (WebCrypto)

```typescript
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-384' },
  false,           // non-extractable — cannot be exported from the browser
  ['sign', 'verify'],
);
// stored in IndexedDB as an opaque CryptoKey object
```

Because `extractable: false`, the private key cannot be read by JavaScript even in the same origin. Signing happens inside the browser's crypto subsystem.

### WebAuthn / FIDO2 (passkeys)

For platforms with a hardware authenticator (TouchID, FaceID, Windows Hello):

```typescript
const credential = await navigator.credentials.create({
  publicKey: {
    challenge,
    pubKeyCredParams: [{ type: 'public-key', alg: -35 }], // ES384
    authenticatorSelection: { residentKey: 'required' },
  },
});
```

The private key is generated and stored inside the authenticator's secure enclave. It **cannot** leave the hardware.

### iOS / macOS (CryptoKit)

```swift
let key = try P384.Signing.PrivateKey(compactRepresentable: false)
// or use SecureEnclave:
let key = try SecureEnclave.P256.Signing.PrivateKey()
```

Store the key in the iOS Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.

### Android (Keystore)

```kotlin
val keyPairGenerator = KeyPairGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
)
keyPairGenerator.initialize(
    KeyGenParameterSpec.Builder("ezone_key",
        KeyProperties.PURPOSE_SIGN)
        .setDigests(KeyProperties.DIGEST_SHA384)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp384r1"))
        .build()
)
val keyPair = keyPairGenerator.generateKeyPair()
```

Keys stored in the Android Keystore cannot be exported; signing operations happen inside the Trusted Execution Environment.

## Device ID

ezone derives a stable device identifier from the public key:

```
device_id = hex(SHA-384(public_key_der)[0..16])
```

This is a 32-character hex string that uniquely identifies a key without requiring the server to store a separate ID.

## Multi-device

Users can register multiple devices. Each device has its own keypair, its own device record, and can be independently revoked. Compromise of one device does not affect others.

## Revocation

```
DELETE /v1/auth/devices/:device_id
Authorization: Bearer <token>
```

Revocation marks the device record as inactive. Subsequent login attempts from that device fail at the `get_device` check before signature verification.

To revoke all devices (e.g., on account reset), set `revoke_all_on_reset: true` in `AuthConfig`.
