/**
 * ezone browser SDK
 *
 * PRODUCTION RECOMMENDATION: use getSecureDevice() — it automatically selects
 * WebAuthn passkeys (hardware-backed) when available, and falls back to
 * WebCrypto + IndexedDB only when passkeys are unavailable.
 *
 * ─── Recommended (production) ────────────────────────────────────────────────
 *
 *   import { getSecureDevice, storeCredentialId } from '@ezone/browser';
 *
 *   // Registration
 *   const device = await getSecureDevice(userId, email, true, {
 *     passkeyOpts: { rpId: 'yourapp.com', rpName: 'Your App' },
 *   });
 *   if (device.credentialId) storeCredentialId(userId, device.credentialId);
 *   // device.publicKey → send to server
 *
 *   // Login
 *   const device = await getSecureDevice(userId, email, false, {
 *     passkeyOpts: { rpId: 'yourapp.com', rpName: 'Your App' },
 *   });
 *   const signature = await device.sign(challenge);
 *
 * ─── Lower-level APIs ────────────────────────────────────────────────────────
 *
 *   EzonePasskey — WebAuthn/FIDO2 passkeys directly
 *   EzoneDevice  — WebCrypto + IndexedDB (non-extractable key, no biometrics)
 */

// ── Recommended production API ────────────────────────────────────────────────
export { getSecureDevice, storeCredentialId,
         getStoredCredentialId }               from './secure-device.js';
export type { SecureDeviceResult,
              SecureDeviceOptions,
              KeyBackend }                     from './secure-device.js';

// ── Lower-level APIs ──────────────────────────────────────────────────────────
export { EzonePasskey }                        from './webauthn.js';
export { EzoneDevice }                         from './device.js';

// ── Utilities ─────────────────────────────────────────────────────────────────
export { base64urlEncode, base64urlDecode,
         bufToB64url, exportPublicKeyDer }     from './utils.js';

export type { PasskeyRegistrationResult,
              PasskeyAuthResult,
              PasskeyOptions }                 from './webauthn.js';
