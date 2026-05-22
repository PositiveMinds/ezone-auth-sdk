/**
 * EzoneSecureDevice — production-safe device key manager.
 *
 * Automatically selects the strongest available key storage:
 *
 *   1. WebAuthn platform authenticator (TouchID, FaceID, Windows Hello, YubiKey)
 *      Keys live in hardware secure enclave — never accessible to JavaScript,
 *      immune to XSS. REQUIRED user gesture before every signing operation.
 *
 *   2. WebCrypto + IndexedDB fallback (when WebAuthn unavailable)
 *      Non-extractable key: the raw bytes cannot be exported, but malicious
 *      JavaScript executing on the same origin during an active session could
 *      call sign(). Mitigate with a strong CSP.
 *
 * For production environments: always prefer passkeys. The fallback exists only
 * for environments where WebAuthn is unavailable (headless test runners, some
 * embedded WebViews). Log a console warning when the fallback path is taken so
 * your monitoring can detect it.
 */

import { EzoneDevice }  from './device.js';
import { EzonePasskey, PasskeyOptions } from './webauthn.js';
import { base64urlEncode }              from './utils.js';

export type KeyBackend = 'passkey' | 'webcrypto';

export interface SecureDeviceResult {
  backend:   KeyBackend;
  publicKey: string;   // base64url SPKI DER — send to server
  /** Only present when backend = 'passkey' — store this client-side */
  credentialId?: string;
  sign(challengeBase64url: string): Promise<string>;
}

export interface SecureDeviceOptions {
  passkeyOpts?: PasskeyOptions;
  /** If true, throw instead of falling back to WebCrypto when passkeys unavailable */
  requirePasskey?: boolean;
}

/**
 * Get or create a secure device key for *userId*.
 *
 * Pass *registering = true* the first time (during registration) so the
 * passkey prompt appears. On subsequent logins, pass false — the existing
 * credential will be used.
 */
export async function getSecureDevice(
  userId:      string,
  userEmail:   string,
  registering: boolean,
  opts:        SecureDeviceOptions = {},
): Promise<SecureDeviceResult> {
  const passkeySupported = EzonePasskey.isSupported();
  const platformAvail    = passkeySupported
    ? await EzonePasskey.isPlatformAuthenticatorAvailable()
    : false;

  if (platformAvail && opts.passkeyOpts) {
    // ── WebAuthn passkey path (preferred) ──────────────────────────────
    const passkey = new EzonePasskey(opts.passkeyOpts);

    if (registering) {
      const result = await passkey.register(userId, userEmail);
      const { publicKey, credentialId } = result;

      return {
        backend:      'passkey',
        publicKey,
        credentialId,
        sign: async (challenge: string) => {
          const auth = await passkey.authenticate(challenge, [credentialId]);
          return auth.signature;
        },
      };
    } else {
      // Load stored credentialId from sessionStorage so we can target it.
      const stored = sessionStorage.getItem(`ezone_cid_${userId}`);
      const credIds = stored ? [stored] : undefined;

      return {
        backend:  'passkey',
        publicKey: '',  // filled in after authenticate()
        sign: async (challenge: string) => {
          const auth = await passkey.authenticate(challenge, credIds);
          // Update stored credId if we got one back
          if (auth.credentialId) {
            sessionStorage.setItem(`ezone_cid_${userId}`, auth.credentialId);
          }
          return auth.signature;
        },
      };
    }
  }

  if (opts.requirePasskey) {
    throw new Error(
      'ezone: passkey required but platform authenticator is unavailable. ' +
      'Ensure the user is on a device with biometrics or a hardware key.'
    );
  }

  // ── WebCrypto + IndexedDB fallback ──────────────────────────────────────
  console.warn(
    '[ezone] WebAuthn platform authenticator unavailable. ' +
    'Falling back to WebCrypto + IndexedDB. ' +
    'This is less secure — ensure your Content-Security-Policy is strict.'
  );

  const device = await EzoneDevice.getOrCreate(userId);
  return {
    backend:   'webcrypto',
    publicKey: await device.getPublicKey(),
    sign:      (challenge: string) => device.signChallenge(challenge),
  };
}

/**
 * Convenience: store the credential ID after passkey registration so it can
 * be retrieved on the next login without asking the server.
 */
export function storeCredentialId(userId: string, credentialId: string): void {
  sessionStorage.setItem(`ezone_cid_${userId}`, credentialId);
}

export function getStoredCredentialId(userId: string): string | null {
  return sessionStorage.getItem(`ezone_cid_${userId}`);
}
