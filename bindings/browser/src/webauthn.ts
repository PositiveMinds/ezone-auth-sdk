/**
 * EzonePasskey — hardware-backed authentication using WebAuthn/FIDO2.
 *
 * Unlike EzoneDevice (which stores keys in IndexedDB), passkeys are managed
 * by the OS/browser and are backed by the device's Secure Enclave or TPM.
 * Private keys are never accessible to JavaScript — only signing is possible.
 *
 * Use this class when you want the strongest possible security guarantees.
 * Passkeys sync across devices via iCloud Keychain, Google Password Manager,
 * or Windows Hello depending on the platform.
 *
 * Flow overview:
 *   Registration : EzonePasskey.register()  → public key → server
 *   Login        : EzonePasskey.authenticate() → signed challenge → server
 */

import { bufToB64url, base64urlDecode, base64urlEncode } from './utils.js';

// COSE algorithm identifier for ES384 (ECDSA w/ P-384 and SHA-384)
const COSE_ES384 = -35;


// ─── COSE → SPKI conversion ──────────────────────────────────────────────────

/**
 * Extract the SubjectPublicKeyInfo DER from a WebAuthn authenticatorData blob.
 *
 * authenticatorData layout:
 *   rpIdHash (32)  | flags (1) | signCount (4) | aaguid (16) |
 *   credIdLen (2)  | credId (credIdLen) | COSE public key (CBOR)
 */
export function extractSpkiFromAuthData(authData: ArrayBuffer): Uint8Array {
  const buf = new Uint8Array(authData);

  // Skip: rpIdHash(32) + flags(1) + signCount(4) + aaguid(16)
  let offset = 55;

  const credIdLen = (buf[offset]! << 8) | buf[offset + 1]!;
  offset += 2 + credIdLen;

  // The remaining bytes are a CBOR-encoded COSE EC2 key map.
  // Minimal COSE EC2 parser for P-384:
  //   { 1: 2, 3: -35, -1: 2 (P-384), -2: x(48), -3: y(48) }
  const cose = buf.slice(offset);
  return parseCoseEcKey(cose);
}

/**
 * Parse a CBOR COSE EC2 key and return SubjectPublicKeyInfo DER.
 * Only handles the subset used by WebAuthn (definite-length CBOR map).
 */
function parseCoseEcKey(cose: Uint8Array): Uint8Array {
  // Simple CBOR decoder for the specific shape WebAuthn produces
  let pos = 0;

  function readByte(): number { return cose[pos++]!; }

  function readLen(additionalInfo: number): number {
    if (additionalInfo < 24) return additionalInfo;
    if (additionalInfo === 24) return readByte();
    if (additionalInfo === 25) {
      const hi = readByte(); const lo = readByte();
      return (hi << 8) | lo;
    }
    throw new Error('CBOR length too large');
  }

  function decodeItem(): unknown {
    const ib  = readByte();
    const mt  = (ib & 0xe0) >> 5;  // major type
    const ai  = ib & 0x1f;         // additional info

    if (mt === 0) return readLen(ai);                    // unsigned int
    if (mt === 1) return -(1 + readLen(ai));             // negative int
    if (mt === 2) {                                       // byte string
      const n = readLen(ai);
      const v = cose.slice(pos, pos + n); pos += n;
      return v;
    }
    if (mt === 3) {                                       // text string
      const n = readLen(ai);
      const v = new TextDecoder().decode(cose.slice(pos, pos + n));
      pos += n; return v;
    }
    if (mt === 5) {                                       // map
      const n = readLen(ai);
      const m = new Map<number, unknown>();
      for (let i = 0; i < n; i++) {
        const k = decodeItem() as number;
        const v = decodeItem();
        m.set(k, v);
      }
      return m;
    }
    throw new Error(`Unsupported CBOR major type: ${mt}`);
  }

  const map = decodeItem() as Map<number, unknown>;

  const x = map.get(-2) as Uint8Array;
  const y = map.get(-3) as Uint8Array;

  if (!x || !y || x.length !== 48 || y.length !== 48)
    throw new Error('Invalid COSE P-384 key: expected 48-byte x and y');

  return buildSpki(x, y);
}

/** Build SubjectPublicKeyInfo DER from raw P-384 x,y coordinates */
function buildSpki(x: Uint8Array, y: Uint8Array): Uint8Array {
  // OID 1.2.840.10045.2.1  (id-ecPublicKey)
  const oidEcPk = new Uint8Array([0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01]);
  // OID 1.3.132.0.34        (secp384r1)
  const oidP384 = new Uint8Array([0x06,0x05,0x2b,0x81,0x04,0x00,0x22]);

  const algId   = derSeq(cat(oidEcPk, oidP384));
  const point   = new Uint8Array([0x04, ...x, ...y]);
  const bitStr  = derTag(0x03, new Uint8Array([0x00, ...point]));

  return derSeq(cat(algId, bitStr));
}

// DER helpers
function derTag(tag: number, v: Uint8Array): Uint8Array {
  const l = derLen(v.length);
  const r = new Uint8Array(1 + l.length + v.length);
  r[0] = tag; r.set(l, 1); r.set(v, 1 + l.length); return r;
}
function derSeq(v: Uint8Array): Uint8Array { return derTag(0x30, v); }
function derLen(n: number): Uint8Array {
  if (n < 0x80) return new Uint8Array([n]);
  if (n < 0x100) return new Uint8Array([0x81, n]);
  return new Uint8Array([0x82, (n >> 8) & 0xff, n & 0xff]);
}
function cat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const r = new Uint8Array(a.length + b.length);
  r.set(a); r.set(b, a.length); return r;
}


// ─── EzonePasskey ─────────────────────────────────────────────────────────────

export interface PasskeyRegistrationResult {
  /** base64url SPKI DER — send to server as public_key */
  publicKey:    string;
  /** opaque credential ID — store client-side for future logins */
  credentialId: string;
}

export interface PasskeyAuthResult {
  /** base64url DER signature — send to server as signature */
  signature:    string;
  /** base64url SPKI DER — send to server as public_key */
  publicKey:    string;
  /** opaque credential ID */
  credentialId: string;
}

export interface PasskeyOptions {
  rpId:    string;   // relying party domain, e.g. "yourapp.com"
  rpName:  string;   // human-readable name,  e.g. "Your App"
}

export class EzonePasskey {
  constructor(private readonly opts: PasskeyOptions) {}

  /**
   * Register a new passkey for *userId* / *userEmail*.
   * Returns the public key to send to the ezone server to complete registration.
   *
   * The browser will prompt the user to authenticate (biometric / PIN).
   */
  async register(
    userId: string,
    userEmail: string,
    challenge?: Uint8Array,
  ): Promise<PasskeyRegistrationResult> {
    if (!challenge) challenge = crypto.getRandomValues(new Uint8Array(32));

    const credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp:   { id: this.opts.rpId, name: this.opts.rpName },
        user: {
          id:          new TextEncoder().encode(userId),
          name:        userEmail,
          displayName: userEmail,
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: COSE_ES384 },   // P-384 preferred
          { type: 'public-key', alg: -7 },            // P-256 fallback
        ],
        authenticatorSelection: {
          userVerification: 'required',
          residentKey:      'preferred',
        },
        timeout: 60_000,
      },
    }) as PublicKeyCredential | null;

    if (!credential) throw new Error('Passkey creation cancelled');

    const response = credential.response as AuthenticatorAttestationResponse;
    const authData = response.getAuthenticatorData();
    const spki     = extractSpkiFromAuthData(authData);

    return {
      publicKey:    base64urlEncode(spki),
      credentialId: base64urlEncode(new Uint8Array(credential.rawId)),
    };
  }

  /**
   * Authenticate using a passkey.
   * *challengeBase64url* is the challenge bytes returned by the ezone server.
   * Returns the signature + public key to complete login.
   *
   * The browser will prompt the user to authenticate (biometric / PIN).
   */
  async authenticate(
    challengeBase64url: string,
    credentialIds?: string[],
  ): Promise<PasskeyAuthResult> {
    const challengeBytes = base64urlDecode(challengeBase64url);

    const allowCreds: PublicKeyCredentialDescriptor[] | undefined =
      credentialIds?.map(id => ({
        type: 'public-key' as const,
        id:   base64urlDecode(id).buffer,
      }));

    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge:          challengeBytes,
        allowCredentials:   allowCreds,
        userVerification:   'required',
        timeout:            60_000,
      },
    }) as PublicKeyCredential | null;

    if (!assertion) throw new Error('Passkey authentication cancelled');

    const response    = assertion.response as AuthenticatorAssertionResponse;
    const authData    = new Uint8Array(response.authenticatorData);
    const clientData  = new Uint8Array(response.clientDataJSON);
    const sigBytes    = new Uint8Array(response.signature);

    // ezone verifies the raw ECDSA signature over the challenge bytes.
    // WebAuthn signatures cover: authData | SHA-256(clientData)
    // We build the same signed payload so the server can verify it.
    const clientHash  = new Uint8Array(
      await crypto.subtle.digest('SHA-256', clientData));
    const signedData  = cat(authData, clientHash);

    // For WebAuthn we also need the public key — try userHandle or
    // re-derive from stored credential. Here we re-export from the
    // assertion's public key if available (getPublicKey() is a newer API).
    let publicKeyB64 = '';
    if (typeof (response as any).getPublicKey === 'function') {
      const spkiDer = (response as any).getPublicKey() as ArrayBuffer | null;
      if (spkiDer) publicKeyB64 = bufToB64url(spkiDer);
    }

    return {
      signature:    base64urlEncode(sigBytes),
      publicKey:    publicKeyB64,
      credentialId: base64urlEncode(new Uint8Array(assertion.rawId)),
    };
  }

  /** True if the browser supports WebAuthn passkeys */
  static isSupported(): boolean {
    return (
      typeof window !== 'undefined' &&
      typeof window.PublicKeyCredential !== 'undefined' &&
      typeof navigator.credentials?.create === 'function'
    );
  }

  /** True if platform authenticator (Touch ID, Face ID, Windows Hello) is available */
  static async isPlatformAuthenticatorAvailable(): Promise<boolean> {
    if (!EzonePasskey.isSupported()) return false;
    try {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      return false;
    }
  }
}
