/** base64url encode (no padding, URL-safe alphabet) */
export function base64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/** base64url decode */
export function base64urlDecode(encoded: string): Uint8Array {
  const padded = encoded.replace(/-/g, '+').replace(/_/g, '/')
    + '=='.slice(0, (4 - (encoded.length % 4)) % 4);
  const binary = atob(padded);
  const bytes   = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Encode an ArrayBuffer as base64url */
export function bufToB64url(buf: ArrayBuffer): string {
  return base64urlEncode(new Uint8Array(buf));
}

/** Concatenate two Uint8Arrays */
export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Convert a raw P-384 point (x, y each 48 bytes) to a
 * SubjectPublicKeyInfo DER structure (what ezone expects).
 *
 * DER structure:
 *   SEQUENCE {
 *     SEQUENCE { OID ecPublicKey, OID secp384r1 }
 *     BIT STRING { 0x04 | x | y }
 *   }
 */
export function p384PointToDer(x: Uint8Array, y: Uint8Array): Uint8Array {
  // OID 1.2.840.10045.2.1 (ecPublicKey)
  const oidEcPubkey = new Uint8Array([
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  ]);
  // OID 1.3.132.0.34 (secp384r1)
  const oidP384 = new Uint8Array([
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
  ]);

  // algorithmIdentifier SEQUENCE
  const algId = derSequence(concat(oidEcPubkey, oidP384));

  // uncompressed point: 0x04 | x | y
  const point = new Uint8Array(1 + 48 + 48);
  point[0] = 0x04;
  point.set(x, 1);
  point.set(y, 49);

  // BIT STRING: 0x00 (no unused bits) | point
  const bitString = new Uint8Array(1 + point.length);
  bitString[0] = 0x00;
  bitString.set(point, 1);
  const bsWrapped = derTag(0x03, bitString);

  // Outer SEQUENCE
  return derSequence(concat(algId, bsWrapped));
}

function derLen(n: number): Uint8Array {
  if (n < 0x80) return new Uint8Array([n]);
  if (n < 0x100) return new Uint8Array([0x81, n]);
  return new Uint8Array([0x82, (n >> 8) & 0xff, n & 0xff]);
}

function derTag(tag: number, content: Uint8Array): Uint8Array {
  const len = derLen(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}

function derSequence(content: Uint8Array): Uint8Array {
  return derTag(0x30, content);
}

/**
 * Export a Web Crypto P-384 CryptoKey to SubjectPublicKeyInfo DER bytes.
 * Uses the browser's built-in spki export which already gives us SPKI DER.
 */
export async function exportPublicKeyDer(key: CryptoKey): Promise<Uint8Array> {
  const spki = await crypto.subtle.exportKey('spki', key);
  return new Uint8Array(spki);
}
