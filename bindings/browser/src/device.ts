/**
 * EzoneDevice — manages a P-384 keypair in the browser.
 *
 * Keys are generated using the Web Crypto API (non-extractable private key)
 * and persisted in IndexedDB so they survive page reloads.
 *
 * On platforms with a Secure Enclave or TPM the private key operations
 * may be hardware-backed automatically (Chrome/Edge on Windows with
 * platform keys enabled, Safari on Apple Silicon, etc.).
 */

import { base64urlDecode, base64urlEncode, bufToB64url, exportPublicKeyDer } from './utils.js';

const DB_NAME    = 'ezone-keys';
const DB_VERSION = 1;
const STORE_NAME = 'keypairs';

const KEY_ALGORITHM: EcKeyGenParams = {
  name:       'ECDSA',
  namedCurve: 'P-384',
};

const SIGN_ALGORITHM: EcdsaParams = {
  name: 'ECDSA',
  hash: 'SHA-384',
};


// ─── IndexedDB helpers ────────────────────────────────────────────────────────

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE_NAME, { keyPath: 'id' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

async function dbGet<T>(db: IDBDatabase, key: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(key);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror   = () => reject(req.error);
  });
}

async function dbPut(db: IDBDatabase, record: object): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(STORE_NAME, 'readwrite');
    const req = tx.objectStore(STORE_NAME).put(record);
    req.onsuccess = () => resolve();
    req.onerror   = () => reject(req.error);
  });
}

async function dbDelete(db: IDBDatabase, key: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(STORE_NAME, 'readwrite');
    const req = tx.objectStore(STORE_NAME).delete(key);
    req.onsuccess = () => resolve();
    req.onerror   = () => reject(req.error);
  });
}


// ─── Stored record shape ─────────────────────────────────────────────────────

interface StoredKeypair {
  id:         string;    // storage key — one per userId
  publicKey:  CryptoKey; // exportable
  privateKey: CryptoKey; // non-extractable
  createdAt:  number;
}


// ─── EzoneDevice ──────────────────────────────────────────────────────────────

export class EzoneDevice {
  private constructor(
    private readonly db:         IDBDatabase,
    private readonly keypair:    StoredKeypair,
  ) {}

  /**
   * Load existing device keys for *userId*, or generate new ones.
   * Call this on page load and cache the result.
   */
  static async getOrCreate(userId: string): Promise<EzoneDevice> {
    const db = await openDb();

    const existing = await dbGet<StoredKeypair>(db, userId);
    if (existing) {
      return new EzoneDevice(db, existing);
    }

    // Generate a new non-extractable P-384 keypair
    const kp = await crypto.subtle.generateKey(
      KEY_ALGORITHM,
      false,          // private key is non-extractable
      ['sign'],
    ) as CryptoKeyPair;

    const record: StoredKeypair = {
      id:         userId,
      publicKey:  kp.publicKey,
      privateKey: kp.privateKey,
      createdAt:  Date.now(),
    };

    await dbPut(db, record);
    return new EzoneDevice(db, record);
  }

  /**
   * Check whether device keys already exist for *userId*
   * without creating new ones.
   */
  static async exists(userId: string): Promise<boolean> {
    const db  = await openDb();
    const rec = await dbGet<StoredKeypair>(db, userId);
    return rec !== undefined;
  }

  /**
   * Get the device's public key as a base64url-encoded
   * SubjectPublicKeyInfo DER string.
   * Pass this to the server during registration or device enrolment.
   */
  async getPublicKey(): Promise<string> {
    const der = await exportPublicKeyDer(this.keypair.publicKey);
    return base64urlEncode(der);
  }

  /**
   * Sign *challengeBase64url* (received from the ezone server) with the
   * device's private key.
   * Returns the base64url-encoded DER signature to send back to the server.
   */
  async signChallenge(challengeBase64url: string): Promise<string> {
    const challengeBytes = base64urlDecode(challengeBase64url);
    const sigBuf = await crypto.subtle.sign(
      SIGN_ALGORITHM,
      this.keypair.privateKey,
      challengeBytes,
    );
    return bufToB64url(sigBuf);
  }

  /**
   * Sign arbitrary bytes (advanced use — prefer signChallenge).
   */
  async sign(data: Uint8Array): Promise<Uint8Array> {
    const buf = await crypto.subtle.sign(SIGN_ALGORITHM, this.keypair.privateKey, data);
    return new Uint8Array(buf);
  }

  /** When the device key was created (Unix ms). */
  get createdAt(): number {
    return this.keypair.createdAt;
  }

  /**
   * Delete this device's keys from IndexedDB.
   * Call on logout or when the device is revoked.
   */
  async clear(): Promise<void> {
    await dbDelete(this.db, this.keypair.id);
  }
}
