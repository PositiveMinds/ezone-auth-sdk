/**
 * ezone auth helpers for the example app.
 *
 * This module wraps the @ezone/browser SDK and the example server's
 * /api/auth/* endpoints into simple async functions.
 */

import { getSecureDevice, storeCredentialId } from '@ezone/browser';

const API = 'http://localhost:3001/api';

// ── Token storage ─────────────────────────────────────────────────────────────
// Use sessionStorage for the example. In production consider in-memory only
// (no storage) for highest security — store in React state and refresh via
// /auth/session/refresh before expiry.

export function getToken(): string | null {
  return sessionStorage.getItem('ezone_token');
}

function setToken(token: string): void {
  sessionStorage.setItem('ezone_token', token);
}

function clearToken(): void {
  sessionStorage.removeItem('ezone_token');
}

// ── API helpers ───────────────────────────────────────────────────────────────

async function post(path: string, body: unknown, token?: string) {
  const res = await fetch(`${API}${path}`, {
    method:  'POST',
    headers: {
      'Content-Type':  'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`);
  return json;
}

async function get(path: string, token?: string) {
  const res = await fetch(`${API}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`);
  return json;
}

// ── Registration ──────────────────────────────────────────────────────────────

/**
 * Step 1: request a magic link. The server emails it to the user.
 * In dev mode the link is logged to the server console.
 */
export async function beginRegistration(email: string): Promise<void> {
  await post('/auth/register/begin', { email });
}

/**
 * Step 2: called when the user arrives at /register/complete?token=...
 * Generates a device keypair (WebAuthn preferred) and completes registration.
 */
export async function completeRegistration(
  magicToken: string,
  email: string,
): Promise<{ token: string; user_id: string }> {
  const device = await getSecureDevice(email, email, true, {
    passkeyOpts: { rpId: window.location.hostname, rpName: 'ezone example' },
  });

  if (device.credentialId) storeCredentialId(email, device.credentialId);

  const session = await post('/auth/register/complete', {
    magic_token:       magicToken,
    device_public_key: device.publicKey,
    device_name:       navigator.userAgent.slice(0, 60),
  });

  setToken(session.token);
  return session;
}

// ── Login ─────────────────────────────────────────────────────────────────────

export async function login(email: string): Promise<{ token: string }> {
  // 1. Get challenge from server
  const { challenge } = await post('/auth/login/begin', { email });

  // 2. Sign with device key (private key never leaves browser)
  const device = await getSecureDevice(email, email, false, {
    passkeyOpts: { rpId: window.location.hostname, rpName: 'ezone example' },
  });

  const signature = await device.sign(challenge);

  // 3. Complete login
  const session = await post('/auth/login/complete', {
    email,
    challenge,
    signature,
    device_public_key: device.publicKey || '',
  });

  setToken(session.token);
  return session;
}

// ── Session ───────────────────────────────────────────────────────────────────

export async function getProfile() {
  const token = getToken();
  if (!token) throw new Error('Not logged in');
  return get('/profile', token);
}

export async function verifySession() {
  const token = getToken();
  if (!token) return null;
  try {
    return await get('/auth/session', token);
  } catch {
    clearToken();
    return null;
  }
}

export async function refreshSession(): Promise<void> {
  const token = getToken();
  if (!token) return;
  try {
    const { token: newToken } = await post('/auth/session/refresh', {}, token);
    setToken(newToken);
  } catch {
    clearToken();
  }
}

export async function logout(): Promise<void> {
  const token = getToken();
  if (token) {
    try { await post('/auth/logout', {}, token); } catch {}
  }
  clearToken();
}

// ── Recovery ──────────────────────────────────────────────────────────────────

export async function beginReset(email: string): Promise<void> {
  await post('/auth/reset/begin', { email });
}

export async function completeReset(magicToken: string, email: string) {
  const device = await getSecureDevice(email, email, true, {
    passkeyOpts: { rpId: window.location.hostname, rpName: 'ezone example' },
  });
  if (device.credentialId) storeCredentialId(email, device.credentialId);

  const session = await post('/auth/reset/complete', {
    magic_token:       magicToken,
    device_public_key: device.publicKey,
    device_name:       navigator.userAgent.slice(0, 60),
  });
  setToken(session.token);
  return session;
}

export async function generateRecoveryCodes(): Promise<string[]> {
  const token = getToken();
  if (!token) throw new Error('Not logged in');
  const { codes } = await post('/auth/recovery/generate', {}, token);
  return codes;
}

// ── Devices ───────────────────────────────────────────────────────────────────

export async function listDevices() {
  const token = getToken();
  if (!token) throw new Error('Not logged in');
  const { devices } = await get('/auth/devices', token);
  return devices as Array<{ device_id: string; device_name: string; registered_at: number }>;
}

export async function revokeDevice(deviceId: string): Promise<void> {
  const token = getToken();
  if (!token) throw new Error('Not logged in');
  const res = await fetch(`${API}/auth/devices/${deviceId}`, {
    method:  'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    const json = await res.json();
    throw new Error(json.error ?? 'Revoke failed');
  }
}
