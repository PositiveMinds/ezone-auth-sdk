import {
  AuthSession,
  BeginLoginRequest,
  BeginRegistrationRequest,
  BeginResetRequest,
  CompleteAddDeviceRequest,
  CompleteRegistrationRequest,
  CompleteResetRequest,
  CompletLoginRequest,
  Device,
  DeviceList,
  EzoneClientConfig,
  EzoneError,
  LoginChallenge,
  LogoutRequest,
  PendingAddDevice,
  PendingAuth,
  RecoverWithCodeRequest,
  RecoveryCodes,
  RefreshedSession,
  SessionInfo,
} from './types.js';

// ─── HTTP helper ──────────────────────────────────────────────────────────────

async function request<T>(
  method: 'GET' | 'POST' | 'DELETE',
  url: string,
  body?: unknown,
  bearerToken?: string,
  timeoutMs = 10_000,
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Accept':       'application/json',
  };
  if (bearerToken) headers['Authorization'] = `Bearer ${bearerToken}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers,
      body:   body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
  } catch (err: unknown) {
    clearTimeout(timer);
    const msg = err instanceof Error ? err.message : String(err);
    throw new EzoneError(`Network error: ${msg}`, 0, msg);
  }
  clearTimeout(timer);

  const text = await res.text();
  let json: Record<string, unknown> = {};
  try { json = JSON.parse(text); } catch { /* empty body */ }

  if (!res.ok) {
    const msg = (json['error'] as string) ?? res.statusText;
    throw new EzoneError(msg, res.status, msg);
  }
  return json as T;
}


// ─── EzoneClient ─────────────────────────────────────────────────────────────

export class EzoneClient {
  private readonly base: string;
  private readonly timeout: number;

  constructor(config: EzoneClientConfig) {
    const prefix = config.prefix ?? '/v1';
    this.base    = config.baseUrl.replace(/\/$/, '') + prefix;
    this.timeout = config.timeoutMs ?? 10_000;
  }

  private url(path: string) {
    return this.base + path;
  }

  private get<T>(path: string, token?: string) {
    return request<T>('GET', this.url(path), undefined, token, this.timeout);
  }
  private post<T>(path: string, body?: unknown, token?: string) {
    return request<T>('POST', this.url(path), body, token, this.timeout);
  }
  private del<T>(path: string, token: string) {
    return request<T>('DELETE', this.url(path), undefined, token, this.timeout);
  }


  // ── Health ──────────────────────────────────────────────────────────────────

  async health(): Promise<{ status: string }> {
    return this.get('/health');
  }


  // ── Registration ────────────────────────────────────────────────────────────

  /**
   * Step 1 — Initiate registration.
   * Returns a magic_token to embed in an email link sent to the user.
   */
  async beginRegistration(email: string): Promise<PendingAuth> {
    return this.post<PendingAuth>('/auth/register/begin', {
      email,
    } satisfies BeginRegistrationRequest);
  }

  /**
   * Step 2 — User clicked magic link and device generated a P-384 keypair.
   * Pass the base64url-encoded SubjectPublicKeyInfo DER of the device public key.
   * Returns an active session.
   */
  async completeRegistration(
    magicToken: string,
    publicKey: string,
    deviceLabel?: string,
  ): Promise<AuthSession> {
    return this.post<AuthSession>('/auth/register/complete', {
      magic_token:  magicToken,
      public_key:   publicKey,
      device_label: deviceLabel,
    } satisfies CompleteRegistrationRequest);
  }


  // ── Login ────────────────────────────────────────────────────────────────────

  /**
   * Step 1 — Request a login challenge for the user's device to sign.
   * Returns challenge bytes (base64url) that the device must sign with its P-384 key.
   */
  async beginLogin(email: string): Promise<LoginChallenge> {
    return this.post<LoginChallenge>('/auth/login/begin', {
      email,
    } satisfies BeginLoginRequest);
  }

  /**
   * Step 2 — Submit the device's signature over the challenge bytes.
   * Returns an active session on success.
   */
  async completeLogin(
    challenge: string,
    signature: string,
    publicKey: string,
  ): Promise<AuthSession> {
    return this.post<AuthSession>('/auth/login/complete', {
      challenge,
      signature,
      public_key: publicKey,
    } satisfies CompletLoginRequest);
  }


  // ── Session ──────────────────────────────────────────────────────────────────

  /**
   * Verify a session token and return session details.
   * Use this in server middleware / request guards.
   */
  async verifySession(token: string): Promise<SessionInfo> {
    return this.get<SessionInfo>('/auth/session', token);
  }

  /**
   * Silently refresh a session before expiry.
   * Returns a new token with a fresh expiry.
   */
  async refreshSession(token: string): Promise<RefreshedSession> {
    return this.post<RefreshedSession>('/auth/session/refresh', undefined, token);
  }

  /**
   * Log out.
   * Pass revokeDevice: true to permanently revoke the signing device
   * so it can never authenticate again.
   */
  async logout(token: string, revokeDevice = false): Promise<void> {
    await this.post('/auth/logout', {
      revoke_device: revokeDevice,
    } satisfies LogoutRequest, token);
  }


  // ── Account reset ────────────────────────────────────────────────────────────

  /**
   * Step 1 — User lost access.  Returns a reset magic_token.
   * Never errors on unknown emails (prevents user enumeration).
   */
  async beginReset(email: string): Promise<PendingAuth> {
    return this.post<PendingAuth>('/auth/reset/begin', {
      email,
    } satisfies BeginResetRequest);
  }

  /**
   * Step 2 — User clicked reset link and registered a new device.
   */
  async completeReset(
    magicToken: string,
    publicKey: string,
    deviceLabel?: string,
  ): Promise<AuthSession> {
    return this.post<AuthSession>('/auth/reset/complete', {
      magic_token:  magicToken,
      public_key:   publicKey,
      device_label: deviceLabel,
    } satisfies CompleteResetRequest);
  }


  // ── Recovery codes ───────────────────────────────────────────────────────────

  /**
   * Generate recovery codes for the authenticated user.
   * Show the codes to the user exactly once — they cannot be retrieved again.
   */
  async generateRecoveryCodes(token: string): Promise<RecoveryCodes> {
    return this.post<RecoveryCodes>('/auth/recovery/generate', undefined, token);
  }

  /**
   * Use one recovery code to obtain a reset magic_token.
   * The code is permanently consumed after this call.
   */
  async recoverWithCode(email: string, code: string): Promise<PendingAuth> {
    return this.post<PendingAuth>('/auth/recovery/use', {
      email,
      code,
    } satisfies RecoverWithCodeRequest);
  }


  // ── Multi-device ─────────────────────────────────────────────────────────────

  /**
   * Step 1 — Start adding a new device to an existing authenticated account.
   * Send the returned add_token to the new device (e.g. via QR code).
   */
  async beginAddDevice(token: string): Promise<PendingAddDevice> {
    return this.post<PendingAddDevice>('/auth/devices/add/begin', undefined, token);
  }

  /**
   * Step 2 — New device supplies its public key to complete enrolment.
   */
  async completeAddDevice(
    addToken: string,
    publicKey: string,
    deviceLabel?: string,
  ): Promise<AuthSession> {
    return this.post<AuthSession>('/auth/devices/add/complete', {
      add_token:    addToken,
      public_key:   publicKey,
      device_label: deviceLabel,
    } satisfies CompleteAddDeviceRequest);
  }

  /**
   * List all devices for the authenticated user.
   */
  async listDevices(token: string): Promise<Device[]> {
    const res = await this.get<DeviceList>('/auth/devices', token);
    return res.devices;
  }

  /**
   * Revoke a device by ID.
   * Requires an active session from a different device.
   */
  async revokeDevice(token: string, deviceId: string): Promise<void> {
    await this.del(`/auth/devices/${encodeURIComponent(deviceId)}`, token);
  }
}
