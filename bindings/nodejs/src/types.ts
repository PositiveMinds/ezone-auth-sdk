// ─── Requests ────────────────────────────────────────────────────────────────

export interface BeginRegistrationRequest {
  email: string;
}

export interface CompleteRegistrationRequest {
  magic_token: string;
  public_key: string;      // base64url-encoded P-384 SubjectPublicKeyInfo DER
  device_label?: string;
}

export interface BeginLoginRequest {
  email: string;
}

export interface CompletLoginRequest {
  challenge: string;       // base64url — from BeginLoginResponse
  signature: string;       // base64url — ECDSA-P384 over challenge bytes
  public_key: string;      // base64url — device public key
}

export interface LogoutRequest {
  revoke_device?: boolean;
}

export interface BeginResetRequest {
  email: string;
}

export interface CompleteResetRequest {
  magic_token: string;
  public_key: string;
  device_label?: string;
}

export interface RecoverWithCodeRequest {
  email: string;
  code: string;
}

export interface CompleteAddDeviceRequest {
  add_token: string;
  public_key: string;
  device_label?: string;
}


// ─── Responses ───────────────────────────────────────────────────────────────

export interface PendingAuth {
  magic_token: string;
  expires_at: number;
}

export interface LoginChallenge {
  challenge: string;       // base64url — sign this bytes with device private key
  expires_at: number;
}

export interface AuthSession {
  token: string;
  user_id: string;
  device_id: string;
  expires_at: number;
}

export interface SessionInfo {
  user_id: string;
  email: string;
  device_id: string;
  issued_at: number;
  expires_at: number;
}

export interface RefreshedSession {
  token: string;
  expires_at: number;
}

export interface RecoveryCodes {
  codes: string[];
}

export interface PendingAddDevice {
  add_token: string;
  expires_at: number;
}

export interface Device {
  device_id: string;
  label: string;
  created_at: number;
  revoked: boolean;
}

export interface DeviceList {
  devices: Device[];
}


// ─── Errors ───────────────────────────────────────────────────────────────────

export class EzoneError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly serverMessage: string,
  ) {
    super(message);
    this.name = 'EzoneError';
  }
}


// ─── Client config ────────────────────────────────────────────────────────────

export interface EzoneClientConfig {
  /** Base URL of the ezone REST server, e.g. "https://auth.yourapp.com" */
  baseUrl: string;
  /** Optional API prefix override (default: "/v1") */
  prefix?: string;
  /** Optional request timeout in milliseconds (default: 10000) */
  timeoutMs?: number;
}
