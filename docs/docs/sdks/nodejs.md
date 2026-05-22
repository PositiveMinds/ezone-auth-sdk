---
id: nodejs
title: Node.js / TypeScript
---

# Node.js SDK

The Node.js SDK uses the native `fetch` API (Node 18+) with full TypeScript types.

## Installation

```bash
npm install ezone-sdk
```

## Quick start

```typescript
import { EzoneClient } from 'ezone-sdk';

const ezone = new EzoneClient({
  baseUrl: 'https://auth.yourapp.com',
  timeoutMs: 5000,
});

// Registration
const { magic_token } = await ezone.beginRegistration({ email: 'alice@example.com' });
// → email magic_token to user

// After user clicks link and sends back their public key:
const session = await ezone.completeRegistration({
  magic_token,
  device_public_key: req.body.device_public_key,
  device_name: req.body.device_name,
});
res.json({ token: session.token });
```

## Express middleware

```typescript
import { EzoneClient } from 'ezone-sdk';

const ezone = new EzoneClient({ baseUrl: process.env.EZONE_URL! });

export async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Missing token' });

  try {
    const info = await ezone.verifySession(token);
    req.userId = info.user_id;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}
```

## API

```typescript
class EzoneClient {
  constructor(config: { baseUrl: string; timeoutMs?: number });

  beginRegistration(req: { email: string }): Promise<{ magic_token: string }>;
  completeRegistration(req: CompleteRegistrationRequest): Promise<SessionResponse>;

  beginLogin(req: { email: string }): Promise<{ challenge: string }>;
  completeLogin(req: CompleteLoginRequest): Promise<SessionResponse>;

  verifySession(token: string): Promise<SessionInfo>;
  refreshSession(token: string): Promise<{ token: string; expires_at: number }>;
  logout(token: string): Promise<void>;

  beginReset(req: { email: string }): Promise<{ magic_token: string }>;
  completeReset(req: CompleteResetRequest): Promise<SessionResponse>;

  generateRecoveryCodes(token: string): Promise<{ codes: string[] }>;
  recoverWithCode(req: RecoveryRequest): Promise<SessionResponse>;

  listDevices(token: string): Promise<{ devices: Device[] }>;
  beginAddDevice(token: string): Promise<{ magic_token: string }>;
  completeAddDevice(req: CompleteAddDeviceRequest): Promise<Device>;
  revokeDevice(token: string, deviceId: string): Promise<void>;
}
```

## Error handling

```typescript
import { EzoneError } from 'ezone-sdk';

try {
  await ezone.completeLogin(req);
} catch (err) {
  if (err instanceof EzoneError) {
    console.error(err.status, err.message); // e.g. 401 "Invalid signature"
  }
}
```

## React integration

The Node.js SDK is for server-side use. For React frontends, use [@ezone/browser](/docs/sdks/browser) on the client, and call your own server which uses the Node.js SDK to verify tokens.
