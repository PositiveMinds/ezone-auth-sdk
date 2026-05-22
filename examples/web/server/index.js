/**
 * ezone example — Express backend
 *
 * This server acts as a thin bridge between the React frontend and the
 * ezone auth server. In a real app you would also have your business
 * logic routes here, protected by the requireAuth middleware.
 *
 * Environment variables:
 *   EZONE_URL      URL of the ezone REST server  (default: http://localhost:8080)
 *   EMAIL_FROM     From address for magic link emails
 *   SMTP_HOST      SMTP server host
 *   SMTP_PORT      SMTP server port  (default: 587)
 *   SMTP_USER      SMTP username
 *   SMTP_PASS      SMTP password
 *   APP_URL        Frontend URL (used to build magic link)  (default: http://localhost:5173)
 *   PORT           Port this server listens on  (default: 3001)
 */

import express    from 'express';
import cors       from 'cors';
import nodemailer from 'nodemailer';
import { EzoneClient, EzoneError } from 'ezone-sdk';

const app   = express();
const ezone = new EzoneClient({ baseUrl: process.env.EZONE_URL ?? 'http://localhost:8080' });

// ── Email transport ────────────────────────────────────────────────────────────
// Replace with your SMTP / SendGrid / Postmark / SES credentials.
// In development, nodemailer's "preview" transport prints links to the console.
const mailer = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT ?? '587'),
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : { sendMail: async (opts) => console.log('\n📧 Magic link email (dev mode):',
      `\nTo: ${opts.to}\nSubject: ${opts.subject}\n${opts.text}\n`) };

async function sendMagicLink(to, subject, magicToken, path) {
  const appUrl = process.env.APP_URL ?? 'http://localhost:5173';
  const link   = `${appUrl}${path}?token=${encodeURIComponent(magicToken)}`;

  await mailer.sendMail({
    from:    process.env.EMAIL_FROM ?? 'auth@ezone.example',
    to,
    subject,
    text:    `Your link (expires in 15 minutes):\n\n${link}\n\nIf you did not request this, ignore this email.`,
    html:    `<p>Click the link below to continue (expires in 15 minutes):</p>
              <p><a href="${link}">${link}</a></p>
              <p>If you did not request this, ignore this email.</p>`,
  });
}

// ── Middleware ─────────────────────────────────────────────────────────────────

app.use(cors({ origin: process.env.APP_URL ?? 'http://localhost:5173', credentials: true }));
app.use(express.json({ limit: '16kb' }));

// Verify ezone session and attach user_id to request.
async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Missing token' });

  try {
    req.ezoneUser = await ezone.verifySession(token);
    next();
  } catch (err) {
    const status = err instanceof EzoneError ? err.status : 401;
    res.status(status).json({ error: 'Invalid or expired token' });
  }
}

// ── Auth routes ───────────────────────────────────────────────────────────────

// Registration: step 1 — generate magic link and email it
app.post('/api/auth/register/begin', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });

  try {
    const { magic_token } = await ezone.beginRegistration({ email });
    await sendMagicLink(email, 'Complete your ezone registration', magic_token, '/register/complete');
    res.json({ ok: true, message: 'Check your email for the registration link.' });
  } catch (err) {
    console.error('register/begin error:', err.message);
    // Don't expose whether the email already exists
    res.json({ ok: true, message: 'Check your email for the registration link.' });
  }
});

// Registration: step 2 — called after user clicks the link and browser generates a key
app.post('/api/auth/register/complete', async (req, res) => {
  const { magic_token, device_public_key, device_name } = req.body;
  if (!magic_token || !device_public_key) {
    return res.status(400).json({ error: 'magic_token and device_public_key required' });
  }

  try {
    const session = await ezone.completeRegistration({
      magic_token,
      device_public_key,
      device_name: device_name ?? 'Browser',
    });
    res.json(session);
  } catch (err) {
    const status = err instanceof EzoneError ? err.status : 400;
    res.status(status).json({ error: err.message });
  }
});

// Login: step 1 — get a challenge
app.post('/api/auth/login/begin', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });

  try {
    const { challenge } = await ezone.beginLogin({ email });
    res.json({ challenge });
  } catch (err) {
    // Return a generic error — don't reveal whether the email is registered
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// Login: step 2 — verify signed challenge
app.post('/api/auth/login/complete', async (req, res) => {
  const { email, challenge, signature, device_public_key } = req.body;
  if (!email || !challenge || !signature || !device_public_key) {
    return res.status(400).json({ error: 'email, challenge, signature and device_public_key required' });
  }

  try {
    const session = await ezone.completeLogin({ email, challenge, signature, device_public_key });
    res.json(session);
  } catch (err) {
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// Session: verify + refresh
app.get('/api/auth/session', requireAuth, (req, res) => {
  res.json(req.ezoneUser);
});

app.post('/api/auth/session/refresh', requireAuth, async (req, res) => {
  try {
    const token = req.headers.authorization.replace('Bearer ', '');
    const newSession = await ezone.refreshSession(token);
    res.json(newSession);
  } catch (err) {
    res.status(401).json({ error: 'Refresh failed' });
  }
});

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  try {
    await ezone.logout(req.headers.authorization.replace('Bearer ', ''));
  } catch {}  // stateless logout always succeeds client-side
  res.json({ ok: true });
});

// Password reset: begin
app.post('/api/auth/reset/begin', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });

  try {
    const { magic_token } = await ezone.beginReset({ email });
    await sendMagicLink(email, 'Reset your ezone account', magic_token, '/reset/complete');
  } catch {}
  // Always return success to prevent email enumeration
  res.json({ ok: true, message: 'If that email is registered you will receive a reset link.' });
});

// Password reset: complete
app.post('/api/auth/reset/complete', async (req, res) => {
  const { magic_token, device_public_key, device_name } = req.body;
  if (!magic_token || !device_public_key) {
    return res.status(400).json({ error: 'magic_token and device_public_key required' });
  }

  try {
    const session = await ezone.completeReset({ magic_token, device_public_key, device_name: device_name ?? 'Browser' });
    res.json(session);
  } catch (err) {
    res.status(400).json({ error: 'Reset failed or link expired' });
  }
});

// Recovery codes
app.post('/api/auth/recovery/generate', requireAuth, async (req, res) => {
  try {
    const token = req.headers.authorization.replace('Bearer ', '');
    const { codes } = await ezone.generateRecoveryCodes(token);
    res.json({ codes });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate codes' });
  }
});

app.post('/api/auth/recovery/use', async (req, res) => {
  const { email, code, device_public_key, device_name } = req.body;
  if (!email || !code || !device_public_key) {
    return res.status(400).json({ error: 'email, code and device_public_key required' });
  }
  try {
    const session = await ezone.recoverWithCode({ email, code, device_public_key, device_name: device_name ?? 'Recovery device' });
    res.json(session);
  } catch {
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// Devices
app.get('/api/auth/devices', requireAuth, async (req, res) => {
  try {
    const token = req.headers.authorization.replace('Bearer ', '');
    const { devices } = await ezone.listDevices(token);
    res.json({ devices });
  } catch (err) {
    res.status(500).json({ error: 'Failed to list devices' });
  }
});

app.delete('/api/auth/devices/:deviceId', requireAuth, async (req, res) => {
  try {
    const token = req.headers.authorization.replace('Bearer ', '');
    await ezone.revokeDevice(token, req.params.deviceId);
    res.json({ ok: true });
  } catch (err) {
    const status = err instanceof EzoneError ? err.status : 400;
    res.status(status).json({ error: err.message });
  }
});

// ── Protected example route ───────────────────────────────────────────────────

app.get('/api/profile', requireAuth, (req, res) => {
  res.json({
    user_id:    req.ezoneUser.user_id,
    email:      req.ezoneUser.email,
    expires_at: req.ezoneUser.expires_at,
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT ?? '3001');
app.listen(PORT, () => console.log(`ezone example server listening on http://localhost:${PORT}`));
