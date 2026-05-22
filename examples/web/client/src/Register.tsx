import React, { useEffect, useState } from 'react';
import { beginRegistration, completeRegistration } from './auth';
import { styles, Input, Button, ErrorMsg, Link } from './ui';

interface Props {
  magicTokenFromUrl?: boolean;
  onSuccess: (user: { user_id: string; email: string }) => void;
  onLogin:   () => void;
}

export default function Register({ magicTokenFromUrl, onSuccess, onLogin }: Props) {
  const [email,  setEmail]  = useState('');
  const [stage,  setStage]  = useState<'email' | 'sent' | 'completing' | 'done'>('email');
  const [error,  setError]  = useState('');
  const [busy,   setBusy]   = useState(false);

  // If we arrived via a magic link URL, auto-complete registration
  useEffect(() => {
    if (!magicTokenFromUrl) return;
    const params = new URLSearchParams(window.location.search);
    const token  = params.get('token');
    const stored = sessionStorage.getItem('ezone_register_email');
    if (token && stored) {
      setEmail(stored);
      setStage('completing');
      completeRegistration(token, stored)
        .then(session => {
          sessionStorage.removeItem('ezone_register_email');
          onSuccess({ user_id: session.user_id, email: stored });
        })
        .catch(err => {
          setError(err.message ?? 'Registration failed. The link may have expired.');
          setStage('email');
        });
    }
  }, []);

  async function handleBegin(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim()) return;
    setBusy(true); setError('');
    try {
      sessionStorage.setItem('ezone_register_email', email.trim());
      await beginRegistration(email.trim());
      setStage('sent');
    } catch (err: any) {
      setError(err.message ?? 'Failed to send email');
    } finally {
      setBusy(false);
    }
  }

  if (stage === 'sent') {
    return (
      <div>
        <h2 style={styles.heading}>Check your email</h2>
        <p style={styles.info}>
          We sent a registration link to <strong>{email}</strong>.<br />
          Click the link in the email to complete setup — your device will then
          generate a secure key for future logins.
        </p>
        <Button onClick={() => setStage('email')}>Use a different email</Button>
        <div style={styles.links}>
          <Link onClick={onLogin}>Already have an account?</Link>
        </div>
      </div>
    );
  }

  if (stage === 'completing') {
    return (
      <div>
        <h2 style={styles.heading}>Setting up your device…</h2>
        <p style={styles.info}>
          Generating a secure key for your device.<br />
          <span style={{ color: '#64748b', fontSize: '0.85rem' }}>
            Your browser or OS may prompt you for biometric confirmation.
          </span>
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={handleBegin}>
      <h2 style={styles.heading}>Create account</h2>
      <p style={{ color: '#64748b', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
        No password required. We'll email you a link to set up your device key.
      </p>
      <Input
        type="email"
        placeholder="your@email.com"
        value={email}
        onChange={e => setEmail(e.target.value)}
        autoFocus
        required
      />
      {error && <ErrorMsg>{error}</ErrorMsg>}
      <Button type="submit" disabled={busy || !email}>
        {busy ? 'Sending…' : 'Send magic link'}
      </Button>
      <div style={styles.links}>
        <Link onClick={onLogin}>Already have an account?</Link>
      </div>
    </form>
  );
}
