import React, { useState } from 'react';
import { login, beginReset } from './auth';
import { styles, Input, Button, ErrorMsg, Link } from './ui';

interface Props {
  onSuccess: (user: { user_id: string; email: string }) => void;
  onRegister: () => void;
}

export default function Login({ onSuccess, onRegister }: Props) {
  const [email,  setEmail]  = useState('');
  const [stage,  setStage]  = useState<'email' | 'signing' | 'reset-sent'>('email');
  const [error,  setError]  = useState('');
  const [busy,   setBusy]   = useState(false);

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim()) return;
    setError(''); setBusy(true);
    setStage('signing');
    try {
      const session = await login(email.trim());
      onSuccess({ user_id: session.user_id ?? '', email: email.trim() });
    } catch (err: any) {
      setError(err.message ?? 'Login failed');
      setStage('email');
    } finally {
      setBusy(false);
    }
  }

  async function handleReset() {
    if (!email.trim()) { setError('Enter your email first'); return; }
    setBusy(true); setError('');
    try {
      await beginReset(email.trim());
      setStage('reset-sent');
    } catch {
      setStage('reset-sent'); // always show success to prevent enumeration
    } finally {
      setBusy(false);
    }
  }

  if (stage === 'reset-sent') {
    return (
      <div>
        <p style={styles.info}>
          If <strong>{email}</strong> is registered, a reset link has been sent. Check your email.
        </p>
        <Button onClick={() => setStage('email')}>Back to sign in</Button>
      </div>
    );
  }

  return (
    <form onSubmit={handleLogin}>
      <h2 style={styles.heading}>Sign in</h2>

      {stage === 'signing' ? (
        <p style={styles.info}>
          Waiting for biometric confirmation…<br />
          <span style={{ color: '#64748b', fontSize: '0.85rem' }}>
            Your device will prompt for TouchID, FaceID, or Windows Hello.
          </span>
        </p>
      ) : (
        <>
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
            {busy ? 'Signing in…' : 'Sign in'}
          </Button>
          <div style={styles.links}>
            <Link onClick={handleReset}>Forgot account / lost device?</Link>
            <Link onClick={onRegister}>Create account</Link>
          </div>
        </>
      )}
    </form>
  );
}
