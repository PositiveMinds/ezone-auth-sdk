import React, { useEffect, useState } from 'react';
import { listDevices, revokeDevice, generateRecoveryCodes, refreshSession } from './auth';
import { styles, Button, ErrorMsg } from './ui';

interface Device {
  device_id:     string;
  device_name:   string;
  registered_at: number;
}

interface Props {
  user:      { user_id: string; email: string };
  onLogout:  () => void;
}

export default function Dashboard({ user, onLogout }: Props) {
  const [devices,       setDevices]       = useState<Device[]>([]);
  const [codes,         setCodes]         = useState<string[]>([]);
  const [error,         setError]         = useState('');
  const [showCodes,     setShowCodes]     = useState(false);
  const [generatingCodes, setGeneratingCodes] = useState(false);

  useEffect(() => {
    listDevices()
      .then(setDevices)
      .catch(err => setError(err.message));
  }, []);

  async function handleRevoke(deviceId: string) {
    if (!confirm('Revoke this device? It will no longer be able to sign in.')) return;
    try {
      await revokeDevice(deviceId);
      setDevices(prev => prev.filter(d => d.device_id !== deviceId));
    } catch (err: any) {
      setError(err.message);
    }
  }

  async function handleGenerateCodes() {
    setGeneratingCodes(true);
    try {
      const newCodes = await generateRecoveryCodes();
      setCodes(newCodes);
      setShowCodes(true);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setGeneratingCodes(false);
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
        <div>
          <h2 style={{ ...styles.heading, marginBottom: '0.25rem' }}>Welcome back</h2>
          <p style={{ color: '#64748b', margin: 0, fontSize: '0.9rem' }}>{user.email}</p>
        </div>
        <Button onClick={onLogout} variant="outline" style={{ padding: '0.4rem 0.9rem', fontSize: '0.85rem' }}>
          Sign out
        </Button>
      </div>

      {error && <ErrorMsg>{error}</ErrorMsg>}

      {/* Devices */}
      <section style={sectionStyle}>
        <h3 style={sectionTitle}>Your devices</h3>
        {devices.length === 0 ? (
          <p style={{ color: '#64748b', fontSize: '0.9rem' }}>No devices found.</p>
        ) : (
          devices.map(d => (
            <div key={d.device_id} style={deviceRow}>
              <div>
                <div style={{ color: '#f0f9ff', fontSize: '0.9rem', fontWeight: 600 }}>
                  {d.device_name || 'Unknown device'}
                </div>
                <div style={{ color: '#64748b', fontSize: '0.8rem' }}>
                  Registered {new Date(d.registered_at * 1000).toLocaleDateString()}
                </div>
              </div>
              <button
                onClick={() => handleRevoke(d.device_id)}
                style={revokeBtn}
              >
                Revoke
              </button>
            </div>
          ))
        )}
      </section>

      {/* Recovery codes */}
      <section style={sectionStyle}>
        <h3 style={sectionTitle}>Recovery codes</h3>
        <p style={{ color: '#64748b', fontSize: '0.85rem', marginTop: 0 }}>
          Generate one-time recovery codes to regain access if you lose all devices.
          Store them somewhere safe — each code can only be used once.
        </p>

        {showCodes && codes.length > 0 ? (
          <div>
            <div style={codesGrid}>
              {codes.map(c => (
                <code key={c} style={codeStyle}>{c}</code>
              ))}
            </div>
            <p style={{ color: '#f59e0b', fontSize: '0.8rem', marginTop: '0.75rem' }}>
              ⚠ Save these now. They won't be shown again.
            </p>
            <Button onClick={() => setShowCodes(false)} variant="outline" style={{ marginTop: '0.5rem' }}>
              I've saved them
            </Button>
          </div>
        ) : (
          <Button onClick={handleGenerateCodes} disabled={generatingCodes} variant="outline">
            {generatingCodes ? 'Generating…' : 'Generate recovery codes'}
          </Button>
        )}
      </section>

      {/* Session info */}
      <section style={{ ...sectionStyle, borderBottom: 'none' }}>
        <h3 style={sectionTitle}>Session</h3>
        <Button onClick={() => refreshSession().then(() => alert('Session refreshed'))} variant="outline">
          Refresh session
        </Button>
      </section>
    </div>
  );
}

const sectionStyle: React.CSSProperties = {
  borderBottom: '1px solid rgba(56,189,248,.08)',
  paddingBottom: '1.5rem',
  marginBottom:  '1.5rem',
};
const sectionTitle: React.CSSProperties = {
  color: '#f0f9ff', fontSize: '0.95rem', fontWeight: 700, marginBottom: '0.75rem',
};
const deviceRow: React.CSSProperties = {
  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
  padding: '0.75rem', background: '#0f172a',
  borderRadius: 8, marginBottom: '0.5rem',
  border: '1px solid rgba(56,189,248,.08)',
};
const revokeBtn: React.CSSProperties = {
  background: 'none', border: '1px solid rgba(239,68,68,.4)',
  color: '#ef4444', borderRadius: 6,
  padding: '0.3rem 0.75rem', fontSize: '0.8rem',
  cursor: 'pointer',
};
const codesGrid: React.CSSProperties = {
  display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.5rem',
};
const codeStyle: React.CSSProperties = {
  background: '#0f172a', border: '1px solid rgba(56,189,248,.15)',
  borderRadius: 6, padding: '0.5rem 0.75rem',
  color: '#38bdf8', fontSize: '0.85rem', fontFamily: 'monospace',
};
