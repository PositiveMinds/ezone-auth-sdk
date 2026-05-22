import React, { useEffect, useState } from 'react';
import { verifySession, logout } from './auth';
import Register  from './Register';
import Login     from './Login';
import Dashboard from './Dashboard';

type View = 'login' | 'register' | 'register-complete' | 'reset' | 'dashboard';

function getInitialView(): View {
  const path = window.location.pathname;
  if (path.startsWith('/register/complete')) return 'register-complete';
  if (path.startsWith('/reset/complete'))    return 'reset';
  return 'login';
}

export default function App() {
  const [view, setView]   = useState<View>(getInitialView);
  const [user, setUser]   = useState<{ user_id: string; email: string } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    verifySession().then(info => {
      if (info) {
        setUser(info);
        setView('dashboard');
      }
      setLoading(false);
    });
  }, []);

  function handleLogout() {
    logout().then(() => {
      setUser(null);
      setView('login');
    });
  }

  if (loading) {
    return (
      <div style={styles.center}>
        <p style={{ color: '#94a3b8' }}>Loading…</p>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <div style={styles.card}>
        {/* Logo / title */}
        <div style={styles.header}>
          <div style={styles.logo}>⚡</div>
          <h1 style={styles.title}>ezone</h1>
          <p style={styles.subtitle}>Passwordless authentication</p>
        </div>

        {view === 'login' && (
          <Login
            onSuccess={(info) => { setUser(info); setView('dashboard'); }}
            onRegister={() => setView('register')}
          />
        )}

        {view === 'register' && (
          <Register
            onSuccess={(info) => { setUser(info); setView('dashboard'); }}
            onLogin={() => setView('login')}
          />
        )}

        {(view === 'register-complete' || view === 'reset') && (
          <Register
            magicTokenFromUrl
            onSuccess={(info) => { setUser(info); setView('dashboard'); }}
            onLogin={() => setView('login')}
          />
        )}

        {view === 'dashboard' && user && (
          <Dashboard user={user} onLogout={handleLogout} />
        )}
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  page: {
    minHeight:       '100vh',
    display:         'flex',
    alignItems:      'center',
    justifyContent:  'center',
    background:      'linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%)',
    fontFamily:      "'Inter', system-ui, sans-serif",
    padding:         '1rem',
  },
  card: {
    background:    '#1e293b',
    border:        '1px solid rgba(56,189,248,.15)',
    borderRadius:  16,
    padding:       '2.5rem',
    width:         '100%',
    maxWidth:      420,
    boxShadow:     '0 24px 48px rgba(0,0,0,.4)',
  },
  center: {
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    minHeight: '100vh', background: '#0f172a',
  },
  header: { textAlign: 'center', marginBottom: '2rem' },
  logo:   { fontSize: '2.5rem', marginBottom: '0.5rem' },
  title:  {
    fontSize: '1.8rem', fontWeight: 800, margin: '0 0 0.25rem',
    background: 'linear-gradient(135deg, #38bdf8, #818cf8)',
    WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
  },
  subtitle: { color: '#64748b', margin: 0, fontSize: '0.9rem' },
};
