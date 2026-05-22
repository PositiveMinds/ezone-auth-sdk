import React from 'react';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import clsx from 'clsx';

const features = [
  {
    icon: '🔐',
    title: 'Military-Grade Cryptography',
    desc: 'P-384 ECDSA (NSA Suite B), AES-256-GCM, SHA-384, and FIPS 140-3 compliant via OpenSSL 3.x. The same primitives trusted by governments and defense contractors.',
  },
  {
    icon: '🚫',
    title: 'Zero Password Storage',
    desc: 'Passwords are never transmitted, hashed, or stored — because they never exist. Authentication is entirely key-based, eliminating the largest class of credential breaches.',
  },
  {
    icon: '🗄️',
    title: 'No Database Required',
    desc: 'Challenges, magic links, and session tokens are cryptographically self-verifying via HMAC-SHA384. Stateless by design — scale horizontally without shared state.',
  },
  {
    icon: '🌐',
    title: '11 Language SDKs',
    desc: 'First-class clients for Node.js, Python, Go, Browser (WebCrypto + WebAuthn), Rust, Java, Dart/Flutter, Swift, .NET, PHP, and Ruby.',
  },
  {
    icon: '🔑',
    title: 'Device-Bound Keys',
    desc: 'Each device generates a non-exportable P-384 keypair stored in secure hardware (WebAuthn / Secure Enclave). Phishing-resistant by construction.',
  },
  {
    icon: '⚡',
    title: 'Drop-In REST Server',
    desc: 'Ships with a production-ready HTTP server (15 endpoints) you can self-host in minutes. TLS, CORS, rate-limit headers, and security headers built in.',
  },
];

const platforms = [
  'Node.js', 'Python', 'Go', 'Browser', 'Rust', 'Java',
  'Dart / Flutter', 'Swift / iOS', '.NET / C#', 'PHP', 'Ruby',
  'C / C++ (native)',
];

const stats = [
  { value: 'P-384', label: 'Elliptic curve' },
  { value: 'AES-256', label: 'Symmetric cipher' },
  { value: '12', label: 'Platforms supported' },
  { value: '0', label: 'Passwords stored' },
];

export default function Home(): React.ReactElement {
  const { siteConfig } = useDocusaurusContext();

  return (
    <Layout
      title={siteConfig.title}
      description="Military-grade passwordless authentication SDK — no passwords, no database, no breach."
    >
      {/* ── Hero ── */}
      <header className="hero">
        <div className="container">
          <h1 className="hero__title">
            Passwordless auth.<br />Zero compromise.
          </h1>
          <p className="hero__subtitle">
            ezone is a military-grade authentication SDK built on P-384, AES-256-GCM,
            and HMAC-SHA384. No passwords. No database. No breach surface.
          </p>
          <div className="hero__cta-group">
            <Link className="button button--primary button--lg" to="/docs/getting-started">
              Get Started — 5 min
            </Link>
            <Link className="button button--secondary button--lg" to="/docs/intro">
              Read the Docs
            </Link>
          </div>
        </div>
      </header>

      {/* ── Stats bar ── */}
      <div className="stats-bar">
        {stats.map(s => (
          <div key={s.label} style={{ textAlign: 'center' }}>
            <div className="stat__value">{s.value}</div>
            <div className="stat__label">{s.label}</div>
          </div>
        ))}
      </div>

      {/* ── Feature cards ── */}
      <section className="features">
        <div className="container">
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: '1.5rem',
            }}
          >
            {features.map(f => (
              <div key={f.title} className="feature-card">
                <div className="feature-card__icon">{f.icon}</div>
                <div className="feature-card__title">{f.title}</div>
                <div className="feature-card__desc">{f.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Quick-start code ── */}
      <section style={{ padding: '4rem 0', background: '#0c1220' }}>
        <div className="container" style={{ maxWidth: 760 }}>
          <h2
            style={{
              textAlign: 'center',
              fontSize: '2rem',
              fontWeight: 800,
              color: '#f0f9ff',
              marginBottom: '0.5rem',
            }}
          >
            Up and running in minutes
          </h2>
          <p style={{ textAlign: 'center', color: '#94a3b8', marginBottom: '2rem' }}>
            One command starts the server. One import is all the client needs.
          </p>

          <div style={{ marginBottom: '1.5rem' }}>
            <div
              style={{
                background: '#1e293b',
                border: '1px solid rgba(56,189,248,.15)',
                borderRadius: 10,
                padding: '1.25rem 1.5rem',
                fontFamily: 'monospace',
                fontSize: '0.9rem',
                color: '#94a3b8',
              }}
            >
              <div style={{ color: '#475569', marginBottom: 8 }}># Start the ezone REST server</div>
              <div>
                <span style={{ color: '#38bdf8' }}>docker</span>{' '}
                <span style={{ color: '#f0f9ff' }}>run -p 8080:8080 ghcr.io/ezone-sdk/ezone-server:latest</span>
              </div>
            </div>
          </div>

          <div
            style={{
              background: '#1e293b',
              border: '1px solid rgba(56,189,248,.15)',
              borderRadius: 10,
              padding: '1.25rem 1.5rem',
              fontFamily: 'monospace',
              fontSize: '0.9rem',
              color: '#94a3b8',
            }}
          >
            <div style={{ color: '#475569', marginBottom: 8 }}># Node.js / TypeScript</div>
            <div>
              <span style={{ color: '#38bdf8' }}>import</span>{' '}
              <span style={{ color: '#f0f9ff' }}>{'{ EzoneClient }'}</span>{' '}
              <span style={{ color: '#38bdf8' }}>from</span>{' '}
              <span style={{ color: '#bae6fd' }}>'ezone-sdk'</span>
              <span style={{ color: '#f0f9ff' }}>;</span>
            </div>
            <br />
            <div>
              <span style={{ color: '#818cf8' }}>const</span>{' '}
              <span style={{ color: '#f0f9ff' }}>client</span>{' '}
              <span style={{ color: '#38bdf8' }}>=</span>{' '}
              <span style={{ color: '#38bdf8' }}>new</span>{' '}
              <span style={{ color: '#f0f9ff' }}>EzoneClient({'{ baseUrl: '}}
              </span>
              <span style={{ color: '#bae6fd' }}>'http://localhost:8080'</span>
              <span style={{ color: '#f0f9ff' }}>{' })'}</span>
              <span style={{ color: '#f0f9ff' }}>;</span>
            </div>
            <br />
            <div style={{ color: '#475569' }}>// Register a new user (sends magic link)</div>
            <div>
              <span style={{ color: '#818cf8' }}>const</span>{' '}
              <span style={{ color: '#f0f9ff' }}>reg</span>{' '}
              <span style={{ color: '#38bdf8' }}>=</span>{' '}
              <span style={{ color: '#818cf8' }}>await</span>{' '}
              <span style={{ color: '#f0f9ff' }}>client.beginRegistration({'{ email: '}</span>
              <span style={{ color: '#bae6fd' }}>'alice@example.com'</span>
              <span style={{ color: '#f0f9ff' }}>{' })'}</span>
              <span style={{ color: '#f0f9ff' }}>;</span>
            </div>
            <div style={{ color: '#475569', marginTop: 4 }}>// → {'{ magic_token: "EZONE-..." }'}</div>
          </div>

          <div style={{ textAlign: 'center', marginTop: '2rem' }}>
            <Link className="button button--primary" to="/docs/getting-started">
              View full quickstart guide →
            </Link>
          </div>
        </div>
      </section>

      {/* ── Platform grid ── */}
      <section style={{ padding: '4rem 0', background: '#0f172a' }}>
        <div className="container" style={{ maxWidth: 760, textAlign: 'center' }}>
          <h2
            style={{
              fontSize: '2rem',
              fontWeight: 800,
              color: '#f0f9ff',
              marginBottom: '0.5rem',
            }}
          >
            Every major platform
          </h2>
          <p style={{ color: '#94a3b8', marginBottom: '2rem' }}>
            One SDK, one REST API, eleven language clients.
          </p>
          <div className="platform-grid" style={{ justifyContent: 'center' }}>
            {platforms.map(p => (
              <span key={p} className="platform-badge">
                {p}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA footer ── */}
      <section
        style={{
          padding: '5rem 0',
          background: 'linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%)',
          textAlign: 'center',
        }}
      >
        <div className="container" style={{ maxWidth: 600 }}>
          <h2
            style={{
              fontSize: '2rem',
              fontWeight: 800,
              color: '#f0f9ff',
              marginBottom: '1rem',
            }}
          >
            Ready to eliminate passwords?
          </h2>
          <p style={{ color: '#94a3b8', marginBottom: '2rem' }}>
            ezone v0.1.0 is in public beta. Start building in 5 minutes.
          </p>
          <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
            <Link className="button button--primary button--lg" to="/docs/getting-started">
              Get Started
            </Link>
            <Link
              className="button button--secondary button--lg"
              href="https://github.com/ezone-sdk/ezone-sdk"
            >
              View on GitHub
            </Link>
          </div>
        </div>
      </section>
    </Layout>
  );
}
