import React from 'react';

// Shared UI primitives for the example app

export const styles = {
  heading: {
    color:        '#f0f9ff',
    fontSize:     '1.25rem',
    fontWeight:   700,
    marginBottom: '1.25rem',
    marginTop:    0,
  } as React.CSSProperties,

  info: {
    color:        '#94a3b8',
    lineHeight:   1.6,
    fontSize:     '0.95rem',
    marginBottom: '1.5rem',
    marginTop:    0,
  } as React.CSSProperties,

  links: {
    display:        'flex',
    justifyContent: 'space-between',
    marginTop:      '1rem',
    flexWrap:       'wrap' as const,
    gap:            '0.5rem',
  } as React.CSSProperties,
};

// ── Input ─────────────────────────────────────────────────────────────────────

type InputProps = React.InputHTMLAttributes<HTMLInputElement>;

export function Input(props: InputProps) {
  return (
    <input
      {...props}
      style={{
        width:         '100%',
        padding:       '0.75rem 1rem',
        background:    '#0f172a',
        border:        '1px solid rgba(56,189,248,.2)',
        borderRadius:  8,
        color:         '#f0f9ff',
        fontSize:      '1rem',
        outline:       'none',
        boxSizing:     'border-box',
        marginBottom:  '1rem',
        ...props.style,
      }}
    />
  );
}

// ── Button ────────────────────────────────────────────────────────────────────

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'outline';
}

export function Button({ variant = 'primary', children, style, ...rest }: ButtonProps) {
  const base: React.CSSProperties = {
    width:         '100%',
    padding:       '0.75rem',
    borderRadius:  8,
    fontSize:      '1rem',
    fontWeight:    700,
    cursor:        'pointer',
    border:        'none',
    transition:    'opacity .15s',
    ...style,
  };

  const variantStyle: React.CSSProperties = variant === 'outline'
    ? { background: 'transparent', border: '1px solid rgba(56,189,248,.35)', color: '#38bdf8' }
    : { background: 'linear-gradient(135deg, #38bdf8, #0ea5e9)', color: '#0f172a' };

  return (
    <button
      {...rest}
      style={{ ...base, ...variantStyle, opacity: rest.disabled ? 0.5 : 1 }}
    >
      {children}
    </button>
  );
}

// ── Error message ─────────────────────────────────────────────────────────────

export function ErrorMsg({ children }: { children: React.ReactNode }) {
  return (
    <p style={{
      color:         '#f87171',
      background:    'rgba(239,68,68,.08)',
      border:        '1px solid rgba(239,68,68,.2)',
      borderRadius:  6,
      padding:       '0.6rem 0.9rem',
      fontSize:      '0.875rem',
      marginBottom:  '1rem',
    }}>
      {children}
    </p>
  );
}

// ── Link ──────────────────────────────────────────────────────────────────────

export function Link({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        background:   'none',
        border:       'none',
        color:        '#38bdf8',
        cursor:       'pointer',
        fontSize:     '0.85rem',
        padding:      0,
        textDecoration: 'underline',
      }}
    >
      {children}
    </button>
  );
}
