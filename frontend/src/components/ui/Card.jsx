import React from 'react';

const Card = ({ children, className = '', variant = 'default', glow = false, style = {}, onClick, ...props }) => {
  const baseStyle = {
    background: 'var(--bg-glass)',
    backdropFilter: 'var(--glass-blur)',
    WebkitBackdropFilter: 'var(--glass-blur)',
    border: 'var(--glass-border)',
    borderRadius: 'var(--radius-lg)',
    padding: 'var(--space-6)',
    transition: 'all var(--transition-normal)',
    position: 'relative',
    overflow: 'hidden',
    cursor: onClick ? 'pointer' : 'default',
  };

  const variants = {
    default: {},
    elevated: {
      background: 'var(--bg-tertiary)',
      boxShadow: 'var(--shadow-md)',
    },
    outlined: {
      background: 'transparent',
      border: '1px solid rgba(255, 255, 255, 0.1)',
    },
    glowing: {
      border: '1px solid rgba(99, 102, 241, 0.2)',
      boxShadow: 'var(--shadow-glow-indigo)',
    },
    subtle: {
      background: 'rgba(12, 17, 32, 0.4)',
      border: '1px solid rgba(255, 255, 255, 0.04)',
    },
  };

  const combinedStyle = {
    ...baseStyle,
    ...(variants[variant] || {}),
    ...style,
  };

  return (
    <div
      className={`glass-card ${glow ? 'glass-card-glow' : ''} ${className}`}
      style={combinedStyle}
      onClick={onClick}
      {...props}
    >
      {children}
    </div>
  );
};

Card.Header = ({ children, className = '', style = {} }) => (
  <div
    className={className}
    style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      marginBottom: 'var(--space-4)',
      ...style,
    }}
  >
    {children}
  </div>
);

Card.Title = ({ children, className = '', icon, subtitle, style = {} }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
    <h3
      className={className}
      style={{
        fontSize: 'var(--font-size-md)',
        fontWeight: 600,
        color: 'var(--text-primary)',
        letterSpacing: '-0.01em',
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        margin: 0,
        ...style,
      }}
    >
      {icon && <span style={{ display: 'flex', alignItems: 'center', opacity: 0.8 }}>{icon}</span>}
      {children}
    </h3>
    {subtitle && (
      <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-muted)' }}>{subtitle}</span>
    )}
  </div>
);

Card.Content = ({ children, className = '', style = {} }) => (
  <div className={className} style={style}>
    {children}
  </div>
);

Card.Footer = ({ children, className = '', style = {} }) => (
  <div
    className={className}
    style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'flex-end',
      gap: 'var(--space-3)',
      marginTop: 'var(--space-4)',
      paddingTop: 'var(--space-4)',
      borderTop: '1px solid rgba(255, 255, 255, 0.06)',
      ...style,
    }}
  >
    {children}
  </div>
);

export default Card;