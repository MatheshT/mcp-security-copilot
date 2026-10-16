import React from 'react';

const Button = ({
  children,
  onClick,
  variant = 'default',
  size = 'md',
  className = '',
  disabled = false,
  loading = false,
  icon = null,
  iconRight = null,
  type = 'button',
  fullWidth = false,
  style = {},
  ...props
}) => {
  const baseStyle = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    fontFamily: 'var(--font-primary)',
    fontWeight: 500,
    borderRadius: 'var(--radius-md)',
    border: 'none',
    cursor: disabled || loading ? 'not-allowed' : 'pointer',
    transition: 'all var(--transition-normal)',
    opacity: disabled ? 0.5 : 1,
    position: 'relative',
    overflow: 'hidden',
    whiteSpace: 'nowrap',
    letterSpacing: '0.01em',
    width: fullWidth ? '100%' : 'auto',
    textDecoration: 'none',
  };

  const sizes = {
    xs: { padding: '4px 8px', fontSize: 'var(--font-size-xs)' },
    sm: { padding: '6px 12px', fontSize: 'var(--font-size-sm)' },
    md: { padding: '8px 18px', fontSize: 'var(--font-size-base)' },
    lg: { padding: '12px 24px', fontSize: 'var(--font-size-md)' },
    xl: { padding: '14px 32px', fontSize: 'var(--font-size-lg)' },
  };

  const variants = {
    default: {
      background: 'var(--gradient-primary)',
      color: '#ffffff',
      boxShadow: '0 2px 8px rgba(99, 102, 241, 0.3)',
    },
    danger: {
      background: 'var(--gradient-danger)',
      color: '#ffffff',
      boxShadow: '0 2px 8px rgba(239, 68, 68, 0.3)',
    },
    success: {
      background: 'var(--gradient-success)',
      color: '#ffffff',
      boxShadow: '0 2px 8px rgba(16, 185, 129, 0.3)',
    },
    warning: {
      background: 'var(--gradient-warning)',
      color: '#ffffff',
      boxShadow: '0 2px 8px rgba(245, 158, 11, 0.3)',
    },
    ghost: {
      background: 'transparent',
      color: 'var(--text-secondary)',
      border: '1px solid rgba(255, 255, 255, 0.08)',
    },
    outline: {
      background: 'transparent',
      color: 'var(--accent-indigo)',
      border: '1px solid rgba(99, 102, 241, 0.3)',
    },
    secondary: {
      background: 'var(--bg-tertiary)',
      color: 'var(--text-primary)',
      border: '1px solid rgba(255, 255, 255, 0.06)',
    },
    cyan: {
      background: 'var(--gradient-cyan)',
      color: '#ffffff',
      boxShadow: '0 2px 8px rgba(6, 182, 212, 0.3)',
    },
  };

  const combinedStyle = {
    ...baseStyle,
    ...(sizes[size] || sizes.md),
    ...(variants[variant] || variants.default),
    ...style,
  };

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || loading}
      className={className}
      style={combinedStyle}
      {...props}
    >
      {loading && (
        <span
          style={{
            width: '14px',
            height: '14px',
            border: '2px solid rgba(255,255,255,0.3)',
            borderTopColor: '#fff',
            borderRadius: '50%',
            animation: 'spin 0.6s linear infinite',
            flexShrink: 0,
          }}
        />
      )}
      {!loading && icon && <span style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>{icon}</span>}
      {children}
      {iconRight && <span style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>{iconRight}</span>}
    </button>
  );
};

export default Button;