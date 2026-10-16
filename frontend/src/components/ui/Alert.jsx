import React, { useState } from 'react';

const Alert = ({ children, variant = 'default', dismissible = false, onDismiss, icon, action, className = '', style = {} }) => {
  const [visible, setVisible] = useState(true);

  const variants = {
    default: {
      background: 'var(--info-bg)',
      borderColor: 'var(--info-border)',
      iconColor: 'var(--info)',
    },
    destructive: {
      background: 'var(--danger-bg)',
      borderColor: 'var(--danger-border)',
      iconColor: 'var(--danger)',
    },
    warning: {
      background: 'var(--warning-bg)',
      borderColor: 'var(--warning-border)',
      iconColor: 'var(--warning)',
    },
    success: {
      background: 'var(--success-bg)',
      borderColor: 'var(--success-border)',
      iconColor: 'var(--success)',
    },
  };

  const v = variants[variant] || variants.default;

  if (!visible) return null;

  const handleDismiss = () => {
    setVisible(false);
    onDismiss?.();
  };

  return (
    <div
      className={className}
      role="alert"
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: '12px',
        padding: '12px 16px',
        borderRadius: 'var(--radius-md)',
        border: `1px solid ${v.borderColor}`,
        background: v.background,
        animation: 'fadeIn 0.3s ease',
        transition: 'all var(--transition-normal)',
        ...style,
      }}
    >
      {icon && <span style={{ flexShrink: 0, marginTop: '2px', color: v.iconColor }}>{icon}</span>}
      <div style={{ flex: 1, fontSize: 'var(--font-size-base)', color: 'var(--text-primary)', lineHeight: 1.5 }}>
        {children}
      </div>
      {action && <div style={{ flexShrink: 0 }}>{action}</div>}
      {dismissible && (
        <button
          onClick={handleDismiss}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            padding: '2px',
            fontSize: '14px',
            lineHeight: 1,
            flexShrink: 0,
            transition: 'color var(--transition-fast)',
          }}
          onMouseEnter={(e) => e.target.style.color = 'var(--text-primary)'}
          onMouseLeave={(e) => e.target.style.color = 'var(--text-muted)'}
        >
          ✕
        </button>
      )}
    </div>
  );
};

Alert.Description = ({ children, className = '' }) => (
  <p className={className} style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', marginTop: '4px', lineHeight: 1.5 }}>
    {children}
  </p>
);

export default Alert;