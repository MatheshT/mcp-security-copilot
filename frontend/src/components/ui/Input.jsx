import React from 'react';

const Input = ({
  type = 'text',
  value,
  onChange,
  placeholder,
  className = '',
  disabled = false,
  icon = null,
  error = '',
  label = '',
  helperText = '',
  style = {},
  inputStyle = {},
  ...props
}) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', ...style }}>
      {label && (
        <label style={{
          fontSize: 'var(--font-size-sm)',
          fontWeight: 500,
          color: 'var(--text-secondary)',
          letterSpacing: '0.02em',
        }}>
          {label}
        </label>
      )}
      <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
        {icon && (
          <span style={{
            position: 'absolute',
            left: '12px',
            color: 'var(--text-muted)',
            display: 'flex',
            alignItems: 'center',
            pointerEvents: 'none',
            zIndex: 1,
          }}>
            {icon}
          </span>
        )}
        <input
          type={type}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          disabled={disabled}
          className={className}
          style={{
            width: '100%',
            padding: icon ? '10px 14px 10px 40px' : '10px 14px',
            fontFamily: 'var(--font-primary)',
            fontSize: 'var(--font-size-base)',
            color: 'var(--text-primary)',
            background: 'var(--bg-secondary)',
            border: error
              ? '1px solid var(--danger)'
              : '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: 'var(--radius-md)',
            outline: 'none',
            transition: 'all var(--transition-fast)',
            opacity: disabled ? 0.5 : 1,
            ...inputStyle,
          }}
          onFocus={(e) => {
            e.target.style.borderColor = error ? 'var(--danger)' : 'rgba(99, 102, 241, 0.5)';
            e.target.style.boxShadow = error
              ? '0 0 0 3px rgba(239, 68, 68, 0.1)'
              : '0 0 0 3px rgba(99, 102, 241, 0.1)';
          }}
          onBlur={(e) => {
            e.target.style.borderColor = error
              ? 'var(--danger)'
              : 'rgba(255, 255, 255, 0.08)';
            e.target.style.boxShadow = 'none';
          }}
          {...props}
        />
      </div>
      {error && (
        <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--danger)', display: 'flex', alignItems: 'center', gap: '4px' }}>
          ⚠ {error}
        </span>
      )}
      {helperText && !error && (
        <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
          {helperText}
        </span>
      )}
    </div>
  );
};

export default Input;