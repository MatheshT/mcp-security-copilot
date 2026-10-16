import React, { useState, useEffect, useCallback, useMemo } from 'react';
import api from '../../services/api';

/* ─── Enhanced Modern Mock Data ─────────────────────────────────────── */
const MOCK_ALERTS = [
  { id: 1, rule: 'SSH Brute Force',          level: 12, severity: 'Critical', agent: 'web-server-01',   timestamp: new Date(Date.now()-1*60000).toISOString(),  description: 'Multiple failed SSH login attempts from 203.0.113.47', category: 'Authentication', source_ip: '203.0.113.47', destination_ip: '192.168.1.10' },
  { id: 2, rule: 'Malware Detected',         level: 10, severity: 'Critical', agent: 'workstation-15',  timestamp: new Date(Date.now()-4*60000).toISOString(),  description: 'Trojan.GenericKD detected in C:\\Users\\Public', category: 'Malware', source_ip: '10.0.0.45', destination_ip: '192.168.1.15' },
  { id: 3, rule: 'Privilege Escalation',     level: 11, severity: 'Critical', agent: 'db-server-01',    timestamp: new Date(Date.now()-9*60000).toISOString(),  description: 'Unexpected sudo usage by service account', category: 'Privilege', source_ip: '192.168.1.20', destination_ip: '192.168.1.20' },
  { id: 4, rule: 'Lateral Movement',         level: 9,  severity: 'High',     agent: 'dc-01',           timestamp: new Date(Date.now()-15*60000).toISOString(), description: 'Pass-the-hash attempt detected via SMB', category: 'Lateral Movement', source_ip: '192.168.1.30', destination_ip: '192.168.1.1' },
  { id: 5, rule: 'Ransomware Behavior',      level: 10, severity: 'Critical', agent: 'file-server-01',  timestamp: new Date(Date.now()-22*60000).toISOString(), description: 'Mass file encryption pattern detected', category: 'Ransomware', source_ip: '192.168.1.50', destination_ip: '192.168.1.25' },
  { id: 6, rule: 'Data Exfiltration',        level: 8,  severity: 'High',     agent: 'web-server-02',   timestamp: new Date(Date.now()-30*60000).toISOString(), description: 'Large outbound data transfer detected', category: 'Data Loss', source_ip: '192.168.1.11', destination_ip: '203.0.113.100' },
  { id: 7, rule: 'SQL Injection Attempt',    level: 7,  severity: 'Medium',   agent: 'db-server-01',    timestamp: new Date(Date.now()-45*60000).toISOString(), description: 'SQL injection patterns in HTTP requests', category: 'Injection', source_ip: '203.0.113.200', destination_ip: '192.168.1.20' },
];

const MOCK_AGENTS = [
  { id: '001', name: 'web-server-01',  ip: '192.168.1.10',  status: 'active',        last_keepalive: new Date(Date.now()-30000).toISOString(),  os: 'Ubuntu 22.04 LTS',        version: '4.7.3', group: 'web-servers' },
  { id: '002', name: 'web-server-02',  ip: '192.168.1.11',  status: 'active',        last_keepalive: new Date(Date.now()-45000).toISOString(),  os: 'Ubuntu 22.04 LTS',        version: '4.7.3', group: 'web-servers' },
  { id: '003', name: 'db-server-01',   ip: '192.168.1.20',  status: 'active',        last_keepalive: new Date(Date.now()-20000).toISOString(),  os: 'CentOS Stream 9',         version: '4.7.2', group: 'database' },
  { id: '004', name: 'dc-01',          ip: '192.168.1.1',   status: 'active',        last_keepalive: new Date(Date.now()-15000).toISOString(),  os: 'Windows Server 2022',    version: '4.7.3', group: 'domain-controllers' },
  { id: '005', name: 'workstation-15', ip: '192.168.1.15',  status: 'disconnected',  last_keepalive: new Date(Date.now()-3600000).toISOString(), os: 'Windows 11 Pro',          version: '4.7.1', group: 'workstations' },
];

/* ─── Enhanced Modern Color System ─────────────────────────────────────── */
const MODERN_COLORS = {
  background: '#0a0a0f',
  backgroundDeep: '#050508',
  surface: '#12121a',
  surfaceLight: '#1a1a2e',
  surfaceElevated: '#252538',
  primary: '#6366f1',
  primaryLight: '#818cf8',
  primaryDark: '#4f46e5',
  secondary: '#8b5cf6',
  accent: '#06b6d4',
  accentLight: '#22d3ee',
  success: '#10b981',
  successLight: '#34d399',
  warning: '#f59e0b',
  warningLight: '#fbbf24',
  danger: '#ef4444',
  dangerLight: '#f87171',
  text: '#f1f5f9',
  textSecondary: '#94a3b8',
  textMuted: '#64748b',
  textDim: '#475569',
  border: 'rgba(99, 102, 241, 0.1)',
  borderLight: 'rgba(255, 255, 255, 0.15)',
  gradient1: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #06b6d4 100%)',
  gradient2: 'linear-gradient(135deg, #ef4444 0%, #f97316 50%, #f59e0b 100%)',
  gradient3: 'linear-gradient(135deg, #10b981 0%, #06b6d4 100%)',
  gradient4: 'linear-gradient(135deg, #8b5cf6 0%, #ec4899 100%)',
  gradient5: 'linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)',
  glass: 'rgba(255, 255, 255, 0.05)',
  glassLight: 'rgba(255, 255, 255, 0.08)',
  glassDark: 'rgba(0, 0, 0, 0.3)',
  glassBorder: 'rgba(255, 255, 255, 0.1)',
  glassBorderLight: 'rgba(255, 255, 255, 0.15)',
};

const SEVERITY_CONFIG = {
  Critical: { 
    color: '#ef4444', 
    gradient: 'linear-gradient(135deg, #ef4444, #dc2626)',
    bg: 'rgba(239, 68, 68, 0.15)',
    shadow: '0 0 30px rgba(239, 68, 68, 0.3)',
    glow: '0 0 20px rgba(239, 68, 68, 0.5)',
    icon: '🔴'
  },
  High:     { 
    color: '#f97316', 
    gradient: 'linear-gradient(135deg, #f97316, #ea580c)',
    bg: 'rgba(249, 115, 22, 0.15)',
    shadow: '0 0 30px rgba(249, 115, 22, 0.3)',
    glow: '0 0 20px rgba(249, 115, 22, 0.5)',
    icon: '🟠'
  },
  Medium:   { 
    color: '#f59e0b', 
    gradient: 'linear-gradient(135deg, #f59e0b, #d97706)',
    bg: 'rgba(245, 158, 11, 0.15)',
    shadow: '0 0 30px rgba(245, 158, 11, 0.3)',
    glow: '0 0 20px rgba(245, 158, 11, 0.5)',
    icon: '🟡'
  },
  Low:      { 
    color: '#10b981', 
    gradient: 'linear-gradient(135deg, #10b981, #059669)',
    bg: 'rgba(16, 185, 129, 0.15)',
    shadow: '0 0 30px rgba(16, 185, 129, 0.3)',
    glow: '0 0 20px rgba(16, 185, 129, 0.5)',
    icon: '🟢'
  },
};

function timeSince(iso) {
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)  return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  return `${Math.floor(s/3600)}h ago`;
}

function formatNumber(num) {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toLocaleString();
}

function getCategoryColor(category) {
  const colors = {
    'Authentication': '#6366f1',
    'Malware': '#ef4444',
    'Privilege': '#f59e0b',
    'Lateral Movement': '#8b5cf6',
    'Ransomware': '#dc2626',
    'Data Loss': '#f97316',
    'Injection': '#06b6d4',
  };
  return colors[category] || '#64748b';
}

/* ─── Enhanced Modern UI Components ─────────────────────────────────────── */
const GlassCard = ({ children, style = {}, className = '', hoverEffect = true }) => (
  <div 
    style={{
      background: MODERN_COLORS.glass,
      backdropFilter: 'blur(20px)',
      WebkitBackdropFilter: 'blur(20px)',
      border: `1px solid ${MODERN_COLORS.glassBorder}`,
      borderRadius: '24px',
      padding: '32px',
      boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)',
      transition: hoverEffect ? 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)' : 'none',
      position: 'relative',
      overflow: 'hidden',
      ...style
    }}
    className={className}
    onMouseOver={(e) => {
      if (hoverEffect) {
        e.currentTarget.style.transform = 'translateY(-4px)';
        e.currentTarget.style.boxShadow = '0 20px 40px rgba(0, 0, 0, 0.4)';
        e.currentTarget.style.borderColor = MODERN_COLORS.glassBorderLight;
      }
    }}
    onMouseOut={(e) => {
      if (hoverEffect) {
        e.currentTarget.style.transform = 'translateY(0)';
        e.currentTarget.style.boxShadow = '0 8px 32px rgba(0, 0, 0, 0.3)';
        e.currentTarget.style.borderColor = MODERN_COLORS.glassBorder;
      }
    }}
  >
    {/* Subtle animated gradient overlay */}
    <div style={{
      position: 'absolute',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.03), transparent, rgba(139, 92, 246, 0.03))',
      pointerEvents: 'none',
      opacity: 0.5
    }} />
    {children}
  </div>
);

const StatCard = ({ title, value, icon, colorKey, trend, index, subtitle, onClick }) => {
  const cfg = SEVERITY_CONFIG[colorKey] || SEVERITY_CONFIG.Low;
  const colors = ['#6366f1', '#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#ec4899'];
  const accentColor = colors[index % colors.length];
  
  return (
    <div 
      onClick={onClick}
      style={{
        position: 'relative',
        background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.08), rgba(139, 92, 246, 0.04))',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        border: `1px solid ${accentColor}25`,
        borderRadius: '24px',
        padding: '32px',
        overflow: 'hidden',
        transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
        cursor: onClick ? 'pointer' : 'default',
        minHeight: '180px'
      }}
      onMouseOver={(e) => {
        e.currentTarget.style.transform = 'translateY(-8px) scale(1.02)';
        e.currentTarget.style.boxShadow = `0 25px 50px ${accentColor}35`;
        e.currentTarget.style.borderColor = `${accentColor}50`;
        e.currentTarget.style.background = `linear-gradient(135deg, ${accentColor}15, rgba(139, 92, 246, 0.08))`;
      }}
      onMouseOut={(e) => {
        e.currentTarget.style.transform = 'translateY(0) scale(1)';
        e.currentTarget.style.boxShadow = '0 8px 32px rgba(0, 0, 0, 0.3)';
        e.currentTarget.style.borderColor = `${accentColor}25`;
        e.currentTarget.style.background = 'linear-gradient(135deg, rgba(99, 102, 241, 0.08), rgba(139, 92, 246, 0.04))';
      }}
    >
      {/* Animated gradient background */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: `linear-gradient(135deg, ${accentColor}15, transparent, ${accentColor}05)`,
        opacity: 0.6,
        transition: 'opacity 0.3s',
        animation: 'gradientShift 8s ease infinite'
      }} />
      
      {/* Gradient top border */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        height: '4px',
        background: `linear-gradient(90deg, ${accentColor}, ${MODERN_COLORS.secondary}, ${accentColor})`,
        borderRadius: '24px 24px 0 0',
        backgroundSize: '200% 100%',
        animation: 'shimmer 3s ease infinite'
      }} />
      
      {/* Decorative corner accents */}
      <div style={{
        position: 'absolute',
        top: '16px',
        right: '16px',
        width: '40px',
        height: '40px',
        background: `radial-gradient(circle, ${accentColor}20, transparent)`,
        borderRadius: '50%',
        opacity: 0.5
      }} />
      
      <div style={{ position: 'relative', zIndex: 1 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '24px' }}>
          <div style={{
            width: '72px',
            height: '72px',
            borderRadius: '20px',
            background: `linear-gradient(135deg, ${accentColor}25, ${accentColor}10)`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '36px',
            boxShadow: `0 12px 32px ${accentColor}35`,
            border: `1px solid ${accentColor}30`,
            transition: 'transform 0.3s ease'
          }}
          onMouseOver={(e) => {
            e.currentTarget.style.transform = 'scale(1.1) rotate(5deg)';
          }}
          onMouseOut={(e) => {
            e.currentTarget.style.transform = 'scale(1) rotate(0deg)';
          }}
          >
            {icon}
          </div>
          
          {trend !== undefined && (
            <div style={{
              padding: '10px 18px',
              borderRadius: '14px',
              background: trend > 0 ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
              color: trend > 0 ? '#10b981' : '#ef4444',
              fontSize: '13px',
              fontWeight: 800,
              border: `1px solid ${trend > 0 ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backdropFilter: 'blur(10px)'
            }}>
              <span style={{ fontSize: '16px' }}>{trend > 0 ? '↑' : '↓'}</span>
              <span>{Math.abs(trend)}%</span>
            </div>
          )}
        </div>
        
        <div>
          <div style={{ 
            fontSize: '52px', 
            fontWeight: 800, 
            color: MODERN_COLORS.text,
            lineHeight: 1,
            marginBottom: '12px',
            background: `linear-gradient(135deg, ${MODERN_COLORS.text}, ${accentColor})`,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            letterSpacing: '-0.02em',
            textShadow: `0 0 30px ${accentColor}20`
          }}>
            {typeof value === 'number' ? formatNumber(value) : value}
          </div>
          <div style={{ 
            fontSize: '13px', 
            color: MODERN_COLORS.textSecondary,
            fontWeight: 700,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            marginBottom: subtitle ? '8px' : '0'
          }}>
            {title}
          </div>
          {subtitle && (
            <div style={{
              fontSize: '11px',
              color: MODERN_COLORS.textMuted,
              fontWeight: 500,
              letterSpacing: '0.05em'
            }}>
              {subtitle}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const ModernSeverityBar = ({ label, count, max, colorKey, animated = true }) => {
  const cfg = SEVERITY_CONFIG[colorKey] || SEVERITY_CONFIG.Low;
  const pct = max > 0 ? Math.max(5, (count / max) * 100) : 5;
  
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '20px', marginBottom: '20px' }}>
      <span style={{ 
        width: '90px', 
        fontSize: '13px', 
        color: MODERN_COLORS.textSecondary, 
        fontWeight: 800,
        textTransform: 'uppercase',
        letterSpacing: '0.1em',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        <span style={{ fontSize: '16px' }}>{cfg.icon}</span>
        {label}
      </span>
      <div style={{ 
        flex: 1, 
        background: 'rgba(255,255,255,0.04)', 
        borderRadius: '16px', 
        height: '20px', 
        overflow: 'hidden',
        position: 'relative',
        border: `1px solid ${cfg.color}20`,
        boxShadow: 'inset 0 2px 8px rgba(0,0,0,0.2)'
      }}>
        <div style={{
          width: animated ? '0%' : `${pct}%`,
          height: '100%',
          background: cfg.gradient,
          borderRadius: '16px',
          boxShadow: cfg.shadow,
          transition: animated ? 'width 1.5s cubic-bezier(0.4, 0, 0.2, 1)' : 'none',
          position: 'relative',
          animation: animated ? 'progressBar 1.5s cubic-bezier(0.4, 0, 0.2, 1) forwards' : 'none'
        }}>
          <div style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent)',
            animation: 'shimmer 2s infinite'
          }} />
          {/* Glow effect */}
          <div style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: `radial-gradient(circle at ${pct}% 50%, ${cfg.color}40, transparent)`,
            opacity: 0.5
          }} />
        </div>
      </div>
      <span style={{ 
        width: '60px', 
        fontSize: '18px', 
        fontWeight: 800, 
        color: cfg.color, 
        textAlign: 'right',
        textShadow: `0 0 25px ${cfg.color}50`,
        letterSpacing: '-0.02em'
      }}>
        {formatNumber(count)}
      </span>
    </div>
  );
};

const ModernAlertCard = ({ alert, onClick, selected, compact = false }) => {
  const cfg = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.Low;
  const categoryColor = getCategoryColor(alert.category);
  
  return (
    <div 
      onClick={() => onClick(alert)}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: compact ? '16px' : '20px',
        padding: compact ? '16px 20px' : '24px',
        background: selected ? `linear-gradient(135deg, ${cfg.bg}, ${cfg.bg}80)` : 'rgba(255,255,255,0.02)',
        backdropFilter: 'blur(10px)',
        WebkitBackdropFilter: 'blur(10px)',
        borderRadius: '16px',
        border: selected ? `2px solid ${cfg.color}` : `1px solid ${cfg.color}25`,
        cursor: 'pointer',
        transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
        position: 'relative',
        overflow: 'hidden'
      }}
      onMouseOver={(e) => {
        if (!selected) {
          e.currentTarget.style.background = 'rgba(255,255,255,0.06)';
          e.currentTarget.style.transform = 'translateX(8px) scale(1.01)';
          e.currentTarget.style.borderColor = `${cfg.color}50`;
          e.currentTarget.style.boxShadow = `0 8px 24px ${cfg.color}20`;
        }
      }}
      onMouseOut={(e) => {
        if (!selected) {
          e.currentTarget.style.background = 'rgba(255,255,255,0.02)';
          e.currentTarget.style.transform = 'translateX(0) scale(1)';
          e.currentTarget.style.borderColor = `${cfg.color}25`;
          e.currentTarget.style.boxShadow = 'none';
        }
      }}
    >
      {/* Glow effect */}
      <div style={{
        position: 'absolute',
        left: 0,
        top: 0,
        bottom: 0,
        width: selected ? '4px' : '3px',
        background: cfg.gradient,
        boxShadow: cfg.glow,
        transition: 'width 0.3s ease'
      }} />
      
      {/* Status indicator */}
      <div style={{
        width: compact ? '12px' : '16px',
        height: compact ? '12px' : '16px',
        borderRadius: '50%',
        background: cfg.gradient,
        boxShadow: cfg.glow,
        flexShrink: 0,
        animation: 'pulse 2s infinite',
        marginLeft: '8px'
      }} />
      
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ 
          fontSize: compact ? '14px' : '16px', 
          fontWeight: 700, 
          color: MODERN_COLORS.text,
          marginBottom: compact ? '4px' : '8px',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          letterSpacing: '-0.01em'
        }}>
          {alert.rule}
        </div>
        
        {/* Category badge */}
        {alert.category && !compact && (
          <div style={{
            display: 'inline-block',
            fontSize: '11px',
            fontWeight: 700,
            color: categoryColor,
            background: `${categoryColor}15`,
            padding: '4px 10px',
            borderRadius: '8px',
            textTransform: 'uppercase',
            letterSpacing: '0.08em',
            marginBottom: '8px',
            border: `1px solid ${categoryColor}30`
          }}>
            {alert.category}
          </div>
        )}
        
        <div style={{ 
          fontSize: '12px', 
          color: MODERN_COLORS.textSecondary,
          display: 'flex',
          gap: '16px',
          flexWrap: 'wrap',
          alignItems: 'center'
        }}>
          <span style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '6px',
            background: 'rgba(99, 102, 241, 0.08)',
            padding: '4px 12px',
            borderRadius: '8px',
            fontWeight: 600,
            fontSize: '11px',
            textTransform: 'uppercase',
            letterSpacing: '0.05em'
          }}>
            <span style={{ fontSize: '12px' }}>🖥️</span> {alert.agent}
          </span>
          <span style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '6px',
            fontWeight: 500,
            fontSize: '11px'
          }}>
            <span style={{ fontSize: '12px' }}>⏱️</span> {timeSince(alert.timestamp)}
          </span>
          {alert.source_ip && (
            <span style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '6px',
              fontWeight: 500,
              fontSize: '11px'
            }}>
              <span style={{ fontSize: '12px' }}>🌐</span> {alert.source_ip}
            </span>
          )}
        </div>
      </div>
      
      <div style={{
        fontSize: '12px',
        fontWeight: 800,
        color: cfg.color,
        padding: compact ? '6px 14px' : '8px 20px',
        borderRadius: '12px',
        background: cfg.bg,
        whiteSpace: 'nowrap',
        textShadow: `0 0 20px ${cfg.color}50`,
        border: `1px solid ${cfg.color}35`,
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
        backdropFilter: 'blur(10px)'
      }}>
        <span style={{ fontSize: '14px' }}>{cfg.icon}</span>
        {alert.severity}
      </div>
    </div>
  );
};

const ModernAgentCard = ({ agent, onClick }) => {
  const isActive = agent.status === 'active';
  const statusColor = isActive ? MODERN_COLORS.success : MODERN_COLORS.danger;
  const statusGradient = isActive ? 'linear-gradient(135deg, #10b981, #059669)' : 'linear-gradient(135deg, #ef4444, #dc2626)';
  
  return (
    <div 
      onClick={onClick}
      style={{
        padding: '24px',
        background: 'rgba(255,255,255,0.02)',
        backdropFilter: 'blur(10px)',
        WebkitBackdropFilter: 'blur(10px)',
        borderRadius: '20px',
        border: `1px solid ${statusColor}25`,
        transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
        cursor: 'pointer',
        position: 'relative',
        overflow: 'hidden'
      }}
      onMouseOver={(e) => {
        e.currentTarget.style.background = 'rgba(255,255,255,0.06)';
        e.currentTarget.style.transform = 'translateY(-6px) scale(1.02)';
        e.currentTarget.style.borderColor = `${statusColor}50`;
        e.currentTarget.style.boxShadow = `0 12px 32px ${statusColor}25`;
      }}
      onMouseOut={(e) => {
        e.currentTarget.style.background = 'rgba(255,255,255,0.02)';
        e.currentTarget.style.transform = 'translateY(0) scale(1)';
        e.currentTarget.style.borderColor = `${statusColor}25`;
        e.currentTarget.style.boxShadow = 'none';
      }}
    >
      {/* Status indicator line */}
      <div style={{
        position: 'absolute',
        left: 0,
        top: 0,
        bottom: 0,
        width: '4px',
        background: statusGradient,
        boxShadow: `0 0 20px ${statusColor}60`,
        transition: 'width 0.3s ease'
      }} />
      
      {/* Decorative background element */}
      <div style={{
        position: 'absolute',
        top: '-50%',
        right: '-50%',
        width: '100%',
        height: '100%',
        background: `radial-gradient(circle, ${statusColor}08, transparent)`,
        pointerEvents: 'none'
      }} />
      
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '20px',
        paddingLeft: '12px',
        position: 'relative',
        zIndex: 1
      }}>
        <div>
          <span style={{ 
            fontSize: '18px', 
            fontWeight: 800, 
            color: MODERN_COLORS.text,
            display: 'block',
            marginBottom: '4px',
            letterSpacing: '-0.01em'
          }}>
            {agent.name}
          </span>
          {agent.group && (
            <span style={{
              fontSize: '11px',
              fontWeight: 600,
              color: MODERN_COLORS.textMuted,
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              background: 'rgba(99, 102, 241, 0.1)',
              padding: '4px 10px',
              borderRadius: '6px'
            }}>
              {agent.group}
            </span>
          )}
        </div>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: '8px 18px',
          borderRadius: '24px',
          background: isActive ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
          border: `1px solid ${statusColor}35`,
          backdropFilter: 'blur(10px)'
        }}>
          <div style={{
            width: '12px',
            height: '12px',
            borderRadius: '50%',
            background: statusGradient,
            boxShadow: `0 0 20px ${statusColor}80`,
            animation: isActive ? 'pulse 2s infinite' : 'none'
          }} />
          <span style={{
            fontSize: '12px',
            fontWeight: 800,
            color: statusColor,
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            {agent.status}
          </span>
        </div>
      </div>
      
      <div style={{ 
        fontSize: '13px', 
        color: MODERN_COLORS.textSecondary,
        display: 'grid',
        gridTemplateColumns: 'repeat(2, 1fr)',
        gap: '14px',
        paddingLeft: '12px',
        position: 'relative',
        zIndex: 1
      }}>
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '10px',
          background: 'rgba(99, 102, 241, 0.08)',
          padding: '10px 14px',
          borderRadius: '12px',
          border: '1px solid rgba(99, 102, 241, 0.15)',
          transition: 'all 0.2s ease'
        }}
        onMouseOver={(e) => {
          e.currentTarget.style.background = 'rgba(99, 102, 241, 0.15)';
          e.currentTarget.style.transform = 'translateX(4px)';
        }}
        onMouseOut={(e) => {
          e.currentTarget.style.background = 'rgba(99, 102, 241, 0.08)';
          e.currentTarget.style.transform = 'translateX(0)';
        }}
        >
          <span style={{ fontSize: '16px' }}>🌐</span> 
          <span style={{ fontWeight: 600, fontSize: '12px' }}>{agent.ip}</span>
        </div>
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '10px',
          background: 'rgba(139, 92, 246, 0.08)',
          padding: '10px 14px',
          borderRadius: '12px',
          border: '1px solid rgba(139, 92, 246, 0.15)',
          transition: 'all 0.2s ease'
        }}
        onMouseOver={(e) => {
          e.currentTarget.style.background = 'rgba(139, 92, 246, 0.15)';
          e.currentTarget.style.transform = 'translateX(4px)';
        }}
        onMouseOut={(e) => {
          e.currentTarget.style.background = 'rgba(139, 92, 246, 0.08)';
          e.currentTarget.style.transform = 'translateX(0)';
        }}
        >
          <span style={{ fontSize: '16px' }}>💻</span> 
          <span style={{ fontWeight: 600, fontSize: '12px' }}>{agent.os}</span>
        </div>
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '10px',
          background: 'rgba(6, 182, 212, 0.08)',
          padding: '10px 14px',
          borderRadius: '12px',
          border: '1px solid rgba(6, 182, 212, 0.15)',
          transition: 'all 0.2s ease'
        }}
        onMouseOver={(e) => {
          e.currentTarget.style.background = 'rgba(6, 182, 212, 0.15)';
          e.currentTarget.style.transform = 'translateX(4px)';
        }}
        onMouseOut={(e) => {
          e.currentTarget.style.background = 'rgba(6, 182, 212, 0.08)';
          e.currentTarget.style.transform = 'translateX(0)';
        }}
        >
          <span style={{ fontSize: '16px' }}>📦</span> 
          <span style={{ fontWeight: 600, fontSize: '12px' }}>{agent.version}</span>
        </div>
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '10px',
          background: 'rgba(16, 185, 129, 0.08)',
          padding: '10px 14px',
          borderRadius: '12px',
          border: '1px solid rgba(16, 185, 129, 0.15)',
          transition: 'all 0.2s ease'
        }}
        onMouseOver={(e) => {
          e.currentTarget.style.background = 'rgba(16, 185, 129, 0.15)';
          e.currentTarget.style.transform = 'translateX(4px)';
        }}
        onMouseOut={(e) => {
          e.currentTarget.style.background = 'rgba(16, 185, 129, 0.08)';
          e.currentTarget.style.transform = 'translateX(0)';
        }}
        >
          <span style={{ fontSize: '16px' }}>⏱️</span> 
          <span style={{ fontWeight: 600, fontSize: '12px' }}>{timeSince(agent.last_keepalive)}</span>
        </div>
      </div>
    </div>
  );
};

/* ─── Advanced Chart Component ─────────────────────────────────────── */
const MiniChart = ({ data, color, height = 60 }) => {
  const max = Math.max(...data, 1);
  const points = data.map((value, index) => {
    const x = (index / (data.length - 1)) * 100;
    const y = 100 - (value / max) * 100;
    return `${x},${y}`;
  }).join(' ');
  
  return (
    <div style={{ position: 'relative', height: `${height}px`, width: '100%' }}>
      <svg
        viewBox="0 0 100 100"
        preserveAspectRatio="none"
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          overflow: 'visible'
        }}
      >
        <defs>
          <linearGradient id={`gradient-${color}`} x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor={color} stopOpacity="0.3" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
        </defs>
        <polygon
          points={`0,100 ${points} 100,100`}
          fill={`url(#gradient-${color})`}
          style={{ transition: 'all 0.3s ease' }}
        />
        <polyline
          points={points}
          fill="none"
          stroke={color}
          strokeWidth="3"
          strokeLinecap="round"
          strokeLinejoin="round"
          style={{
            filter: `drop-shadow(0 0 6px ${color}40)`,
            transition: 'all 0.3s ease'
          }}
        />
      </svg>
    </div>
  );
};

/* ─── Filter Component ─────────────────────────────────────── */
const FilterBar = ({ filters, onFilterChange, availableFilters }) => {
  return (
    <div style={{
      display: 'flex',
      gap: '12px',
      flexWrap: 'wrap',
      marginBottom: '24px',
      padding: '16px 20px',
      background: 'rgba(255,255,255,0.03)',
      borderRadius: '16px',
      border: '1px solid rgba(255,255,255,0.08)',
      backdropFilter: 'blur(10px)'
    }}>
      {availableFilters.map(filter => (
        <button
          key={filter.key}
          onClick={() => onFilterChange(filter.key)}
          style={{
            padding: '10px 20px',
            borderRadius: '12px',
            background: filters[filter.key] 
              ? MODERN_COLORS.gradient1 
              : 'rgba(255,255,255,0.05)',
            color: filters[filter.key] 
              ? '#ffffff' 
              : MODERN_COLORS.textSecondary,
            border: filters[filter.key] 
              ? 'none' 
              : '1px solid rgba(255,255,255,0.1)',
            fontSize: '13px',
            fontWeight: 700,
            cursor: 'pointer',
            transition: 'all 0.3s ease',
            textTransform: 'uppercase',
            letterSpacing: '0.05em'
          }}
          onMouseOver={(e) => {
            if (!filters[filter.key]) {
              e.currentTarget.style.background = 'rgba(255,255,255,0.1)';
              e.currentTarget.style.borderColor = MODERN_COLORS.primary;
            }
          }}
          onMouseOut={(e) => {
            if (!filters[filter.key]) {
              e.currentTarget.style.background = 'rgba(255,255,255,0.05)';
              e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)';
            }
          }}
        >
          {filter.icon} {filter.label}
        </button>
      ))}
    </div>
  );
};

/* ─── Main Component ─────────────────────────────────────── */
const WazuhDashboard = () => {
  const [alerts, setAlerts]     = useState([]);
  const [agents, setAgents]     = useState([]);
  const [stats, setStats]       = useState(null);
  const [loading, setLoading]   = useState(true);
  const [isLive, setIsLive]     = useState(false);
  const [dataSource, setDataSource] = useState('mock');
  const [countdown, setCountdown] = useState(30);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [showAlertDetail, setShowAlertDetail] = useState(false);
  const [filters, setFilters] = useState({
    critical: false,
    high: false,
    medium: false,
    low: false
  });
  const [viewMode, setViewMode] = useState('grid'); // 'grid' or 'list'
  const [selectedTimeRange, setSelectedTimeRange] = useState('24h');
  const [chartData, setChartData] = useState([12, 19, 15, 25, 22, 30, 28, 35, 20, 40, 38, 45]);

  const handleAlertClick = (alert) => {
    setSelectedAlert(alert);
    setShowAlertDetail(true);
  };

  const handleFilterChange = (filterKey) => {
    setFilters(prev => ({
      ...prev,
      [filterKey]: !prev[filterKey]
    }));
  };

  const filteredAlerts = useMemo(() => {
    if (!Object.values(filters).some(Boolean)) return alerts;
    
    return alerts.filter(alert => {
      if (filters.critical && alert.severity === 'Critical') return true;
      if (filters.high && alert.severity === 'High') return true;
      if (filters.medium && alert.severity === 'Medium') return true;
      if (filters.low && alert.severity === 'Low') return true;
      return false;
    });
  }, [alerts, filters]);

  const availableFilters = [
    { key: 'critical', label: 'Critical', icon: '🔴' },
    { key: 'high', label: 'High', icon: '🟠' },
    { key: 'medium', label: 'Medium', icon: '🟡' },
    { key: 'low', label: 'Low', icon: '🟢' }
  ];

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      console.log('=== Starting Wazuh data load ===');
      console.log('API URL:', import.meta.env.VITE_API_URL || 'http://localhost:8001');
      
      const timeoutPromise = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('API request timeout')), 45000)
      );
      
      const wazuhDashboardData = await Promise.race([
        api.getWazuhDashboard(),
        timeoutPromise
      ]);
      
      console.log('Wazuh dashboard API response:', wazuhDashboardData);
      console.log('Connected status:', wazuhDashboardData?.connected);
      console.log('Data source:', wazuhDashboardData?.source);

      if (wazuhDashboardData && wazuhDashboardData.connected === true) {
        console.log('Using real Wazuh data');
        setIsLive(true);
        setDataSource('wazuh');
        
        const realAlerts = (wazuhDashboardData.recent_alerts || []).map((alert, index) => {
          let ruleLevel = 0;
          let severity = 'Low';
          
          if (typeof alert.rule?.level === 'string') {
            const levelStr = alert.rule.level.toLowerCase();
            if (levelStr === 'error' || levelStr === 'critical') {
              ruleLevel = 12;
              severity = 'Critical';
            } else if (levelStr === 'warning') {
              ruleLevel = 7;
              severity = 'Medium';
            } else if (levelStr === 'info') {
              ruleLevel = 3;
              severity = 'Low';
            } else {
              ruleLevel = parseInt(alert.rule.level, 10) || 0;
              if (ruleLevel >= 12) severity = 'Critical';
              else if (ruleLevel >= 10) severity = 'Critical';
              else if (ruleLevel >= 7) severity = 'High';
              else if (ruleLevel >= 4) severity = 'Medium';
            }
          } else if (typeof alert.rule?.level === 'number') {
            ruleLevel = alert.rule.level;
            if (ruleLevel >= 12) severity = 'Critical';
            else if (ruleLevel >= 10) severity = 'Critical';
            else if (ruleLevel >= 7) severity = 'High';
            else if (ruleLevel >= 4) severity = 'Medium';
          }
          
          return {
            id: alert.id || index,
            rule: alert.rule?.description || 'Security Event',
            level: ruleLevel,
            severity: severity,
            agent: alert.agent?.name || alert.agent?.id || 'Unknown',
            timestamp: alert.timestamp || new Date().toISOString(),
            description: alert.rule?.description || 'Security event detected',
            source_ip: alert.src_ip || alert.source_ip || 'N/A',
            destination_ip: alert.dst_ip || alert.destination_ip || 'N/A'
          };
        });
        
        const realAgents = (wazuhDashboardData.agents_data || []).map(agent => ({
          id: agent.id,
          name: agent.name || agent.id,
          ip: agent.ip || agent.address || 'N/A',
          status: agent.status || 'unknown',
          last_keepalive: agent.lastKeepAlive || agent.last_keepalive || new Date().toISOString(),
          os: agent.os?.name || agent.os || 'Unknown',
          version: agent.version || 'N/A'
        }));
        
        console.log('Transformed agents:', realAgents);
        
        if (realAgents.length === 0) {
          console.log('No real agents available from Wazuh');
        }
        
        const realStats = {
          total_alerts: wazuhDashboardData.alerts?.total || 0,
          critical_alerts: wazuhDashboardData.alerts?.critical || 0,
          high_alerts: wazuhDashboardData.alerts?.high || 0,
          medium_alerts: wazuhDashboardData.alerts?.medium || 0,
          low_alerts: wazuhDashboardData.alerts?.low || 0,
          total_agents: wazuhDashboardData.agents?.total || realAgents.length,
          active_agents: wazuhDashboardData.agents?.active || realAgents.filter(a => a.status === 'active').length
        };
        
        setAlerts(realAlerts);
        setAgents(realAgents);
        setStats(realStats);
        console.log('Real Wazuh data loaded successfully');
      } else {
        if (wazuhDashboardData && wazuhDashboardData.agents_data && wazuhDashboardData.agents_data.length > 0) {
          console.log('Using partial Wazuh data despite connection flag');
          setIsLive(true);
          setDataSource('wazuh_partial');
          
          const partialAgents = wazuhDashboardData.agents_data.map(agent => ({
            id: agent.id,
            name: agent.name || agent.id,
            ip: agent.ip || agent.address || 'N/A',
            status: agent.status || 'unknown',
            last_keepalive: agent.lastKeepAlive || agent.last_keepalive || new Date().toISOString(),
            os: agent.os?.name || agent.os || 'Unknown',
            version: agent.version || 'N/A'
          }));
          
          const partialAlerts = (wazuhDashboardData.recent_alerts || []).map((alert, index) => ({
            id: alert.id || index,
            rule: alert.rule?.description || 'Security Event',
            level: 0,
            severity: 'Low',
            agent: alert.agent?.name || alert.agent?.id || 'Unknown',
            timestamp: alert.timestamp || new Date().toISOString(),
            description: alert.rule?.description || 'Security event detected',
            source_ip: alert.src_ip || alert.source_ip || 'N/A',
            destination_ip: alert.dst_ip || alert.destination_ip || 'N/A'
          }));
          
          setAlerts(partialAlerts);
          setAgents(partialAgents);
          setStats({
            total_alerts: wazuhDashboardData.alerts?.total || partialAlerts.length,
            critical_alerts: wazuhDashboardData.alerts?.critical || 0,
            high_alerts: wazuhDashboardData.alerts?.high || 0,
            medium_alerts: wazuhDashboardData.alerts?.medium || 0,
            low_alerts: wazuhDashboardData.alerts?.low || 0,
            total_agents: wazuhDashboardData.agents?.total || partialAgents.length,
            active_agents: wazuhDashboardData.agents?.active || partialAgents.filter(a => a.status === 'active').length
          });
        } else {
          console.log('Wazuh not connected, using mock data. Connected status:', wazuhDashboardData?.connected);
          console.log('Error details:', wazuhDashboardData?.error);
          setIsLive(false);
          setDataSource('error');
          setAlerts([]);
          setAgents([]);
          setStats({
            total_alerts: 0,
            critical_alerts: 0,
            high_alerts: 0,
            medium_alerts: 0,
            low_alerts: 0,
            total_agents: 0,
            active_agents: 0
          });
        }
      }
    } catch (error) {
      console.error('Error loading Wazuh data:', error);
      console.error('Error message:', error.message);
      console.error('Error response:', error.response?.data);
      
      setIsLive(false);
      setDataSource('error');
      setAlerts([]);
      setAgents([]);
      setStats({
        total_alerts: 0,
        critical_alerts: 0,
        high_alerts: 0,
        medium_alerts: 0,
        low_alerts: 0,
        total_agents: 0,
        active_agents: 0
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, [loadData]);

  useEffect(() => {
    const interval = setInterval(() => {
      setCountdown(prev => (prev > 0 ? prev - 1 : 30));
      // Update chart data with random variations
      setChartData(prev => prev.map(value => {
        const change = Math.floor(Math.random() * 10) - 5;
        return Math.max(5, Math.min(50, value + change));
      }));
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Add CSS animations
  useEffect(() => {
    const style = document.createElement('style');
    style.textContent = `
      @keyframes pulse {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.7; transform: scale(1.1); }
      }
      @keyframes shimmer {
        0% { background-position: -200% 0; }
        100% { background-position: 200% 0; }
      }
      @keyframes gradientShift {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
      }
      @keyframes progressBar {
        from { width: 0%; }
      }
      @keyframes float {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-10px); }
      }
      @keyframes glow {
        0%, 100% { box-shadow: 0 0 20px rgba(99, 102, 241, 0.3); }
        50% { box-shadow: 0 0 40px rgba(99, 102, 241, 0.6); }
      }
    `;
    document.head.appendChild(style);
    return () => document.head.removeChild(style);
  }, []);

  if (loading) {
    return (
      <div style={{ 
        display: 'flex', 
        flexDirection: 'column',
        justifyContent: 'center', 
        alignItems: 'center', 
        minHeight: '100vh',
        background: MODERN_COLORS.backgroundDeep,
        color: MODERN_COLORS.textSecondary
      }}>
        <div style={{
          width: '80px',
          height: '80px',
          border: '4px solid rgba(99, 102, 241, 0.2)',
          borderTop: '4px solid #6366f1',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite',
          marginBottom: '24px',
          boxShadow: '0 0 40px rgba(99, 102, 241, 0.3)'
        }} />
        <div style={{ fontSize: '20px', fontWeight: 700, marginBottom: '8px' }}>Loading SentinelAI</div>
        <div style={{ fontSize: '14px', opacity: 0.7 }}>Connecting to security infrastructure</div>
      </div>
    );
  }

  const maxSeverity = Math.max(
    stats?.critical_alerts || 0,
    stats?.high_alerts || 0,
    stats?.medium_alerts || 0,
    stats?.low_alerts || 0,
    1
  );

  return (
    <div style={{ 
      minHeight: '100vh',
      background: MODERN_COLORS.background,
      color: MODERN_COLORS.text,
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      padding: '32px',
      position: 'relative',
      overflow: 'hidden'
    }}>
      {/* Animated background gradient */}
      <div style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: `
          radial-gradient(circle at 20% 50%, rgba(99, 102, 241, 0.1) 0%, transparent 50%),
          radial-gradient(circle at 80% 20%, rgba(139, 92, 246, 0.1) 0%, transparent 50%),
          radial-gradient(circle at 40% 80%, rgba(6, 182, 212, 0.1) 0%, transparent 50%)
        `,
        pointerEvents: 'none',
        zIndex: 0
      }} />

      {/* Header */}
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center',
        marginBottom: '40px',
        paddingBottom: '24px',
        borderBottom: '1px solid rgba(255,255,255,0.1)',
        position: 'relative',
        zIndex: 1
      }}>
        <div>
          <h1 style={{ 
            fontSize: '36px', 
            fontWeight: 800, 
            margin: '0 0 16px 0',
            background: MODERN_COLORS.gradient1,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            letterSpacing: '-0.02em'
          }}>
            🛡️ SentinelAI Security Dashboard
          </h1>
          <div style={{ 
            marginTop: '16px',
            fontSize: '15px',
            color: isLive ? MODERN_COLORS.success : MODERN_COLORS.warning,
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '12px'
          }}>
            {isLive ? (
              <>
                <span style={{ 
                  width: '10px', 
                  height: '10px', 
                  borderRadius: '50%', 
                  background: MODERN_COLORS.success,
                  boxShadow: '0 0 20px rgba(16, 185, 129, 0.6)',
                  animation: 'pulse 2s infinite'
                }} />
                <span>LIVE DATA — Refreshing in {countdown}s</span>
              </>
            ) : (
              <>
                <span style={{ 
                  width: '10px', 
                  height: '10px', 
                  borderRadius: '50%', 
                  background: MODERN_COLORS.warning,
                  boxShadow: '0 0 20px rgba(245, 158, 11, 0.6)'
                }} />
                <span>DEMO MODE — No live connection</span>
              </>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          {/* View toggle */}
          <div style={{
            display: 'flex',
            background: 'rgba(255,255,255,0.05)',
            borderRadius: '12px',
            padding: '4px',
            border: '1px solid rgba(255,255,255,0.1)'
          }}>
            <button
              onClick={() => setViewMode('grid')}
              style={{
                padding: '10px 16px',
                background: viewMode === 'grid' ? MODERN_COLORS.gradient1 : 'transparent',
                border: 'none',
                borderRadius: '8px',
                color: viewMode === 'grid' ? '#ffffff' : MODERN_COLORS.textSecondary,
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: 700,
                transition: 'all 0.3s ease',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
            >
              ⊞ Grid
            </button>
            <button
              onClick={() => setViewMode('list')}
              style={{
                padding: '10px 16px',
                background: viewMode === 'list' ? MODERN_COLORS.gradient1 : 'transparent',
                border: 'none',
                borderRadius: '8px',
                color: viewMode === 'list' ? '#ffffff' : MODERN_COLORS.textSecondary,
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: 700,
                transition: 'all 0.3s ease',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
            >
              ☰ List
            </button>
          </div>
          
          {/* Time range selector */}
          <select
            value={selectedTimeRange}
            onChange={(e) => setSelectedTimeRange(e.target.value)}
            style={{
              padding: '12px 20px',
              background: 'rgba(255,255,255,0.05)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '12px',
              color: MODERN_COLORS.text,
              fontSize: '14px',
              fontWeight: 600,
              cursor: 'pointer',
              outline: 'none',
              transition: 'all 0.3s ease'
            }}
          >
            <option value="1h">Last 1 Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
          
          <button 
            onClick={loadData}
            style={{
              padding: '16px 32px',
              background: MODERN_COLORS.gradient1,
              border: 'none',
              borderRadius: '16px',
              color: '#ffffff',
              cursor: 'pointer',
              fontSize: '15px',
              fontWeight: 700,
              transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
              boxShadow: '0 8px 24px rgba(99, 102, 241, 0.3)',
              display: 'flex',
              alignItems: 'center',
              gap: '10px'
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.transform = 'translateY(-4px) scale(1.05)';
              e.currentTarget.style.boxShadow = '0 12px 32px rgba(99, 102, 241, 0.5)';
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.transform = 'translateY(0) scale(1)';
              e.currentTarget.style.boxShadow = '0 8px 24px rgba(99, 102, 241, 0.3)';
            }}
          >
            🔄 Refresh
          </button>
        </div>
      </div>

      {/* Stats Grid */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
        gap: '24px',
        marginBottom: '40px',
        position: 'relative',
        zIndex: 1
      }}>
        <StatCard 
          title="TOTAL ALERTS" 
          value={stats?.total_alerts || 0} 
          icon="🚨" 
          colorKey="Critical" 
          trend={5} 
          index={0} 
          subtitle="All time"
          onClick={() => setFilters({ critical: true, high: true, medium: true, low: true })}
        />
        <StatCard 
          title="CRITICAL" 
          value={stats?.critical_alerts || 0} 
          icon="🔴" 
          colorKey="Critical" 
          trend={-2} 
          index={1} 
          subtitle="Immediate action"
          onClick={() => setFilters({ ...filters, critical: !filters.critical })}
        />
        <StatCard 
          title="HIGH" 
          value={stats?.high_alerts || 0} 
          icon="🟠" 
          colorKey="High" 
          trend={8} 
          index={2} 
          subtitle="Requires attention"
          onClick={() => setFilters({ ...filters, high: !filters.high })}
        />
        <StatCard 
          title="ACTIVE AGENTS" 
          value={stats?.active_agents || 0} 
          icon="🖥️" 
          colorKey="Medium" 
          trend={3} 
          index={3} 
          subtitle="Currently online"
        />
        <StatCard 
          title="TOTAL AGENTS" 
          value={stats?.total_agents || 0} 
          icon="📡" 
          colorKey="Low" 
          index={4} 
          subtitle="Registered endpoints"
        />
      </div>

      {/* Alert Trends Chart */}
      <GlassCard style={{ marginBottom: '40px' }}>
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          marginBottom: '24px' 
        }}>
          <h2 style={{ 
            margin: 0, 
            fontSize: '20px', 
            fontWeight: 800,
            background: MODERN_COLORS.gradient1,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text'
          }}>
            📈 Alert Trends (12h)
          </h2>
          <div style={{
            display: 'flex',
            gap: '16px',
            alignItems: 'center'
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: '13px',
              fontWeight: 600,
              color: MODERN_COLORS.textSecondary
            }}>
              <div style={{
                width: '12px',
                height: '12px',
                borderRadius: '50%',
                background: MODERN_COLORS.primary
              }} />
              Alerts
            </div>
          </div>
        </div>
        <MiniChart data={chartData} color={MODERN_COLORS.primary} height={120} />
      </GlassCard>

      {/* Main Content Grid */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: '2fr 1fr',
        gap: '32px',
        position: 'relative',
        zIndex: 1
      }}>
        {/* Left Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
          {/* Overview Card */}
          <GlassCard>
            <h2 style={{ 
              margin: '0 0 32px 0', 
              fontSize: '24px', 
              fontWeight: 800,
              background: MODERN_COLORS.gradient1,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text'
            }}>
              📊 Security Overview
            </h2>
            
            {/* Severity Distribution */}
            <div style={{ marginBottom: '32px' }}>
              <h3 style={{ 
                margin: '0 0 24px 0', 
                fontSize: '14px', 
                color: MODERN_COLORS.textSecondary,
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.1em'
              }}>
                Severity Distribution
              </h3>
              <ModernSeverityBar label="Critical" count={stats?.critical_alerts || 0} max={maxSeverity} colorKey="Critical" />
              <ModernSeverityBar label="High" count={stats?.high_alerts || 0} max={maxSeverity} colorKey="High" />
              <ModernSeverityBar label="Medium" count={stats?.medium_alerts || 0} max={maxSeverity} colorKey="Medium" />
              <ModernSeverityBar label="Low" count={stats?.low_alerts || 0} max={maxSeverity} colorKey="Low" />
            </div>

            {/* Top Rules */}
            <div>
              <h3 style={{ 
                margin: '0 0 24px 0', 
                fontSize: '14px', 
                color: MODERN_COLORS.textSecondary,
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.1em'
              }}>
                Top Attack Patterns
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {alerts.slice(0, 5).map((alert, index) => (
                  <div key={alert.id} style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '16px',
                    padding: '16px 20px',
                    background: 'rgba(255,255,255,0.03)',
                    borderRadius: '12px',
                    border: `1px solid ${SEVERITY_CONFIG[alert.severity]?.color}30`,
                    transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                    cursor: 'pointer'
                  }}
                  onMouseOver={(e) => {
                    e.currentTarget.style.background = 'rgba(255,255,255,0.08)';
                    e.currentTarget.style.transform = 'translateX(8px)';
                    e.currentTarget.style.borderColor = `${SEVERITY_CONFIG[alert.severity]?.color}60`;
                  }}
                  onMouseOut={(e) => {
                    e.currentTarget.style.background = 'rgba(255,255,255,0.03)';
                    e.currentTarget.style.transform = 'translateX(0)';
                    e.currentTarget.style.borderColor = `${SEVERITY_CONFIG[alert.severity]?.color}30`;
                  }}
                  >
                    <span style={{ 
                      fontSize: '14px', 
                      fontWeight: 800, 
                      color: MODERN_COLORS.textMuted,
                      minWidth: '40px',
                      background: 'rgba(99, 102, 241, 0.1)',
                      padding: '8px 16px',
                      borderRadius: '10px',
                      textAlign: 'center'
                    }}>
                      #{index + 1}
                    </span>
                    <span style={{ 
                      flex: 1, 
                      fontSize: '15px', 
                      color: MODERN_COLORS.text,
                      fontWeight: 600
                    }}>
                      {alert.rule}
                    </span>
                    <span style={{ 
                      fontSize: '14px', 
                      color: MODERN_COLORS.textSecondary,
                      minWidth: '40px',
                      textAlign: 'right',
                      fontWeight: 700
                    }}>
                      Lvl {alert.level}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </GlassCard>

          {/* Recent Alerts */}
          <GlassCard>
            <div style={{ 
              display: 'flex', 
              justifyContent: 'space-between', 
              alignItems: 'center', 
              marginBottom: '32px' 
            }}>
              <h2 style={{ 
                margin: 0, 
                fontSize: '24px', 
                fontWeight: 800,
                background: MODERN_COLORS.gradient1,
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                backgroundClip: 'text'
              }}>
                🔔 Recent Alerts
              </h2>
              <div style={{
                fontSize: '14px',
                fontWeight: 600,
                color: MODERN_COLORS.textSecondary,
                background: 'rgba(99, 102, 241, 0.1)',
                padding: '8px 16px',
                borderRadius: '12px'
              }}>
                Showing {filteredAlerts.length} of {alerts.length} alerts
              </div>
            </div>
            
            {/* Filter Bar */}
            <FilterBar 
              filters={filters} 
              onFilterChange={handleFilterChange} 
              availableFilters={availableFilters}
            />
            
            {/* Alerts Grid/List */}
            <div style={{
              display: viewMode === 'grid' ? 'grid' : 'flex',
              gridTemplateColumns: viewMode === 'grid' ? 'repeat(auto-fill, minmax(300px, 1fr))' : 'auto',
              gap: viewMode === 'grid' ? '20px' : '16px',
              flexDirection: 'column'
            }}>
              {filteredAlerts.length > 0 ? (
                filteredAlerts.map((alert) => (
                  <ModernAlertCard
                    key={alert.id}
                    alert={alert}
                    onClick={handleAlertClick}
                    selected={selectedAlert?.id === alert.id}
                    compact={viewMode === 'list'}
                  />
                ))
              ) : (
                <div style={{
                  textAlign: 'center',
                  padding: '60px 20px',
                  color: MODERN_COLORS.textMuted,
                  fontSize: '16px',
                  fontWeight: 500
                }}>
                  <div style={{ fontSize: '48px', marginBottom: '16px' }}>🔍</div>
                  No alerts match the current filters
                </div>
              )}
            </div>
          </GlassCard>
        </div>

        {/* Right Column - Agents */}
        <GlassCard style={{ height: 'fit-content' }}>
          <h2 style={{ 
            margin: '0 0 32px 0', 
            fontSize: '24px', 
            fontWeight: 800,
            background: MODERN_COLORS.gradient1,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text'
          }}>
            🖥️ Protected Assets
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {agents.map(agent => (
              <ModernAgentCard key={agent.id} agent={agent} />
            ))}
          </div>
        </GlassCard>
      </div>

      {/* Alert Detail Modal */}
      {selectedAlert && showAlertDetail && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0,0,0,0.9)',
          backdropFilter: 'blur(20px)',
          WebkitBackdropFilter: 'blur(20px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 1000,
          animation: 'fadeIn 0.3s ease'
        }}
        onClick={() => {
          setSelectedAlert(null);
          setShowAlertDetail(false);
        }}
        >
          <div style={{
            background: 'linear-gradient(135deg, rgba(18, 18, 26, 0.98), rgba(26, 26, 46, 0.95))',
            backdropFilter: 'blur(20px)',
            WebkitBackdropFilter: 'blur(20px)',
            border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: '24px',
            padding: '48px',
            maxWidth: '700px',
            width: '90%',
            maxHeight: '80vh',
            overflow: 'auto',
            boxShadow: '0 32px 64px rgba(0,0,0,0.5)',
            animation: 'slideIn 0.4s cubic-bezier(0.4, 0, 0.2, 1)'
          }}
          onClick={(e) => e.stopPropagation()}
          >
            <div style={{ 
              display: 'flex', 
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '32px'
            }}>
              <h2 style={{ 
                margin: 0, 
                fontSize: '32px', 
                fontWeight: 800,
                background: MODERN_COLORS.gradient1,
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                backgroundClip: 'text'
              }}>
                Alert Details
              </h2>
              <button 
                onClick={() => {
                  setSelectedAlert(null);
                  setShowAlertDetail(false);
                }}
                style={{
                  background: 'rgba(255,255,255,0.1)',
                  border: 'none',
                  color: MODERN_COLORS.textSecondary,
                  fontSize: '32px',
                  cursor: 'pointer',
                  width: '48px',
                  height: '48px',
                  borderRadius: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  transition: 'all 0.3s'
                }}
                onMouseOver={(e) => {
                  e.currentTarget.style.background = 'rgba(239, 68, 68, 0.2)';
                  e.currentTarget.style.color = '#ef4444';
                  e.currentTarget.style.transform = 'rotate(90deg)';
                }}
                onMouseOut={(e) => {
                  e.currentTarget.style.background = 'rgba(255,255,255,0.1)';
                  e.currentTarget.style.color = MODERN_COLORS.textSecondary;
                  e.currentTarget.style.transform = 'rotate(0deg)';
                }}
              >
                ×
              </button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              <div style={{
                padding: '24px',
                background: 'rgba(99, 102, 241, 0.1)',
                border: '1px solid rgba(99, 102, 241, 0.2)',
                borderRadius: '16px'
              }}>
                <label style={{ 
                  fontSize: '12px', 
                  color: MODERN_COLORS.textSecondary,
                  fontWeight: 700,
                  display: 'block',
                  marginBottom: '12px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.1em'
                }}>
                  Rule
                </label>
                <div style={{ 
                  fontSize: '20px', 
                  color: MODERN_COLORS.text,
                  fontWeight: 700
                }}>
                  {selectedAlert.rule}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '20px' }}>
                <div>
                  <label style={{ 
                    fontSize: '12px', 
                    color: MODERN_COLORS.textSecondary,
                    fontWeight: 700,
                    display: 'block',
                    marginBottom: '12px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.1em'
                  }}>
                    Severity
                  </label>
                  <div style={{
                    display: 'inline-block',
                    fontSize: '16px',
                    fontWeight: 800,
                    color: SEVERITY_CONFIG[selectedAlert.severity]?.color,
                    padding: '12px 24px',
                    borderRadius: '12px',
                    background: SEVERITY_CONFIG[selectedAlert.severity]?.bg,
                    border: `1px solid ${SEVERITY_CONFIG[selectedAlert.severity]?.color}40`,
                    textShadow: `0 0 20px ${SEVERITY_CONFIG[selectedAlert.severity]?.color}60`
                  }}>
                    {selectedAlert.severity} (Level {selectedAlert.level})
                  </div>
                </div>
                <div>
                  <label style={{ 
                    fontSize: '12px', 
                    color: MODERN_COLORS.textSecondary,
                    fontWeight: 700,
                    display: 'block',
                    marginBottom: '12px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.1em'
                  }}>
                    Agent
                  </label>
                  <div style={{ 
                    fontSize: '18px', 
                    color: MODERN_COLORS.text,
                    fontWeight: 600
                  }}>
                    {selectedAlert.agent}
                  </div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '20px' }}>
                <div>
                  <label style={{ 
                    fontSize: '12px', 
                    color: MODERN_COLORS.textSecondary,
                    fontWeight: 700,
                    display: 'block',
                    marginBottom: '12px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.1em'
                  }}>
                    Timestamp
                  </label>
                  <div style={{ 
                    fontSize: '16px', 
                    color: MODERN_COLORS.textSecondary
                  }}>
                    {new Date(selectedAlert.timestamp).toLocaleString()}
                  </div>
                </div>
                <div>
                  <label style={{ 
                    fontSize: '12px', 
                    color: MODERN_COLORS.textSecondary,
                    fontWeight: 700,
                    display: 'block',
                    marginBottom: '12px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.1em'
                  }}>
                    Time Ago
                  </label>
                  <div style={{ 
                    fontSize: '16px', 
                    color: MODERN_COLORS.textSecondary
                  }}>
                    {timeSince(selectedAlert.timestamp)}
                  </div>
                </div>
              </div>

              <div>
                <label style={{ 
                  fontSize: '12px', 
                  color: MODERN_COLORS.textSecondary,
                  fontWeight: 700,
                  display: 'block',
                  marginBottom: '12px',
                  textTransform: 'uppercase',
                    letterSpacing: '0.1em'
                }}>
                  Description
                </label>
                <div style={{ 
                  fontSize: '18px', 
                  color: MODERN_COLORS.text,
                  lineHeight: 1.6
                }}>
                  {selectedAlert.description}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default WazuhDashboard;