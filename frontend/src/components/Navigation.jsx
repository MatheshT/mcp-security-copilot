import React, { memo, useCallback } from 'react';
import { MODERN_COLORS as colors, SPACING, BORDER_RADIUS, TYPOGRAPHY, Z_INDEX } from '../theme/modernTheme';
import { cyberAudio } from '../utils/cyberSound';

const MENU_ITEMS = [
  { id: 'home', icon: '🏠', label: 'SOC Command Center', badge: 'HUD', shortcut: '1' },
  { id: 'simulator', icon: '⚡', label: 'Cyber Range Simulator', badge: 'RED/BLUE', shortcut: '2' },
  { id: 'mldetection', icon: '🧠', label: 'ML Threat Detection', badge: 'UEBA', shortcut: 'M' },
  { id: 'soar', icon: '🛡️', label: 'SOAR Active Defense', badge: 'AUTO', shortcut: '3' },
  { id: 'mitre', icon: '🗺️', label: 'MITRE ATT&CK Matrix', badge: 'TTP', shortcut: '4' },
  { id: 'chat', icon: '🤖', label: 'AI Security Copilot', badge: 'SWARM', shortcut: '5' },
  { id: 'alerts', icon: '🚨', label: 'Real Wazuh Alerts', badge: 'LIVE', shortcut: '6' },
  { id: 'investigation', icon: '🔍', label: 'Live AI Investigation', badge: 'DEEP', shortcut: '7' },
  { id: 'intel', icon: '🌐', label: 'Threat Intel Feeds', badge: 'IOC', shortcut: '8' },
  { id: 'reports', icon: '📄', label: 'Forensic Reports', badge: 'PDF', shortcut: '9' },
  { id: 'swarm', icon: '🐝', label: 'AI Swarm & STIX 2.1', badge: 'AGENTIC', shortcut: '0' },
];

const NavItem = memo(({ item, isActive, onClick, collapsed }) => (
  <button
    onClick={() => {
      cyberAudio.playNav();
      onClick(item.id);
    }}
    onMouseEnter={() => cyberAudio.playClick()}
    title={collapsed ? `${item.label} (Alt+${item.shortcut})` : undefined}
    style={{
      width: '100%',
      display: 'flex',
      alignItems: 'center',
      gap: 12,
      padding: collapsed ? '10px 0' : '10px 14px',
      marginBottom: 3,
      borderRadius: 10,
      border: isActive ? '1px solid var(--primary-color, #00f5d4)' : '1px solid transparent',
      background: isActive
        ? 'linear-gradient(135deg, rgba(0, 245, 212, 0.18), rgba(139, 92, 246, 0.12))'
        : 'transparent',
      color: isActive ? 'var(--primary-color, #00f5d4)' : 'var(--text-secondary, #98c1d9)',
      cursor: 'pointer',
      fontSize: '0.8rem',
      fontWeight: isActive ? 700 : 500,
      transition: 'all 160ms cubic-bezier(0.2, 0.8, 0.2, 1)',
      position: 'relative',
      overflow: 'hidden',
      textAlign: 'left',
      justifyContent: collapsed ? 'center' : 'flex-start',
      boxSizing: 'border-box',
      boxShadow: isActive ? '0 0 16px rgba(0, 245, 212, 0.2)' : 'none'
    }}
    onMouseOver={e => {
      if (!isActive) {
        e.currentTarget.style.background = 'rgba(255, 255, 255, 0.04)';
        e.currentTarget.style.color = '#ffffff';
        e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.1)';
      }
    }}
    onMouseOut={e => {
      if (!isActive) {
        e.currentTarget.style.background = 'transparent';
        e.currentTarget.style.color = 'var(--text-secondary, #98c1d9)';
        e.currentTarget.style.borderColor = 'transparent';
      }
    }}
  >
    {/* Active Left Neon Beam */}
    {isActive && (
      <div style={{
        position: 'absolute',
        left: 0,
        top: '15%',
        height: '70%',
        width: 3,
        background: 'var(--primary-color, #00f5d4)',
        boxShadow: '0 0 10px var(--primary-color, #00f5d4)',
        borderRadius: '0 3px 3px 0'
      }} />
    )}

    {/* Module Icon */}
    <span style={{
      fontSize: 18,
      flexShrink: 0,
      filter: isActive ? 'drop-shadow(0 0 8px var(--primary-color, #00f5d4))' : 'none',
      transition: 'filter 150ms'
    }}>
      {item.icon}
    </span>

    {/* Label & Badge */}
    {!collapsed && (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flex: 1, minWidth: 0 }}>
        <span style={{
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          fontSize: '0.78rem',
          letterSpacing: '-0.01em'
        }}>
          {item.label}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <span style={{
            fontSize: '0.58rem',
            fontWeight: 800,
            padding: '1px 5px',
            borderRadius: 4,
            background: isActive ? 'rgba(0, 245, 212, 0.2)' : 'rgba(255, 255, 255, 0.05)',
            color: isActive ? 'var(--primary-color, #00f5d4)' : 'rgba(255, 255, 255, 0.4)',
            fontFamily: 'JetBrains Mono, monospace'
          }}>
            {item.badge}
          </span>
          <span style={{
            fontSize: '0.55rem',
            color: 'rgba(255, 255, 255, 0.3)',
            fontFamily: 'JetBrains Mono, monospace'
          }}>
            {item.shortcut}
          </span>
        </div>
      </div>
    )}
  </button>
));
NavItem.displayName = 'NavItem';

const Navigation = ({ currentView, setCurrentView, user, sidebarCollapsed, setSidebarCollapsed }) => {
  const handleNav = useCallback((id) => setCurrentView(id), [setCurrentView]);

  return (
    <div style={{
      width: sidebarCollapsed ? '80px' : '280px',
      height: '100vh',
      background: 'var(--bg-primary, rgba(4, 6, 14, 0.96))',
      backdropFilter: 'blur(24px)',
      WebkitBackdropFilter: 'blur(24px)',
      borderRight: '1px solid var(--glass-border, rgba(0, 245, 212, 0.18))',
      display: 'flex',
      flexDirection: 'column',
      position: 'fixed',
      left: 0,
      top: 0,
      zIndex: Z_INDEX.sticky,
      transition: 'width 300ms cubic-bezier(0.25, 0.8, 0.25, 1)',
      overflow: 'hidden',
      boxShadow: '4px 0 24px rgba(0, 0, 0, 0.5)'
    }}>
      {/* Dynamic Cyber Radial Aura */}
      <div style={{
        position: 'absolute',
        top: 0, left: 0, right: 0, bottom: 0,
        background: 'radial-gradient(circle at 40% 15%, rgba(0, 245, 212, 0.07) 0%, transparent 60%)',
        pointerEvents: 'none'
      }} />

      {/* Logo Header */}
      <div style={{
        padding: '16px',
        borderBottom: '1px solid var(--glass-border, rgba(0, 245, 212, 0.14))',
        position: 'relative',
        zIndex: 1,
        flexShrink: 0
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              width: 42,
              height: 42,
              borderRadius: 12,
              background: 'var(--gradient-primary, linear-gradient(135deg, #00f5d4, #7928ca))',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 22,
              boxShadow: '0 0 20px var(--primary-color, rgba(0, 245, 212, 0.4))',
              flexShrink: 0
            }}>
              🛡️
            </div>
            {!sidebarCollapsed && (
              <div>
                <div style={{
                  fontSize: '1rem',
                  fontWeight: 900,
                  background: 'var(--gradient-primary, linear-gradient(135deg, #00f5d4, #7928ca))',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  backgroundClip: 'text',
                  letterSpacing: '-0.02em',
                  fontFamily: 'Inter, sans-serif'
                }}>
                  SentinelAI X
                </div>
                <div style={{
                  fontSize: '0.58rem',
                  color: 'var(--primary-color, #00f5d4)',
                  letterSpacing: '0.14em',
                  fontWeight: 800,
                  fontFamily: 'JetBrains Mono, monospace'
                }}>
                  FLAGSHIP CYBER SOC v2.5
                </div>
              </div>
            )}
          </div>
          <button
            onClick={() => {
              cyberAudio.playClick();
              setSidebarCollapsed(!sidebarCollapsed);
            }}
            title={sidebarCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
            style={{
              width: 32,
              height: 32,
              borderRadius: 8,
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              color: 'var(--text-secondary, #98c1d9)',
              cursor: 'pointer',
              fontSize: 14,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 150ms ease',
              flexShrink: 0
            }}
            onMouseOver={e => {
              e.currentTarget.style.background = 'rgba(0, 245, 212, 0.15)';
              e.currentTarget.style.color = 'var(--primary-color, #00f5d4)';
            }}
            onMouseOut={e => {
              e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)';
              e.currentTarget.style.color = 'var(--text-secondary, #98c1d9)';
            }}
          >
            {sidebarCollapsed ? '→' : '←'}
          </button>
        </div>
      </div>

      {/* Nav Items List */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        padding: '12px 10px',
        position: 'relative',
        zIndex: 1
      }}>
        {MENU_ITEMS.map(item => (
          <NavItem
            key={item.id}
            item={item}
            isActive={currentView === item.id}
            onClick={handleNav}
            collapsed={sidebarCollapsed}
          />
        ))}
      </div>

      {/* Footer: User Identity & Telemetry Status */}
      {!sidebarCollapsed ? (
        <div style={{
          padding: '14px 16px',
          borderTop: '1px solid var(--glass-border, rgba(0, 245, 212, 0.14))',
          position: 'relative',
          zIndex: 1,
          flexShrink: 0,
          background: 'rgba(0, 0, 0, 0.25)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{
                width: 34,
                height: 34,
                borderRadius: '50%',
                background: 'linear-gradient(135deg, #1e293b, #0f172a)',
                border: '1px solid var(--primary-color, #00f5d4)',
                boxShadow: '0 0 10px rgba(0, 245, 212, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 15,
                flexShrink: 0
              }}>
                👤
              </div>
              <div style={{ overflow: 'hidden' }}>
                <div style={{
                  fontSize: '0.78rem',
                  fontWeight: 800,
                  color: '#ffffff',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis'
                }}>
                  {user?.username || 'SOC Commander'}
                </div>
                <div style={{
                  fontSize: '0.62rem',
                  color: 'var(--primary-color, #00f5d4)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 5,
                  fontWeight: 700
                }}>
                  <span style={{
                    width: 6,
                    height: 6,
                    borderRadius: '50%',
                    background: '#10b981',
                    boxShadow: '0 0 6px #10b981',
                    display: 'inline-block'
                  }} />
                  2 Agents Active
                </div>
              </div>
            </div>

            <div style={{
              fontSize: '0.6rem',
              color: 'rgba(255, 255, 255, 0.4)',
              textAlign: 'right',
              fontFamily: 'JetBrains Mono, monospace'
            }}>
              <div>SOAR: ARMED</div>
              <div style={{ color: '#10b981' }}>● 100% SECURE</div>
            </div>
          </div>
        </div>
      ) : (
        <div style={{
          padding: '12px 0',
          borderTop: '1px solid var(--glass-border, rgba(0, 245, 212, 0.14))',
          display: 'flex',
          justifyContent: 'center'
        }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 8px #10b981' }} />
        </div>
      )}
    </div>
  );
};

export default memo(Navigation);