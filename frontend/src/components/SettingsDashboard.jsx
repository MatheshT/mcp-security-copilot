import React, { useState } from 'react';
import { 
  MODERN_COLORS, 
  SPACING, 
  BORDER_RADIUS, 
  TYPOGRAPHY,
  ANIMATION_CONFIG
} from '../theme/modernTheme';
import AdminPanel from './AdminPanel';

const SettingsDashboard = () => {
  const [activeTab, setActiveTab] = useState('api');

  const tabs = [
    { id: 'api', label: 'API Keys', icon: '🔑' },
    { id: 'windows', label: 'Windows Collectors', icon: '🪟' },
    { id: 'wazuh', label: 'Wazuh Settings', icon: '⚙️' },
    { id: 'users', label: 'User Management', icon: '👥' },
    { id: 'health', label: 'System Health', icon: '💚' }
  ];

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: '100%',
      background: MODERN_COLORS.background,
      color: MODERN_COLORS.text
    }}>
      {/* Header */}
      <div style={{
        padding: `${SPACING.xl}px ${SPACING.xxl}px`,
        borderBottom: `1px solid ${MODERN_COLORS.glassBorder}`,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <div>
          <h1 style={{
            fontSize: TYPOGRAPHY.fontSize['2xl'],
            fontWeight: TYPOGRAPHY.fontWeight.extrabold,
            marginBottom: SPACING.xs
          }}>
            ⚙️ Settings
          </h1>
          <p style={{
            color: MODERN_COLORS.textSecondary,
            fontSize: TYPOGRAPHY.fontSize.md
          }}>
            Configure system settings and integrations
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div style={{
        padding: `${SPACING.lg}px ${SPACING.xxl}px`,
        borderBottom: `1px solid ${MODERN_COLORS.glassBorder}`,
        display: 'flex',
        gap: SPACING.sm,
        flexWrap: 'wrap'
      }}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              padding: `${SPACING.md}px ${SPACING.lg}px`,
              borderRadius: BORDER_RADIUS.lg,
              border: 'none',
              background: activeTab === tab.id 
                ? MODERN_COLORS.primaryGradient 
                : MODERN_COLORS.glass,
              color: activeTab === tab.id ? '#ffffff' : MODERN_COLORS.text,
              cursor: 'pointer',
              fontSize: TYPOGRAPHY.fontSize.sm,
              fontWeight: TYPOGRAPHY.fontWeight.semibold,
              transition: `all ${ANIMATION_CONFIG.duration.fast} ${ANIMATION_CONFIG.easing.smooth}`,
              display: 'flex',
              alignItems: 'center',
              gap: SPACING.sm
            }}
            onMouseOver={(e) => {
              if (activeTab !== tab.id) {
                e.currentTarget.style.background = MODERN_COLORS.glassLight;
              }
            }}
            onMouseOut={(e) => {
              if (activeTab !== tab.id) {
                e.currentTarget.style.background = MODERN_COLORS.glass;
              }
            }}
          >
            <span>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{
        flex: 1,
        padding: `${SPACING.xl}px ${SPACING.xxl}px`,
        overflow: 'auto'
      }}>
        {activeTab === 'api' && (
          <div style={{
            background: MODERN_COLORS.glass,
            borderRadius: BORDER_RADIUS.xl,
            padding: SPACING.xl,
            border: `1px solid ${MODERN_COLORS.glassBorder}`
          }}>
            <h2 style={{ marginBottom: SPACING.lg }}>API Keys</h2>
            <p style={{ color: MODERN_COLORS.textSecondary }}>
              Manage API keys for external integrations and services.
            </p>
            <div style={{
              marginTop: SPACING.lg,
              padding: SPACING.lg,
              background: MODERN_COLORS.surface,
              borderRadius: BORDER_RADIUS.lg,
              border: `1px solid ${MODERN_COLORS.glassBorder}`
            }}>
              <p style={{ fontSize: TYPOGRAPHY.fontSize.sm, color: MODERN_COLORS.textSecondary }}>
                🔑 Configure API keys for VirusTotal, MISP, Shodan, and other threat intelligence sources.
              </p>
            </div>
          </div>
        )}
        {activeTab === 'windows' && (
          <div style={{
            background: MODERN_COLORS.glass,
            borderRadius: BORDER_RADIUS.xl,
            padding: SPACING.xl,
            border: `1px solid ${MODERN_COLORS.glassBorder}`
          }}>
            <h2 style={{ marginBottom: SPACING.lg }}>Windows Collectors</h2>
            <p style={{ color: MODERN_COLORS.textSecondary }}>
              Configure Windows event log collectors and data sources.
            </p>
          </div>
        )}
        {activeTab === 'wazuh' && (
          <div style={{
            background: MODERN_COLORS.glass,
            borderRadius: BORDER_RADIUS.xl,
            padding: SPACING.xl,
            border: `1px solid ${MODERN_COLORS.glassBorder}`
          }}>
            <h2 style={{ marginBottom: SPACING.lg }}>Wazuh Settings</h2>
            <p style={{ color: MODERN_COLORS.textSecondary }}>
              Configure Wazuh integration and alert management settings.
            </p>
          </div>
        )}
        {activeTab === 'users' && (
          <AdminPanel />
        )}
        {activeTab === 'health' && (
          <div style={{
            background: MODERN_COLORS.glass,
            borderRadius: BORDER_RADIUS.xl,
            padding: SPACING.xl,
            border: `1px solid ${MODERN_COLORS.glassBorder}`
          }}>
            <h2 style={{ marginBottom: SPACING.lg }}>System Health</h2>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: SPACING.lg,
              marginTop: SPACING.lg
            }}>
              <div style={{
                background: MODERN_COLORS.surface,
                padding: SPACING.lg,
                borderRadius: BORDER_RADIUS.lg,
                border: `1px solid ${MODERN_COLORS.glassBorder}`
              }}>
                <h3 style={{ fontSize: TYPOGRAPHY.fontSize.md, marginBottom: SPACING.sm }}>API Status</h3>
                <div style={{ color: MODERN_COLORS.success, fontSize: TYPOGRAPHY.fontSize.lg, fontWeight: TYPOGRAPHY.fontWeight.bold }}>
                  ● Online
                </div>
              </div>
              <div style={{
                background: MODERN_COLORS.surface,
                padding: SPACING.lg,
                borderRadius: BORDER_RADIUS.lg,
                border: `1px solid ${MODERN_COLORS.glassBorder}`
              }}>
                <h3 style={{ fontSize: TYPOGRAPHY.fontSize.md, marginBottom: SPACING.sm }}>Database</h3>
                <div style={{ color: MODERN_COLORS.success, fontSize: TYPOGRAPHY.fontSize.lg, fontWeight: TYPOGRAPHY.fontWeight.bold }}>
                  ● Connected
                </div>
              </div>
              <div style={{
                background: MODERN_COLORS.surface,
                padding: SPACING.lg,
                borderRadius: BORDER_RADIUS.lg,
                border: `1px solid ${MODERN_COLORS.glassBorder}`
              }}>
                <h3 style={{ fontSize: TYPOGRAPHY.fontSize.md, marginBottom: SPACING.sm }}>Wazuh</h3>
                <div style={{ color: MODERN_COLORS.success, fontSize: TYPOGRAPHY.fontSize.lg, fontWeight: TYPOGRAPHY.fontWeight.bold }}>
                  ● Connected
                </div>
              </div>
              <div style={{
                background: MODERN_COLORS.surface,
                padding: SPACING.lg,
                borderRadius: BORDER_RADIUS.lg,
                border: `1px solid ${MODERN_COLORS.glassBorder}`
              }}>
                <h3 style={{ fontSize: TYPOGRAPHY.fontSize.md, marginBottom: SPACING.sm }}>VirusTotal</h3>
                <div style={{ color: MODERN_COLORS.success, fontSize: TYPOGRAPHY.fontSize.lg, fontWeight: TYPOGRAPHY.fontWeight.bold }}>
                  ● Connected
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SettingsDashboard;