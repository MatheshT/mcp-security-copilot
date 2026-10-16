import React, { useState } from 'react';
import { 
  MODERN_COLORS, 
  SPACING, 
  BORDER_RADIUS, 
  TYPOGRAPHY,
  ANIMATION_CONFIG
} from '../theme/modernTheme';

const ThreatHuntingDashboard = () => {
  const [activeTab, setActiveTab] = useState('ioc');

  const tabs = [
    { id: 'ioc', label: 'Search IOC', icon: '🔎' },
    { id: 'process', label: 'Process Analysis', icon: '⚙️' },
    { id: 'host', label: 'Host Analysis', icon: '🖥️' },
    { id: 'user', label: 'User Activity', icon: '👤' }
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
            🔎 Threat Hunting
          </h1>
          <p style={{
            color: MODERN_COLORS.textSecondary,
            fontSize: TYPOGRAPHY.fontSize.md
          }}>
            Proactively search for threats and analyze system activity
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div style={{
        padding: `${SPACING.lg}px ${SPACING.xxl}px`,
        borderBottom: `1px solid ${MODERN_COLORS.glassBorder}`,
        display: 'flex',
        gap: SPACING.sm
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
        {activeTab === 'ioc' && (
          <div style={{
            background: MODERN_COLORS.glass,
            borderRadius: BORDER_RADIUS.xl,
            padding: SPACING.xl,
            border: `1px solid ${MODERN_COLORS.glassBorder}`
          }}>
            <h2 style={{ marginBottom: SPACING.lg }}>IOC Search</h2>
            <p style={{ color: MODERN_COLORS.textSecondary }}>
              Search for Indicators of Compromise across your environment and threat intelligence sources.
            </p>
            <div style={{
              marginTop: SPACING.lg,
              padding: SPACING.lg,
              background: MODERN_COLORS.surface,
              borderRadius: BORDER_RADIUS.lg,
              border: `1px solid ${MODERN_COLORS.glassBorder}`
            }}>
              <p style={{ fontSize: TYPOGRAPHY.fontSize.sm, color: MODERN_COLORS.textSecondary }}>
                💡 Use AI Chat to perform IOC searches by asking about specific indicators.
              </p>
            </div>
          </div>
        )}
        {activeTab === 'process' && (
          <div style={{
            background: MODERN_COLORS.glass,
            borderRadius: BORDER_RADIUS.xl,
            padding: SPACING.xl,
            border: `1px solid ${MODERN_COLORS.glassBorder}`
          }}>
            <h2 style={{ marginBottom: SPACING.lg }}>Process Analysis</h2>
            <p style={{ color: MODERN_COLORS.textSecondary }}>
              Analyze running processes for suspicious activity and potential threats.
            </p>
          </div>
        )}
        {activeTab === 'host' && (
          <div style={{
            background: MODERN_COLORS.glass,
            borderRadius: BORDER_RADIUS.xl,
            padding: SPACING.xl,
            border: `1px solid ${MODERN_COLORS.glassBorder}`
          }}>
            <h2 style={{ marginBottom: SPACING.lg }}>Host Analysis</h2>
            <p style={{ color: MODERN_COLORS.textSecondary }}>
              Examine individual hosts for compromise indicators and security issues.
            </p>
          </div>
        )}
        {activeTab === 'user' && (
          <div style={{
            background: MODERN_COLORS.glass,
            borderRadius: BORDER_RADIUS.xl,
            padding: SPACING.xl,
            border: `1px solid ${MODERN_COLORS.glassBorder}`
          }}>
            <h2 style={{ marginBottom: SPACING.lg }}>User Activity</h2>
            <p style={{ color: MODERN_COLORS.textSecondary }}>
              Monitor user behavior for anomalies and potential insider threats.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatHuntingDashboard;