import React, { useState } from 'react';
import { 
  MODERN_COLORS, 
  SPACING, 
  BORDER_RADIUS, 
  TYPOGRAPHY,
  ANIMATION_CONFIG
} from '../theme/modernTheme';
import Alerts from './detection/Alerts';
import Agents from './detection/Agents';
import EventLogs from './detection/EventLogs';
import SimpleSecurityDashboard from './security/SimpleSecurityDashboard';

const SecurityDashboard = () => {
  const [activeTab, setActiveTab] = useState('overview');

  const tabs = [
    { id: 'overview', label: 'Overview', icon: '📊' },
    { id: 'alerts', label: 'Alerts', icon: '🚨' },
    { id: 'agents', label: 'Agents', icon: '🖥️' },
    { id: 'events', label: 'Event Logs', icon: '📋' }
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
            🛡️ Security Operations
          </h1>
          <p style={{
            color: MODERN_COLORS.textSecondary,
            fontSize: TYPOGRAPHY.fontSize.md
          }}>
            Monitor alerts, agents, and security events in real-time
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
        {activeTab === 'overview' && <SimpleSecurityDashboard />}
        {activeTab === 'alerts' && <Alerts />}
        {activeTab === 'agents' && <Agents />}
        {activeTab === 'events' && <EventLogs />}
      </div>
    </div>
  );
};

export default SecurityDashboard;