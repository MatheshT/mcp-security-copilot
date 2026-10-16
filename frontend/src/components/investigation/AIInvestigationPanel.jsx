import React, { useState, useEffect } from 'react';
import api from '../../services/api';
import ComprehensiveInvestigationReport from './ComprehensiveInvestigationReport';
import { 
  MODERN_COLORS as colors, 
  SPACING, 
  BORDER_RADIUS, 
  TYPOGRAPHY,
  ANIMATION_CONFIG,
  glassCardStyle,
  modernButtonStyle,
  modernInputStyle
} from '../../theme/modernTheme';

const AIInvestigationPanel = () => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [investigationData, setInvestigationData] = useState(null);
  const [serviceStatus, setServiceStatus] = useState(null);
  const [mode, setMode] = useState('enhanced');
  const [options, setOptions] = useState({
    useAllTools: true,
    focusWazuh: true
  });

  useEffect(() => {
    loadServiceStatus();
  }, []);

  const loadServiceStatus = async () => {
    try {
      const status = await api.getInvestigationStatus();
      setServiceStatus(status);
      setMode(status.mode || 'enhanced');
    } catch (error) {
      console.error('Failed to load service status:', error);
    }
  };

  const handleInvestigate = async () => {
    if (!query.trim()) return;

    setLoading(true);
    setInvestigationData(null);

    try {
      const result = await api.comprehensiveInvestigation(query, options);
      setInvestigationData(result);
    } catch (error) {
      console.error('Investigation failed:', error);
      alert('Investigation failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleModeSwitch = async (newMode) => {
    try {
      await api.switchInvestigationMode(newMode === 'enhanced');
      setMode(newMode);
      loadServiceStatus();
    } catch (error) {
      console.error('Failed to switch mode:', error);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleInvestigate();
    }
  };

  if (loading) {
    return (
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '400px',
        background: colors.background,
        color: colors.textSecondary
      }}>
        <div style={{
          width: '80px',
          height: '80px',
          border: '4px solid rgba(99, 102, 241, 0.2)',
          borderTop: '4px solid #6366f1',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite',
          marginBottom: SPACING.lg,
          boxShadow: '0 0 40px rgba(99, 102, 241, 0.3)'
        }} />
        <div style={{ fontSize: TYPOGRAPHY.fontSize.lg, fontWeight: TYPOGRAPHY.fontWeight.bold, marginBottom: SPACING.xs }}>
          Running comprehensive AI investigation...
        </div>
        <div style={{ fontSize: TYPOGRAPHY.fontSize.sm, color: colors.textMuted }}>
          Analyzing with {options.useAllTools ? 'all available tools' : 'selected tools'}
        </div>
      </div>
    );
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: colors.background,
      color: colors.text,
      fontFamily: TYPOGRAPHY.fontFamily,
      padding: SPACING.xl,
      position: 'relative',
      overflow: 'hidden'
    }}>
      {/* Animated background */}
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
        marginBottom: SPACING.xl,
        paddingBottom: SPACING.lg,
        borderBottom: `1px solid ${colors.border}`,
        position: 'relative',
        zIndex: 1
      }}>
        <h1 style={{
          fontSize: TYPOGRAPHY.fontSize.xxxl,
          fontWeight: TYPOGRAPHY.fontWeight.extrabold,
          margin: '0 0 SPACING.md 0',
          background: colors.primaryGradient,
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text',
          letterSpacing: TYPOGRAPHY.letterSpacing.tight
        }}>
          🤖 AI Security Investigation
        </h1>
        <p style={{ color: colors.textSecondary, margin: 0, fontSize: TYPOGRAPHY.fontSize.md }}>
          Comprehensive security analysis using all available tools and threat intelligence sources
        </p>
      </div>

      {/* Service Status */}
      {serviceStatus && (
        <div style={{
          ...glassCardStyle,
          marginBottom: SPACING.xl,
          position: 'relative',
          zIndex: 1
        }}>
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center', 
            flexWrap: 'wrap', 
            gap: SPACING.lg 
          }}>
            <div>
              <div style={{ 
                fontSize: TYPOGRAPHY.fontSize.xs, 
                color: colors.textMuted, 
                marginBottom: SPACING.xs,
                fontWeight: TYPOGRAPHY.fontWeight.bold,
                letterSpacing: TYPOGRAPHY.letterSpacing.wider,
                textTransform: 'uppercase'
              }}>
                Service Status
              </div>
              <div style={{ 
                fontSize: TYPOGRAPHY.fontSize.lg, 
                fontWeight: TYPOGRAPHY.fontWeight.bold, 
                color: colors.success,
                display: 'flex',
                alignItems: 'center',
                gap: SPACING.sm
              }}>
                <span style={{
                  width: '10px',
                  height: '10px',
                  borderRadius: '50%',
                  background: colors.success,
                  boxShadow: '0 0 16px rgba(16, 185, 129, 0.6)',
                  animation: 'pulse 2s infinite'
                }} />
                {serviceStatus.status?.toUpperCase()}
              </div>
            </div>
            
            <div>
              <div style={{ 
                fontSize: TYPOGRAPHY.fontSize.xs, 
                color: colors.textMuted, 
                marginBottom: SPACING.xs,
                fontWeight: TYPOGRAPHY.fontWeight.bold,
                letterSpacing: TYPOGRAPHY.letterSpacing.wider,
                textTransform: 'uppercase'
              }}>
                Current Mode
              </div>
              <div style={{ 
                fontSize: TYPOGRAPHY.fontSize.lg, 
                fontWeight: TYPOGRAPHY.fontWeight.bold, 
                color: colors.primary 
              }}>
                {mode.toUpperCase()}
              </div>
            </div>
            
            <div>
              <div style={{ 
                fontSize: TYPOGRAPHY.fontSize.xs, 
                color: colors.textMuted, 
                marginBottom: SPACING.xs,
                fontWeight: TYPOGRAPHY.fontWeight.bold,
                letterSpacing: TYPOGRAPHY.letterSpacing.wider,
                textTransform: 'uppercase'
              }}>
                Orchestrator
              </div>
              <div style={{ 
                fontSize: TYPOGRAPHY.fontSize.md, 
                color: colors.textSecondary,
                fontWeight: TYPOGRAPHY.fontWeight.semibold
              }}>
                {serviceStatus.orchestrator?.default_tools || 'Standard'}
              </div>
            </div>
            
            <div style={{ display: 'flex', gap: SPACING.sm }}>
              <button
                onClick={() => handleModeSwitch('enhanced')}
                style={{
                  padding: `${SPACING.sm} ${SPACING.lg}`,
                  background: mode === 'enhanced' ? `${colors.primary}20` : colors.glass,
                  border: mode === 'enhanced' ? `1px solid ${colors.primary}40` : colors.border,
                  borderRadius: BORDER_RADIUS.md,
                  color: mode === 'enhanced' ? colors.primary : colors.textSecondary,
                  cursor: 'pointer',
                  fontSize: TYPOGRAPHY.fontSize.sm,
                  fontWeight: TYPOGRAPHY.fontWeight.semibold,
                  transition: `all ${ANIMATION_CONFIG.duration.fast} ${ANIMATION_CONFIG.easing.smooth}`
                }}
                onMouseOver={(e) => {
                  e.currentTarget.style.background = mode === 'enhanced' ? `${colors.primary}30` : colors.glassLight;
                  e.currentTarget.style.borderColor = mode === 'enhanced' ? `${colors.primary}60` : colors.borderLight;
                }}
                onMouseOut={(e) => {
                  e.currentTarget.style.background = mode === 'enhanced' ? `${colors.primary}20` : colors.glass;
                  e.currentTarget.style.borderColor = mode === 'enhanced' ? `${colors.primary}40` : colors.border;
                }}
              >
                Enhanced
              </button>
              <button
                onClick={() => handleModeSwitch('standard')}
                style={{
                  padding: `${SPACING.sm} ${SPACING.lg}`,
                  background: mode === 'standard' ? `${colors.primary}20` : colors.glass,
                  border: mode === 'standard' ? `1px solid ${colors.primary}40` : colors.border,
                  borderRadius: BORDER_RADIUS.md,
                  color: mode === 'standard' ? colors.primary : colors.textSecondary,
                  cursor: 'pointer',
                  fontSize: TYPOGRAPHY.fontSize.sm,
                  fontWeight: TYPOGRAPHY.fontWeight.semibold,
                  transition: `all ${ANIMATION_CONFIG.duration.fast} ${ANIMATION_CONFIG.easing.smooth}`
                }}
                onMouseOver={(e) => {
                  e.currentTarget.style.background = mode === 'standard' ? `${colors.primary}30` : colors.glassLight;
                  e.currentTarget.style.borderColor = mode === 'standard' ? `${colors.primary}60` : colors.borderLight;
                }}
                onMouseOut={(e) => {
                  e.currentTarget.style.background = mode === 'standard' ? `${colors.primary}20` : colors.glass;
                  e.currentTarget.style.borderColor = mode === 'standard' ? `${colors.primary}40` : colors.border;
                }}
              >
                Standard
              </button>
            </div>
          </div>
          
          {/* Capabilities */}
          <div style={{ marginTop: SPACING.md, display: 'flex', gap: SPACING.sm, flexWrap: 'wrap' }}>
            {Object.entries(serviceStatus.capabilities || {}).map(([key, value]) => (
              value && (
                <span key={key} style={{
                  padding: `${SPACING.xs} ${SPACING.md}`,
                  background: `${colors.success}15`,
                  border: `1px solid ${colors.success}30`,
                  borderRadius: BORDER_RADIUS.sm,
                  color: colors.success,
                  fontSize: TYPOGRAPHY.fontSize.xs,
                  fontWeight: TYPOGRAPHY.fontWeight.bold,
                  letterSpacing: TYPOGRAPHY.letterSpacing.wider,
                  textTransform: 'uppercase'
                }}>
                  {key.replace('_', ' ')}
                </span>
              )
            ))}
          </div>
        </div>
      )}

      {/* Investigation Query Input */}
      <div style={{
        ...glassCardStyle,
        marginBottom: SPACING.xl,
        position: 'relative',
        zIndex: 1
      }}>
        <div style={{ marginBottom: SPACING.lg }}>
          <label style={{ 
            display: 'block', 
            fontSize: TYPOGRAPHY.fontSize.md, 
            fontWeight: TYPOGRAPHY.fontWeight.bold, 
            color: colors.text,
            marginBottom: SPACING.md 
          }}>
            Investigation Query
          </label>
          <textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Enter your security investigation query... (e.g., 'Investigate IP 192.168.1.1', 'Analyze alert #12345', 'Check file hash abc123...')"
            style={{
              ...modernInputStyle,
              width: '100%',
              minHeight: '120px',
              resize: 'vertical',
              fontSize: TYPOGRAPHY.fontSize.md,
              lineHeight: 1.6
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.borderColor = colors.borderLight;
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.borderColor = colors.border;
            }}
          />
        </div>
        
        {/* Options */}
        <div style={{ 
          display: 'flex', 
          gap: SPACING.lg, 
          flexWrap: 'wrap',
          marginBottom: SPACING.lg
        }}>
          <label style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: SPACING.sm,
            cursor: 'pointer',
            fontSize: TYPOGRAPHY.fontSize.sm,
            color: colors.textSecondary,
            fontWeight: TYPOGRAPHY.fontWeight.semibold
          }}>
            <input
              type="checkbox"
              checked={options.useAllTools}
              onChange={(e) => setOptions({...options, useAllTools: e.target.checked})}
              style={{
                width: '20px',
                height: '20px',
                accentColor: colors.primary,
                cursor: 'pointer'
              }}
            />
            Use All Tools
          </label>
          
          <label style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: SPACING.sm,
            cursor: 'pointer',
            fontSize: TYPOGRAPHY.fontSize.sm,
            color: colors.textSecondary,
            fontWeight: TYPOGRAPHY.fontWeight.semibold
          }}>
            <input
              type="checkbox"
              checked={options.focusWazuh}
              onChange={(e) => setOptions({...options, focusWazuh: e.target.checked})}
              style={{
                width: '20px',
                height: '20px',
                accentColor: colors.primary,
                cursor: 'pointer'
              }}
            />
            Focus Wazuh
          </label>
        </div>
        
        <button
          onClick={handleInvestigate}
          disabled={!query.trim() || loading}
          style={{
            ...modernButtonStyle,
            width: '100%',
            justifyContent: 'center',
            padding: `${SPACING.lg} ${SPACING.xl}`,
            fontSize: TYPOGRAPHY.fontSize.lg,
            opacity: !query.trim() ? 0.5 : 1,
            cursor: !query.trim() ? 'not-allowed' : 'pointer'
          }}
          onMouseOver={(e) => {
            if (query.trim()) {
              e.currentTarget.style.transform = 'translateY(-4px) scale(1.02)';
              e.currentTarget.style.boxShadow = '0 12px 32px rgba(99, 102, 241, 0.5)';
            }
          }}
          onMouseOut={(e) => {
            e.currentTarget.style.transform = 'translateY(0) scale(1)';
            e.currentTarget.style.boxShadow = '0 8px 24px rgba(99, 102, 241, 0.3)';
          }}
        >
          🔍 Start Investigation
        </button>
      </div>

      {/* Investigation Results */}
      {investigationData && (
        <div style={{ position: 'relative', zIndex: 1 }}>
          <ComprehensiveInvestigationReport data={investigationData} />
        </div>
      )}
    </div>
  );
};

export default AIInvestigationPanel;