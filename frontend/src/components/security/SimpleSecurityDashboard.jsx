import React, { useState, useEffect } from 'react';
import { collectWazuhLogs, getWazuhAgents, getWazuhAlerts, getWazuhStatistics } from '../../services/api';

// Modern color system
const MODERN_COLORS = {
  background: '#0a0a0f',
  backgroundDeep: '#050508',
  surface: '#12121a',
  surfaceLight: '#1a1a2e',
  primary: '#6366f1',
  primaryLight: '#818cf8',
  secondary: '#8b5cf6',
  accent: '#06b6d4',
  success: '#10b981',
  warning: '#f59e0b',
  danger: '#ef4444',
  text: '#f1f5f9',
  textSecondary: '#94a3b8',
  textMuted: '#64748b',
  glass: 'rgba(255, 255, 255, 0.05)',
  glassBorder: 'rgba(255, 255, 255, 0.1)',
  gradient1: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #06b6d4 100%)',
  gradient2: 'linear-gradient(135deg, #ef4444 0%, #f97316 50%, #f59e0b 100%)',
  gradient3: 'linear-gradient(135deg, #10b981 0%, #06b6d4 100%)',
};

function formatNumber(num) {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toLocaleString();
}

function normalizeWazuhLog(log) {
  const level = Number(log.level ?? log.rule?.level ?? 0);
  const severity = level >= 12 ? 'critical' : level >= 10 ? 'high' : level >= 7 ? 'medium' : 'low';

  return {
    ...log,
    timestamp: log.timestamp || log.date || new Date().toISOString(),
    source: log.source || log.tag || log.location || 'Wazuh Manager',
    computer: log.computer || log.agent?.name || log.agent?.id || log.location || 'Wazuh Manager',
    severity: log.severity || severity,
    message: log.message || log.description || log.full_log || JSON.stringify(log)
  };
}

const SimpleSecurityDashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showLogsModal, setShowLogsModal] = useState(false);
  const [collectedLogs, setCollectedLogs] = useState([]);
  const [collectingLogs, setCollectingLogs] = useState(false);
  const [collectError, setCollectError] = useState(null);
  const [investigationMessage, setInvestigationMessage] = useState(null);

  useEffect(() => {
    let isCancelled = false;

    const loadRealWazuhData = async () => {
      try {
        if (isCancelled) return;
        
        setLoading(true);
        console.log('=== Starting to load real Wazuh data for Security Dashboard ===');

        // Load real Wazuh data
        const [agentsData, alertsData, statsData] = await Promise.all([
          getWazuhAgents().catch(err => {
            console.error('Error loading agents:', err);
            return { agents: [] };
          }),
          getWazuhAlerts().catch(err => {
            console.error('Error loading alerts:', err);
            return { alerts: [] };
          }),
          getWazuhStatistics().catch(err => {
            console.error('Error loading statistics:', err);
            return {};
          })
        ]);

        if (isCancelled) return;

        console.log('Security Dashboard - Agents data:', agentsData);
        console.log('Security Dashboard - Alerts data:', alertsData);
        console.log('Security Dashboard - Statistics data:', statsData);

        // Process real data
        const activeAgents = agentsData.agents?.filter(a => a.status?.toLowerCase() === 'active').length || 0;
        const totalAlerts = alertsData.alerts?.length || 0;
        const criticalAlerts = alertsData.alerts?.filter(a => a.rule?.level >= 10).length || 0;
        const openAlerts = alertsData.alerts?.filter(a => !a.status || a.status === 'open').length || totalAlerts;

        const realStats = {
          total_investigations: statsData.total_investigations || 0,
          active_investigations: statsData.active_investigations || 0,
          total_iocs: statsData.total_iocs || 0,
          high_risk_iocs: statsData.high_risk_iocs || 0,
          total_alerts: totalAlerts,
          open_alerts: openAlerts,
          critical_alerts: criticalAlerts,
          logs_collected_24h: statsData.logs_collected_24h || 0,
          threat_score: criticalAlerts > 5 ? 85 : (criticalAlerts > 0 ? 65 : 30),
          avg_response_time: statsData.avg_response_time || '3.5m',
          system_health: activeAgents > 0 ? '98.5%' : '95.0%'
        };

        console.log('Setting security dashboard stats:', realStats);
        setStats(realStats);
      } catch (err) {
        if (isCancelled) return;
        
        console.error('Error loading real Wazuh data:', err);
        // Fallback to minimal data if API fails
        setStats({
          total_investigations: 0,
          active_investigations: 0,
          total_iocs: 0,
          high_risk_iocs: 0,
          total_alerts: 0,
          open_alerts: 0,
          critical_alerts: 0,
          logs_collected_24h: 0,
          threat_score: 0,
          avg_response_time: 'N/A',
          system_health: 'Unknown'
        });
      } finally {
        if (!isCancelled) {
          console.log('=== Finished loading security dashboard data, setting loading to false ===');
          setLoading(false);
        }
      }
    };

    loadRealWazuhData();

    // Add CSS animations
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
      @keyframes float {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-10px); }
      }
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
    `;
    document.head.appendChild(style);
    
    return () => {
      isCancelled = true;
      document.head.removeChild(style);
    };
  }, []);

  const startInvestigation = () => {
    setInvestigationMessage(null);

    fetch('/api/log-analysis/investigation/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: 'Wazuh Security Investigation',
        description: 'Investigation started from the Security Dashboard',
        investigation_type: 'incident_response',
        log_sources: ['wazuh'],
        time_range_hours: 24,
        auto_start: true
      })
    })
      .then(async response => {
        const data = await response.json();
        if (!response.ok || data.status !== 'success') {
          throw new Error(data.detail || data.message || `HTTP ${response.status}`);
        }
        return data;
      })
      .then(data => {
        setInvestigationMessage(`Investigation ${data.investigation_id} started. Status: planning.`);
      })
      .catch(error => {
        console.error('Investigation start error:', error);
        setInvestigationMessage(`Investigation could not be started: ${error.message}`);
      });
  };

  const collectLogs = async () => {
    setCollectingLogs(true);
    setCollectError(null);
    setCollectedLogs([]);
    
    try {
      const data = await collectWazuhLogs({ hours_back: 24, log_type: 'all' });

      if (data.status !== 'success') {
        throw new Error(data.message || 'Failed to collect logs from Wazuh');
      }

      const logs = Array.isArray(data.logs) ? data.logs.map(normalizeWazuhLog) : [];
      setCollectedLogs(logs);
      setShowLogsModal(true);
      setStats(prev => ({
        ...prev,
        logs_collected_24h: (prev?.logs_collected_24h || 0) + logs.length
      }));
    } catch (error) {
      console.error('Error collecting Wazuh logs:', error);
      setCollectError(`Wazuh log collection failed: ${error.response?.data?.detail || error.message}`);
    } finally {
      setCollectingLogs(false);
    }
  };

  if (loading) {
    return (
      <div style={{ 
        display: 'flex', 
        flexDirection: 'column',
        justifyContent: 'center', 
        alignItems: 'center', 
        minHeight: '100vh',
        background: MODERN_COLORS.backgroundDeep,
        color: MODERN_COLORS.text
      }}>
        {investigationMessage && (
          <div style={{
            margin: '16px 32px 0',
            padding: '14px 18px',
            borderRadius: '12px',
            background: investigationMessage.includes('could not')
              ? 'rgba(239, 68, 68, 0.12)'
              : 'rgba(16, 185, 129, 0.12)',
            border: `1px solid ${investigationMessage.includes('could not')
              ? 'rgba(239, 68, 68, 0.3)'
              : 'rgba(16, 185, 129, 0.3)'}`,
            color: investigationMessage.includes('could not') ? '#fca5a5' : '#6ee7b7',
            fontSize: '14px'
          }}>
            {investigationMessage}
          </div>
        )}

        <div style={{
          width: '60px',
          height: '60px',
          border: `4px solid ${MODERN_COLORS.glassBorder}`,
          borderTop: `4px solid ${MODERN_COLORS.primary}`,
          borderRadius: '50%',
          animation: 'spin 1s linear infinite',
          marginBottom: '20px'
        }} />
        <div style={{ fontSize: '20px', fontWeight: 700, marginBottom: '8px' }}>Loading Security Dashboard</div>
        <div style={{ fontSize: '14px', opacity: 0.7 }}>Connecting to Wazuh security infrastructure</div>
      </div>
    );
  }

  const ModernStatCard = ({ title, value, icon, color, trend, subtitle }) => {
    const colors = {
      primary: MODERN_COLORS.primary,
      secondary: MODERN_COLORS.secondary,
      accent: MODERN_COLORS.accent,
      success: MODERN_COLORS.success,
      warning: MODERN_COLORS.warning,
      danger: MODERN_COLORS.danger
    };
    const accentColor = colors[color] || MODERN_COLORS.primary;
    
    return (
      <div style={{
        position: 'relative',
        background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.08), rgba(139, 92, 246, 0.04))',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        border: `1px solid ${accentColor}25`,
        borderRadius: '20px',
        padding: '28px',
        overflow: 'hidden',
        transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
        cursor: 'pointer'
      }}
      onMouseOver={(e) => {
        e.currentTarget.style.transform = 'translateY(-8px) scale(1.02)';
        e.currentTarget.style.boxShadow = `0 20px 40px ${accentColor}35`;
        e.currentTarget.style.borderColor = `${accentColor}50`;
      }}
      onMouseOut={(e) => {
        e.currentTarget.style.transform = 'translateY(0) scale(1)';
        e.currentTarget.style.boxShadow = '0 8px 32px rgba(0, 0, 0, 0.3)';
        e.currentTarget.style.borderColor = `${accentColor}25`;
      }}
      >
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '4px',
          background: `linear-gradient(90deg, ${accentColor}, ${MODERN_COLORS.secondary})`,
          borderRadius: '20px 20px 0 0'
        }} />
        
        <div style={{ position: 'relative', zIndex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
            <div style={{
              width: '64px',
              height: '64px',
              borderRadius: '16px',
              background: `linear-gradient(135deg, ${accentColor}30, ${accentColor}10)`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '32px',
              boxShadow: `0 8px 24px ${accentColor}40`
            }}>
              {icon}
            </div>
            
            {trend && (
              <div style={{
                padding: '8px 16px',
                borderRadius: '12px',
                background: trend > 0 ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                color: trend > 0 ? '#10b981' : '#ef4444',
                fontSize: '13px',
                fontWeight: 700,
                border: `1px solid ${trend > 0 ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`
              }}>
                {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%
              </div>
            )}
          </div>
          
          <div>
            <div style={{ 
              fontSize: '48px', 
              fontWeight: 800, 
              color: MODERN_COLORS.text,
              lineHeight: 1,
              marginBottom: '8px',
              background: `linear-gradient(135deg, ${MODERN_COLORS.text}, ${accentColor})`,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text'
            }}>
              {typeof value === 'number' ? formatNumber(value) : value}
            </div>
            <div style={{ 
              fontSize: '14px', 
              color: MODERN_COLORS.textSecondary,
              fontWeight: 600,
              letterSpacing: '0.05em',
              textTransform: 'uppercase'
            }}>
              {title}
            </div>
            {subtitle && (
              <div style={{
                fontSize: '11px',
                color: MODERN_COLORS.textMuted,
                fontWeight: 500,
                marginTop: '4px'
              }}>
                {subtitle}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div style={{ 
      padding: '32px', 
      backgroundColor: MODERN_COLORS.background,
      minHeight: '100vh',
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
            🛡️ Security Operations Center
          </h1>
          <p style={{ 
            fontSize: '16px', 
            color: MODERN_COLORS.textSecondary, 
            margin: 0 
          }}>
            Real-time Wazuh security monitoring and analysis
          </p>
        </div>
        <div style={{ display: 'flex', gap: '16px' }}>
          <button
            onClick={collectLogs}
            style={{
              padding: '16px 32px',
              background: 'rgba(255,255,255,0.05)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '16px',
              cursor: 'pointer',
              fontSize: '15px',
              fontWeight: 700,
              color: MODERN_COLORS.text,
              transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
              display: 'flex',
              alignItems: 'center',
              gap: '10px'
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.transform = 'translateY(-4px)';
              e.currentTarget.style.background = 'rgba(255,255,255,0.1)';
              e.currentTarget.style.borderColor = MODERN_COLORS.primary;
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.background = 'rgba(255,255,255,0.05)';
              e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)';
            }}
          >
            📡 Collect Logs
          </button>
          <button
            onClick={startInvestigation}
            style={{
              padding: '16px 32px',
              background: MODERN_COLORS.gradient1,
              border: 'none',
              borderRadius: '16px',
              cursor: 'pointer',
              fontSize: '15px',
              fontWeight: 700,
              color: '#ffffff',
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
            🛡️ Start Investigation
          </button>
        </div>
      </div>

      {/* Critical Alerts Section */}
      {(stats?.critical_alerts > 0 || stats?.open_alerts > 0) && (
        <div style={{ 
          padding: '20px', 
          background: 'rgba(239, 68, 68, 0.1)', 
          border: '1px solid rgba(239, 68, 68, 0.3)', 
          borderRadius: '16px',
          marginBottom: '32px',
          display: 'flex',
          alignItems: 'center',
          gap: '16px',
          position: 'relative',
          zIndex: 1,
          backdropFilter: 'blur(10px)'
        }}>
          <span style={{ 
            fontSize: '32px',
            animation: 'pulse 2s infinite'
          }}>⚠️</span>
          <span style={{ color: MODERN_COLORS.danger, fontSize: '16px', fontWeight: 600 }}>
            {stats?.critical_alerts > 0 && (
              <strong>{stats.critical_alerts} critical alerts</strong>
            )}
            {stats?.critical_alerts > 0 && stats?.open_alerts > 0 && ' and '}
            {stats?.open_alerts > 0 && (
              <span>{stats.open_alerts} open alerts</span>
            )}
            {' '}require immediate attention.
          </span>
        </div>
      )}

      {/* Stats Grid */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', 
        gap: '24px',
        marginBottom: '40px',
        position: 'relative',
        zIndex: 1
      }}>
        <ModernStatCard
          title="Total Investigations"
          value={stats?.total_investigations || 0}
          icon="🔍"
          color="primary"
          trend={5}
          subtitle="Last 30 days"
        />
        <ModernStatCard
          title="Active Investigations"
          value={stats?.active_investigations || 0}
          icon="⚡"
          color="warning"
          trend={-2}
          subtitle="Currently running"
        />
        <ModernStatCard
          title="Total IOCs"
          value={stats?.total_iocs || 0}
          icon="🎯"
          color="secondary"
          trend={8}
          subtitle="All time"
        />
        <ModernStatCard
          title="High Risk IOCs"
          value={stats?.high_risk_iocs || 0}
          icon="⚠️"
          color="danger"
          trend={-3}
          subtitle="Requires attention"
        />
        <ModernStatCard
          title="Total Alerts"
          value={stats?.total_alerts || 0}
          icon="🚨"
          color="primary"
          trend={12}
          subtitle="All time"
        />
        <ModernStatCard
          title="Open Alerts"
          value={stats?.open_alerts || 0}
          icon="🔔"
          color="warning"
          trend={-5}
          subtitle="Pending review"
        />
        <ModernStatCard
          title="Critical Alerts"
          value={stats?.critical_alerts || 0}
          icon="🔴"
          color="danger"
          trend={-8}
          subtitle="Immediate action"
        />
        <ModernStatCard
          title="Logs Collected (24h)"
          value={stats?.logs_collected_24h || 0}
          icon="📡"
          color="success"
          trend={15}
          subtitle="Recent activity"
        />
      </div>

      {/* Logs Collection Modal */}
      {showLogsModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{
            background: MODERN_COLORS.surface,
            borderRadius: '20px',
            padding: '32px',
            maxWidth: '900px',
            width: '90%',
            maxHeight: '90vh',
            overflow: 'auto',
            border: `1px solid ${MODERN_COLORS.glassBorder}`,
            position: 'relative'
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '24px'
            }}>
              <h3 style={{ margin: 0, color: MODERN_COLORS.text, fontSize: '24px', fontWeight: 700 }}>
                📡 Collected Logs
              </h3>
              <button
                onClick={() => setShowLogsModal(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: MODERN_COLORS.textSecondary,
                  fontSize: '28px',
                  cursor: 'pointer',
                  padding: '0'
                }}
              >
                ×
              </button>
            </div>

            {collectError && (
              <div style={{
                padding: '16px',
                background: 'rgba(245, 158, 11, 0.1)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                borderRadius: '12px',
                color: MODERN_COLORS.warning,
                marginBottom: '20px',
                fontSize: '14px'
              }}>
                ⚠️ {collectError}
              </div>
            )}

            {collectingLogs ? (
              <div style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '60px 20px'
              }}>
                <div style={{
                  width: '60px',
                  height: '60px',
                  border: `4px solid ${MODERN_COLORS.glassBorder}`,
                  borderTop: `4px solid ${MODERN_COLORS.primary}`,
                  borderRadius: '50%',
                  animation: 'spin 1s linear infinite',
                  marginBottom: '20px'
                }} />
                <div style={{ color: MODERN_COLORS.text, fontSize: '18px', fontWeight: 600 }}>
                  Collecting logs...
                </div>
                <div style={{ color: MODERN_COLORS.textSecondary, fontSize: '14px', marginTop: '8px' }}>
                  Gathering recent logs from Wazuh Manager
                </div>
              </div>
            ) : collectedLogs.length === 0 ? (
              <div style={{
                padding: '60px 20px',
                textAlign: 'center',
                color: MODERN_COLORS.textSecondary
              }}>
                <div style={{ fontSize: '48px', marginBottom: '16px' }}>📭</div>
                <div style={{ fontSize: '18px', fontWeight: 600, marginBottom: '8px' }}>
                  No logs collected
                </div>
                <div style={{ fontSize: '14px' }}>
                  Try collecting logs from different sources or time ranges
                </div>
              </div>
            ) : (
              <div>
                <div style={{
                  marginBottom: '20px',
                  padding: '16px',
                  background: 'rgba(16, 185, 129, 0.1)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  borderRadius: '12px',
                  color: MODERN_COLORS.success,
                  fontSize: '14px',
                  fontWeight: 600
                }}>
                  ✅ Successfully collected {collectedLogs.length} log entries
                </div>

                <div style={{
                  maxHeight: '400px',
                  overflowY: 'auto',
                  background: 'rgba(0, 0, 0, 0.2)',
                  borderRadius: '12px',
                  border: `1px solid ${MODERN_COLORS.glassBorder}`
                }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{
                        borderBottom: `1px solid ${MODERN_COLORS.glassBorder}`,
                        background: 'rgba(255,255,255,0.05)'
                      }}>
                        <th style={{ padding: '12px', textAlign: 'left', color: MODERN_COLORS.textSecondary, fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' }}>
                          Timestamp
                        </th>
                        <th style={{ padding: '12px', textAlign: 'left', color: MODERN_COLORS.textSecondary, fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' }}>
                          Source
                        </th>
                        <th style={{ padding: '12px', textAlign: 'left', color: MODERN_COLORS.textSecondary, fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' }}>
                          Computer
                        </th>
                        <th style={{ padding: '12px', textAlign: 'left', color: MODERN_COLORS.textSecondary, fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' }}>
                          Severity
                        </th>
                        <th style={{ padding: '12px', textAlign: 'left', color: MODERN_COLORS.textSecondary, fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' }}>
                          Message
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {collectedLogs.map((log, index) => (
                        <tr key={index} style={{
                          borderBottom: `1px solid ${MODERN_COLORS.glassBorder}`,
                          cursor: 'pointer'
                        }}
                        onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.05)'}
                        onMouseOut={(e) => e.currentTarget.style.background = 'transparent'}
                        >
                          <td style={{ padding: '12px', fontSize: '13px', color: MODERN_COLORS.text, whiteSpace: 'nowrap' }}>
                            {new Date(log.timestamp).toLocaleString()}
                          </td>
                          <td style={{ padding: '12px', fontSize: '13px', color: MODERN_COLORS.textSecondary }}>
                            {log.source}
                          </td>
                          <td style={{ padding: '12px', fontSize: '13px', color: MODERN_COLORS.text, fontFamily: 'monospace' }}>
                            {log.computer}
                          </td>
                          <td style={{ padding: '12px' }}>
                            <span style={{
                              padding: '4px 8px',
                              borderRadius: '6px',
                              fontSize: '11px',
                              fontWeight: 600,
                              textTransform: 'uppercase',
                              background: log.severity === 'critical' ? 'rgba(239, 68, 68, 0.2)' :
                                          log.severity === 'high' ? 'rgba(245, 158, 11, 0.2)' :
                                          log.severity === 'medium' ? 'rgba(59, 130, 246, 0.2)' :
                                          'rgba(16, 185, 129, 0.2)',
                              color: log.severity === 'critical' ? '#ef4444' :
                                     log.severity === 'high' ? '#f59e0b' :
                                     log.severity === 'medium' ? '#3b82f6' :
                                     '#10b981'
                            }}>
                              {log.severity}
                            </span>
                          </td>
                          <td style={{ padding: '12px', fontSize: '13px', color: MODERN_COLORS.text, maxWidth: '300px' }}>
                            <div style={{
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            }}>
                              {log.message}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div style={{
                  marginTop: '20px',
                  display: 'flex',
                  gap: '12px',
                  justifyContent: 'flex-end'
                }}>
                  <button
                    onClick={() => setShowLogsModal(false)}
                    style={{
                      padding: '12px 24px',
                      borderRadius: '12px',
                      border: `1px solid ${MODERN_COLORS.glassBorder}`,
                      background: 'transparent',
                      color: MODERN_COLORS.text,
                      cursor: 'pointer',
                      fontSize: '14px',
                      fontWeight: 600
                    }}
                  >
                    Close
                  </button>
                  <button
                    onClick={() => {
                      const csv = [
                        ['Timestamp', 'Source', 'Computer', 'Severity', 'Message'].join(','),
                        ...collectedLogs.map(log => [
                          log.timestamp,
                          log.source,
                          log.computer,
                          log.severity,
                          `"${log.message.replace(/"/g, '""')}"`
                        ].join(','))
                      ].join('\n');

                      const blob = new Blob([csv], { type: 'text/csv' });
                      const url = window.URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `collected-logs-${new Date().toISOString().split('T')[0]}.csv`;
                      a.click();
                      window.URL.revokeObjectURL(url);
                    }}
                    style={{
                      padding: '12px 24px',
                      borderRadius: '12px',
                      border: 'none',
                      background: MODERN_COLORS.gradient1,
                      color: '#ffffff',
                      cursor: 'pointer',
                      fontSize: '14px',
                      fontWeight: 600
                    }}
                  >
                    📥 Export CSV
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default SimpleSecurityDashboard;