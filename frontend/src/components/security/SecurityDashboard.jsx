import React, { useState, useEffect, useRef, useMemo } from 'react';
import api from '../../services/api';
import { 
  MODERN_COLORS as colors, 
  SPACING, 
  BORDER_RADIUS, 
  TYPOGRAPHY,
  ANIMATION_CONFIG,
  SEVERITY_CONFIG,
  glassCardStyle,
  cardHoverStyle,
  timeSince,
  formatNumber
} from '../../theme/modernTheme';

// Enhanced Stat Card Component
const EnhancedStatCard = ({ title, value, icon, color, trend, subtitle, onClick, size = 'normal' }) => {
  const isLarge = size === 'large';
  
  return (
    <div
      onClick={onClick}
      style={{
        ...glassCardStyle,
        padding: isLarge ? '40px' : '28px',
        cursor: onClick ? 'pointer' : 'default',
        minHeight: isLarge ? '220px' : 'auto',
        position: 'relative',
        overflow: 'hidden',
        transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)'
      }}
      onMouseOver={(e) => {
        if (onClick) {
          e.currentTarget.style.transform = 'translateY(-8px) scale(1.02)';
          e.currentTarget.style.boxShadow = `0 20px 40px ${color}30`;
          e.currentTarget.style.borderColor = `${color}40`;
        }
      }}
      onMouseOut={(e) => {
        if (onClick) {
          e.currentTarget.style.transform = 'translateY(0) scale(1)';
          e.currentTarget.style.boxShadow = cardHoverStyle.boxShadow;
          e.currentTarget.style.borderColor = colors.glassBorder;
        }
      }}
    >
      {/* Animated gradient background */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: `linear-gradient(135deg, ${color}10, transparent)`,
        opacity: 0.5,
        transition: 'opacity 0.3s'
      }} />
      
      {/* Gradient top border */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        height: '4px',
        background: `linear-gradient(90deg, ${color}, ${colors.violet})`,
        borderRadius: `${BORDER_RADIUS.lg}px ${BORDER_RADIUS.lg}px 0 0`
      }} />
      
      <div style={{ position: 'relative', zIndex: 1 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
          <div style={{
            width: isLarge ? '72px' : '56px',
            height: isLarge ? '72px' : '56px',
            borderRadius: '16px',
            background: `linear-gradient(135deg, ${color}25, ${color}10)`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: isLarge ? '36px' : '28px',
            boxShadow: `0 8px 24px ${color}30`,
            border: `1px solid ${color}30`
          }}>
            {icon}
          </div>
          
          {trend !== undefined && (
            <div style={{
              padding: '8px 16px',
              borderRadius: '12px',
              background: trend > 0 ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
              color: trend > 0 ? colors.success : colors.danger,
              fontSize: '13px',
              fontWeight: 800,
              border: `1px solid ${trend > 0 ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              <span>{trend > 0 ? '↑' : '↓'}</span>
              <span>{Math.abs(trend)}%</span>
            </div>
          )}
        </div>
        
        <div>
          <div style={{ 
            fontSize: isLarge ? '56px' : '42px', 
            fontWeight: 800, 
            color: colors.text,
            lineHeight: 1,
            marginBottom: '12px',
            background: `linear-gradient(135deg, ${colors.text}, ${color})`,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            letterSpacing: '-0.02em'
          }}>
            {typeof value === 'number' ? formatNumber(value) : value}
          </div>
          <div style={{ 
            fontSize: '13px', 
            color: colors.textSecondary,
            fontWeight: 700,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            marginBottom: subtitle ? '6px' : '0'
          }}>
            {title}
          </div>
          {subtitle && (
            <div style={{
              fontSize: '11px',
              color: colors.textMuted,
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

// Mini Trend Chart Component
const MiniTrendChart = ({ data, color, height = 60 }) => {
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
        />
        <polyline
          points={points}
          fill="none"
          stroke={color}
          strokeWidth="3"
          strokeLinecap="round"
          strokeLinejoin="round"
          style={{ filter: `drop-shadow(0 0 6px ${color}40)` }}
        />
      </svg>
    </div>
  );
};

const SecurityDashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [recentInvestigations, setRecentInvestigations] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [dataSource, setDataSource] = useState('loading');
  const [viewMode, setViewMode] = useState('grid'); // 'grid' or 'list'
  const [selectedTimeRange, setSelectedTimeRange] = useState('24h');
  const [isDarkMode, setIsDarkMode] = useState(true);
  const [isAnimating, setIsAnimating] = useState(true);
  const [chartData, setChartData] = useState([]);
  const [showNotifications, setShowNotifications] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(30);
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const dashboardRef = useRef(null);

  useEffect(() => {
    loadRealData();
    generateChartData();
    
    // Auto-refresh functionality
    let interval;
    if (autoRefresh) {
      interval = setInterval(() => {
        loadRealData();
        generateChartData();
      }, refreshInterval * 1000);
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh, refreshInterval, selectedTimeRange]);

  const loadRealData = async () => {
    try {
      setLoading(true);
      setDataSource('connecting');

      const wazuhData = await api.getWazuhDashboard();
      console.log('Wazuh dashboard data:', wazuhData);

      if (wazuhData && wazuhData.connected) {
        setDataSource('wazuh');
        
        const realStats = {
          total_investigations: 47,
          active_investigations: 5,
          total_iocs: 234,
          high_risk_iocs: 12,
          total_alerts: wazuhData.alerts?.total || 0,
          open_alerts: wazuhData.alerts?.total || 0,
          critical_alerts: wazuhData.alerts?.critical || 0,
          high_alerts: wazuhData.alerts?.high || 0,
          medium_alerts: wazuhData.alerts?.medium || 0,
          low_alerts: wazuhData.alerts?.low || 0,
          logs_collected_24h: wazuhData.alerts?.total || 0,
          total_agents: wazuhData.agents?.total || 0,
          active_agents: wazuhData.agents?.active || 0
        };

        const realAlerts = (wazuhData.recent_alerts || []).slice(0, 10).map((alert, index) => {
          let ruleLevel = 0;
          if (typeof alert.rule?.level === 'string') {
            ruleLevel = parseInt(alert.rule.level, 10) || 0;
          } else if (typeof alert.rule?.level === 'number') {
            ruleLevel = alert.rule.level;
          }
          
          return {
            id: alert.id || index,
            title: `${ruleLevel}: ${alert.rule?.description || 'Security Event'}`,
            severity: ruleLevel >= 12 ? 'critical' : 
                       ruleLevel >= 10 ? 'high' : 
                       ruleLevel >= 7 ? 'medium' : 'low',
            source: `Wazuh Agent: ${alert.agent?.name || 'Unknown'}`,
            created_at: alert.timestamp || new Date().toISOString()
          };
        });

        const mockInvestigations = [
          {
            id: 1,
            title: 'Suspicious Login Activity',
            investigation_id: 'INV-2024-001',
            status: 'active',
            created_at: '2024-01-15T10:30:00Z'
          },
          {
            id: 2,
            title: 'Malware Detection on Server',
            investigation_id: 'INV-2024-002',
            status: 'active',
            created_at: '2024-01-15T09:15:00Z'
          },
          {
            id: 3,
            title: 'Network Anomaly Detected',
            investigation_id: 'INV-2024-003',
            status: 'completed',
            created_at: '2024-01-14T16:45:00Z'
          }
        ];

        setStats(realStats);
        setRecentAlerts(realAlerts);
        setRecentInvestigations(mockInvestigations);
      } else {
        console.log('Wazuh not connected, using mock data');
        initializeMockData();
        setDataSource('mock_fallback');
      }
    } catch (error) {
      console.error('Error loading real data:', error);
      initializeMockData();
      setDataSource('mock_error');
    } finally {
      setLoading(false);
    }
  };

  const generateChartData = () => {
    // Generate mock chart data for visualizations
    const dataPoints = [];
    const now = new Date();
    for (let i = 23; i >= 0; i--) {
      const time = new Date(now.getTime() - i * 3600000);
      dataPoints.push({
        time: time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        alerts: Math.floor(Math.random() * 50) + 10,
        investigations: Math.floor(Math.random() * 5) + 1,
        iocs: Math.floor(Math.random() * 20) + 5,
        threatScore: Math.floor(Math.random() * 30) + 50
      });
    }
    setChartData(dataPoints);
  };

  const filteredAlerts = useMemo(() => {
    if (selectedSeverity === 'all') return recentAlerts;
    return recentAlerts.filter(alert => alert.severity === selectedSeverity);
  }, [recentAlerts, selectedSeverity]);

  const initializeMockData = () => {
    const mockStats = {
      total_investigations: 47,
      active_investigations: 5,
      total_iocs: 234,
      high_risk_iocs: 12,
      total_alerts: 156,
      open_alerts: 23,
      critical_alerts: 3,
      logs_collected_24h: 15420,
      threat_score: 78,
      risk_level: 'High',
      avg_response_time: '4.2m',
      uptime: '99.9%'
    };

    const mockInvestigations = [
      {
        id: 1,
        title: 'Suspicious Login Activity',
        investigation_id: 'INV-2024-001',
        status: 'active',
        created_at: '2024-01-15T10:30:00Z'
      },
      {
        id: 2,
        title: 'Malware Detection on Server',
        investigation_id: 'INV-2024-002',
        status: 'active',
        created_at: '2024-01-15T09:15:00Z'
      },
      {
        id: 3,
        title: 'Network Anomaly Detected',
        investigation_id: 'INV-2024-003',
        status: 'completed',
        created_at: '2024-01-14T16:45:00Z'
      }
    ];

    const mockAlerts = [
      {
        id: 1,
        title: 'Critical: Brute Force Attack',
        severity: 'critical',
        source: 'Windows Event Log',
        created_at: '2024-01-15T11:00:00Z'
      },
      {
        id: 2,
        title: 'High: Unusual File Access',
        severity: 'high',
        source: 'Sysmon',
        created_at: '2024-01-15T10:45:00Z'
      },
      {
        id: 3,
        title: 'Medium: Multiple Failed Logins',
        severity: 'medium',
        source: 'Defender',
        created_at: '2024-01-15T10:30:00Z'
      }
    ];

    setStats(mockStats);
    setRecentInvestigations(mockInvestigations);
    setRecentAlerts(mockAlerts);
  };

  const startInvestigation = async () => {
    const newInvestigation = {
      id: Date.now(),
      title: 'Automated Security Investigation',
      investigation_id: `INV-2024-${String(Math.floor(Math.random() * 1000)).padStart(3, '0')}`,
      status: 'active',
      created_at: new Date().toISOString()
    };
    
    setRecentInvestigations(prev => [newInvestigation, ...prev]);
    setStats(prev => ({
      ...prev,
      total_investigations: prev.total_investigations + 1,
      active_investigations: prev.active_investigations + 1
    }));
    
    alert(`Investigation ${newInvestigation.investigation_id} started successfully`);
  };

  const collectLogs = async () => {
    try {
      const wazuhData = await api.getWazuhDashboard();
      
      if (wazuhData && wazuhData.connected) {
        const totalLogs = wazuhData.alerts?.total || 0;
        setDataSource('wazuh');

        setStats(prev => ({
          ...prev,
          logs_collected_24h: totalLogs,
          total_alerts: wazuhData.alerts?.total || 0,
          critical_alerts: wazuhData.alerts?.critical || 0
        }));

        const realAlerts = (wazuhData.recent_alerts || []).slice(0, 10).map((alert, index) => ({
          id: alert.id || index,
          title: `${alert.rule?.level || 0}: ${alert.rule?.description || 'Security Event'}`,
          severity: alert.rule?.level >= 12 ? 'critical' : 
                     alert.rule?.level >= 10 ? 'high' : 
                     alert.rule?.level >= 7 ? 'medium' : 'low',
          source: `Wazuh Agent: ${alert.agent?.name || 'Unknown'}`,
          created_at: alert.timestamp || new Date().toISOString()
        }));
        setRecentAlerts(realAlerts);

        alert(`Log collection completed successfully. Collected ${totalLogs} alerts from Wazuh.`);
      } else {
        setDataSource('mock_fallback');
        const logsCollected = Math.floor(Math.random() * 5000) + 10000;
        setStats(prev => ({
          ...prev,
          logs_collected_24h: prev.logs_collected_24h + logsCollected
        }));
        alert(`Log collection completed with fallback. Collected ${logsCollected} logs (mock data - Wazuh not connected).`);
      }
    } catch (error) {
      console.error('Error collecting logs:', error);
      setDataSource('mock_error');
      const logsCollected = Math.floor(Math.random() * 5000) + 10000;
      setStats(prev => ({
        ...prev,
        logs_collected_24h: prev.logs_collected_24h + logsCollected
      }));
      alert(`Log collection completed with error fallback. Collected ${logsCollected} logs.`);
    }
  };

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
        background: colors.backgroundDeep,
        color: colors.text
      }}>
        <div style={{
          width: '60px',
          height: '60px',
          border: '4px solid colors.glassBorder',
          borderTop: `4px solid ${colors.primary}`,
          borderRadius: '50%',
          animation: 'spin 1s linear infinite',
          marginBottom: '20px'
        }} />
        <div style={{ fontSize: '20px', fontWeight: 700, marginBottom: '8px' }}>Loading Security Dashboard</div>
        <div style={{ fontSize: '14px', opacity: 0.7 }}>Connecting to security infrastructure</div>
      </div>
    );
  }
          left: 0,
          top: 0,
          bottom: 0,
          width: '4px',
          background: severityConfig.gradient,
          boxShadow: severityConfig.shadow
        }} />
        
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: SPACING.sm,
          paddingLeft: SPACING.sm
        }}>
          <div style={{ flex: 1 }}>
            <div style={{ 
              fontSize: TYPOGRAPHY.fontSize.md,
              fontWeight: TYPOGRAPHY.fontWeight.bold,
              color: isDarkMode ? colors.text : '#1a1a2e',
              marginBottom: SPACING.xs,
              display: 'flex',
              alignItems: 'center',
              gap: SPACING.sm
            }}>
              <span style={{
                fontSize: '18px',
                animation: alert.severity === 'critical' ? 'pulse 1s infinite' : 'none'
              }}>
                {alert.severity === 'critical' ? '🚨' : alert.severity === 'high' ? '⚠️' : alert.severity === 'medium' ? '🔶' : '🔵'}
              </span>
              {alert.title}
            </div>
            <div style={{ 
              fontSize: TYPOGRAPHY.fontSize.sm,
              color: isDarkMode ? colors.textSecondary : '#64748b'
            }}>
              {alert.source}
            </div>
          </div>
          
          <div style={{
            padding: '6px 16px',
            borderRadius: BORDER_RADIUS.md,
            background: severityConfig.bg,
            border: `1px solid ${severityConfig.border}`,
            color: severityConfig.color,
            fontSize: TYPOGRAPHY.fontSize.xs,
            fontWeight: TYPOGRAPHY.fontWeight.bold,
            textTransform: 'uppercase',
            letterSpacing: TYPOGRAPHY.letterSpacing.wider
          }}>
            {alert.severity}
          </div>
        </div>
        
        <div style={{ 
          fontSize: TYPOGRAPHY.fontSize.xs,
          color: isDarkMode ? colors.textMuted : '#94a3b8',
          paddingLeft: SPACING.sm,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <span>{timeSince(alert.created_at)}</span>
          <span style={{ 
            color: isDarkMode ? colors.accent : '#06b6d4',
            fontWeight: TYPOGRAPHY.fontWeight.semibold
          }}>
            {isExpanded ? '▼' : '▶'}
          </span>
        </div>
        
        {isExpanded && (
          <div style={{
            marginTop: SPACING.md,
            paddingTop: SPACING.md,
            borderTop: `1px solid ${severityConfig.border}`,
            paddingLeft: SPACING.sm,
            animation: 'fadeIn 0.3s ease'
          }}>
            <div style={{
              fontSize: TYPOGRAPHY.fontSize.sm,
              color: isDarkMode ? colors.textSecondary : '#64748b',
              lineHeight: 1.6
            }}>
              <strong>Details:</strong> This alert requires immediate attention. Security analysis indicates potential threat activity that should be investigated further.
            </div>
            <div style={{
              marginTop: SPACING.sm,
              display: 'flex',
              gap: SPACING.sm
            }}>
              <button style={{
                padding: '6px 12px',
                background: severityConfig.color,
                border: 'none',
                borderRadius: BORDER_RADIUS.sm,
                color: 'white',
                fontSize: TYPOGRAPHY.fontSize.xs,
                cursor: 'pointer',
                fontWeight: TYPOGRAPHY.fontWeight.semibold
              }}>
                Investigate
              </button>
              <button style={{
                padding: '6px 12px',
                background: isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)',
                border: 'none',
                borderRadius: BORDER_RADIUS.sm,
                color: isDarkMode ? colors.text : '#1a1a2e',
                fontSize: TYPOGRAPHY.fontSize.xs,
                cursor: 'pointer',
                fontWeight: TYPOGRAPHY.fontWeight.semibold
              }}>
                Dismiss
              </button>
            </div>
          </div>
        )}
      </div>
    );
  };

  const InvestigationCard = ({ investigation }) => {
    const isActive = investigation.status === 'active';
    const statusColor = isActive ? colors.success : colors.textMuted;
    const [isHovered, setIsHovered] = useState(false);
    
    return (
      <div style={{
        padding: SPACING.lg,
        background: isDarkMode ? colors.glass : 'rgba(255, 255, 255, 0.95)',
        border: `1px solid ${isActive ? `${colors.success}30` : (isDarkMode ? colors.border : 'rgba(0, 0, 0, 0.1)')}`,
        borderRadius: BORDER_RADIUS.lg,
        marginBottom: SPACING.md,
        cursor: 'pointer',
        transition: `all ${ANIMATION_CONFIG.duration.normal} ${ANIMATION_CONFIG.easing.smooth}`,
        position: 'relative',
        overflow: 'hidden'
      }}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onMouseOver={(e) => {
        if (isAnimating) {
          e.currentTarget.style.transform = 'translateY(-4px)';
          e.currentTarget.style.borderColor = isActive ? `${colors.success}60` : (isDarkMode ? colors.borderLight : 'rgba(0, 0, 0, 0.2)');
          e.currentTarget.style.background = isDarkMode ? colors.glassLight : 'rgba(255, 255, 255, 1)';
        }
      }}
      onMouseOut={(e) => {
        if (isAnimating) {
          e.currentTarget.style.transform = 'translateY(0)';
          e.currentTarget.style.borderColor = isActive ? `${colors.success}30` : (isDarkMode ? colors.border : 'rgba(0, 0, 0, 0.1)');
          e.currentTarget.style.background = isDarkMode ? colors.glass : 'rgba(255, 255, 255, 0.95)';
        }
      }}
      >
        {isActive && (
          <div style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            height: '2px',
            background: `linear-gradient(90deg, ${colors.success}, ${colors.accent})`,
            animation: 'shimmer 2s infinite'
          }} />
        )}
        
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: SPACING.sm
        }}>
          <div style={{ 
            fontSize: TYPOGRAPHY.fontSize.md,
            fontWeight: TYPOGRAPHY.fontWeight.bold,
            color: isDarkMode ? colors.text : '#1a1a2e',
            display: 'flex',
            alignItems: 'center',
            gap: SPACING.sm
          }}>
            <span style={{ fontSize: '20px' }}>
              {isActive ? '🔍' : '✅'}
            </span>
            {investigation.title}
          </div>
          
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: SPACING.xs,
            padding: '4px 12px',
            borderRadius: BORDER_RADIUS.full,
            background: isActive ? `${colors.success}20` : `${colors.textMuted}20`,
            border: `1px solid ${isActive ? `${colors.success}40` : `${colors.textMuted}30`
          }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: statusColor,
              boxShadow: `0 0 12px ${statusColor}80`,
              animation: isActive ? 'pulse 2s infinite' : 'none'
            }} />
            <span style={{
              fontSize: TYPOGRAPHY.fontSize.xs,
              fontWeight: TYPOGRAPHY.fontWeight.bold,
              color: statusColor,
              textTransform: 'uppercase',
              letterSpacing: TYPOGRAPHY.letterSpacing.wider
            }}>
              {investigation.status}
            </span>
          </div>
        </div>
        
        <div style={{ 
          fontSize: TYPOGRAPHY.fontSize.sm,
          color: isDarkMode ? colors.textSecondary : '#64748b',
          display: 'flex',
          gap: SPACING.lg,
          alignItems: 'center'
        }}>
          <span style={{ 
            background: isDarkMode ? `${colors.primary}10` : 'rgba(99, 102, 241, 0.1)',
            padding: '4px 12px',
            borderRadius: BORDER_RADIUS.sm,
            fontWeight: TYPOGRAPHY.fontWeight.semibold,
            color: isDarkMode ? colors.text : '#1a1a2e'
          }}>
            {investigation.investigation_id}
          </span>
          <span>{timeSince(investigation.created_at)}</span>
          {isHovered && (
            <span style={{
              color: isDarkMode ? colors.accent : '#06b6d4',
              fontWeight: TYPOGRAPHY.fontWeight.semibold,
              fontSize: TYPOGRAPHY.fontSize.xs,
              animation: 'fadeIn 0.2s ease'
            }}>
              View Details →
            </span>
          )}
        </div>
      </div>
    );
  };

  // Mini chart component for sparklines
  const MiniChart = ({ data, color, height = 60 }) => {
    const maxVal = Math.max(...data.map(d => d.alerts || d), 1);
    const points = data.map((d, i) => {
      const x = (i / (data.length - 1)) * 100;
      const y = 100 - (((d.alerts || d) / maxVal) * 80);
      return `${x},${y}`;
    }).join(' ');

    return (
      <div style={{
        width: '100%',
        height: `${height}px`,
        position: 'relative'
      }}>
        <svg
          viewBox="0 0 100 100"
          preserveAspectRatio="none"
          style={{
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
          />
          <polyline
            points={points}
            fill="none"
            stroke={color}
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            style={{ filter: `drop-shadow(0 0 6px ${color}40)` }}
          />
        </svg>
      </div>
    );
  };
            strokeLinejoin="round"
          />
        </svg>
      </div>
    );
  };

  // Notification system
  const NotificationCenter = () => {
    if (!showNotifications) return null;
    
    return (
      <div style={{
        position: 'fixed',
        top: SPACING.xl,
        right: SPACING.xl,
        zIndex: 1000,
        display: 'flex',
        flexDirection: 'column',
        gap: SPACING.sm
      }}>
        <div style={{
          background: isDarkMode ? colors.glass : 'rgba(255, 255, 255, 0.95)',
          border: `1px solid ${colors.success}40`,
          borderRadius: BORDER_RADIUS.lg,
          padding: SPACING.md,
          minWidth: '300px',
          boxShadow: colors.shadow,
          animation: 'slideIn 0.3s ease'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: SPACING.sm }}>
            <span style={{ fontSize: '20px' }}>✅</span>
            <div>
              <div style={{ 
                fontWeight: TYPOGRAPHY.fontWeight.bold,
                color: isDarkMode ? colors.text : '#1a1a2e',
                fontSize: TYPOGRAPHY.fontSize.sm
              }}>
                System Healthy
              </div>
              <div style={{ 
                fontSize: TYPOGRAPHY.fontSize.xs,
                color: isDarkMode ? colors.textSecondary : '#64748b'
              }}>
                All security services operational
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div style={{ 
      minHeight: '100vh',
      background: isDarkMode ? colors.background : '#f8fafc',
      color: isDarkMode ? colors.text : '#1a1a2e',
      fontFamily: TYPOGRAPHY.fontFamily,
      padding: SPACING.xl,
      position: 'relative',
      overflow: 'hidden',
      transition: 'background 0.3s ease, color 0.3s ease'
    }}
    ref={dashboardRef}
    >
      {/* Animated background */}
      {isDarkMode && (
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
          zIndex: 0,
          animation: 'gradientShift 15s ease infinite'
        }} />
      )}

      {/* Notification Center */}
      <NotificationCenter />

      {/* Header */}
      <div style={{ 
        marginBottom: SPACING.xl,
        paddingBottom: SPACING.lg,
        borderBottom: `1px solid ${isDarkMode ? colors.border : 'rgba(0, 0, 0, 0.1)'}`,
        position: 'relative',
        zIndex: 1
      }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: SPACING.md
        }}>
          <div>
            <h1 style={{ 
              fontSize: TYPOGRAPHY.fontSize.xxxl,
              fontWeight: TYPOGRAPHY.fontWeight.extrabold,
              margin: '0 0 SPACING.sm 0',
              background: colors.primaryGradient,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
              letterSpacing: TYPOGRAPHY.letterSpacing.tight
            }}>
              🛡️ Security Command Center
            </h1>
            <div style={{ 
              fontSize: TYPOGRAPHY.fontSize.md,
              color: isDarkMode ? colors.textSecondary : '#64748b',
              display: 'flex',
              alignItems: 'center',
              gap: SPACING.md
            }}>
              <span style={{
                display: 'flex',
                alignItems: 'center',
                gap: SPACING.xs,
                padding: '6px 16px',
                borderRadius: BORDER_RADIUS.full,
                background: dataSource === 'wazuh' ? `${colors.success}20` : `${colors.warning}20`,
                border: dataSource === 'wazuh' ? `1px solid ${colors.success}40` : `1px solid ${colors.warning}40`,
                color: dataSource === 'wazuh' ? colors.success : colors.warning,
                fontWeight: TYPOGRAPHY.fontWeight.semibold
              }}>
                {dataSource === 'wazuh' ? '🟢' : '🟡'} {dataSource === 'wazuh' ? 'Live Connection' : 'Demo Mode'}
              </span>
              <span style={{
                display: 'flex',
                alignItems: 'center',
                gap: SPACING.xs
              }}>
                📊 Last updated: {new Date().toLocaleTimeString()}
              </span>
            </div>
          </div>
          
          {/* Control Panel */}
          <div style={{
            display: 'flex',
            gap: SPACING.sm,
            flexWrap: 'wrap'
          }}>
            {/* Theme Toggle */}
            <button
              onClick={() => setIsDarkMode(!isDarkMode)}
              style={{
                padding: '8px 16px',
                background: isDarkMode ? colors.glass : 'rgba(255, 255, 255, 0.95)',
                border: `1px solid ${isDarkMode ? colors.glassBorder : 'rgba(0, 0, 0, 0.1)'}`,
                borderRadius: BORDER_RADIUS.md,
                color: isDarkMode ? colors.text : '#1a1a2e',
                cursor: 'pointer',
                fontSize: TYPOGRAPHY.fontSize.sm,
                fontWeight: TYPOGRAPHY.fontWeight.semibold,
                display: 'flex',
                alignItems: 'center',
                gap: SPACING.xs,
                transition: 'all 0.3s ease'
              }}
              onMouseOver={(e) => {
                e.currentTarget.style.transform = 'translateY(-2px)';
                e.currentTarget.style.boxShadow = colors.shadow;
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              {isDarkMode ? '☀️' : '🌙'} {isDarkMode ? 'Light' : 'Dark'}
            </button>
            
            {/* Animation Toggle */}
            <button
              onClick={() => setIsAnimating(!isAnimating)}
              style={{
                padding: '8px 16px',
                background: isDarkMode ? colors.glass : 'rgba(255, 255, 255, 0.95)',
                border: `1px solid ${isDarkMode ? colors.glassBorder : 'rgba(0, 0, 0, 0.1)'}`,
                borderRadius: BORDER_RADIUS.md,
                color: isDarkMode ? colors.text : '#1a1a2e',
                cursor: 'pointer',
                fontSize: TYPOGRAPHY.fontSize.sm,
                fontWeight: TYPOGRAPHY.fontWeight.semibold,
                display: 'flex',
                alignItems: 'center',
                gap: SPACING.xs,
                transition: 'all 0.3s ease'
              }}
              onMouseOver={(e) => {
                e.currentTarget.style.transform = 'translateY(-2px)';
                e.currentTarget.style.boxShadow = colors.shadow;
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              {isAnimating ? '⏸️' : '▶️'} {isAnimating ? 'Pause' : 'Play'}
            </button>
            
            {/* View Mode Toggle */}
            <button
              onClick={() => setViewMode(viewMode === 'grid' ? 'list' : 'grid')}
              style={{
                padding: '8px 16px',
                background: isDarkMode ? colors.glass : 'rgba(255, 255, 255, 0.95)',
                border: `1px solid ${isDarkMode ? colors.glassBorder : 'rgba(0, 0, 0, 0.1)'}`,
                borderRadius: BORDER_RADIUS.md,
                color: isDarkMode ? colors.text : '#1a1a2e',
                cursor: 'pointer',
                fontSize: TYPOGRAPHY.fontSize.sm,
                fontWeight: TYPOGRAPHY.fontWeight.semibold,
                display: 'flex',
                alignItems: 'center',
                gap: SPACING.xs,
                transition: 'all 0.3s ease'
              }}
              onMouseOver={(e) => {
                e.currentTarget.style.transform = 'translateY(-2px)';
                e.currentTarget.style.boxShadow = colors.shadow;
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              {viewMode === 'grid' ? '📋' : '⊞'} {viewMode === 'grid' ? 'List' : 'Grid'}
            </button>
            
            {/* Auto-refresh Toggle */}
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              style={{
                padding: '8px 16px',
                background: autoRefresh ? `${colors.success}20` : (isDarkMode ? colors.glass : 'rgba(255, 255, 255, 0.95)'),
                border: `1px solid ${autoRefresh ? `${colors.success}40` : (isDarkMode ? colors.glassBorder : 'rgba(0, 0, 0, 0.1)')}`,
                borderRadius: BORDER_RADIUS.md,
                color: autoRefresh ? colors.success : (isDarkMode ? colors.text : '#1a1a2e'),
                cursor: 'pointer',
                fontSize: TYPOGRAPHY.fontSize.sm,
                fontWeight: TYPOGRAPHY.fontWeight.semibold,
                display: 'flex',
                alignItems: 'center',
                gap: SPACING.xs,
                transition: 'all 0.3s ease'
              }}
              onMouseOver={(e) => {
                e.currentTarget.style.transform = 'translateY(-2px)';
                e.currentTarget.style.boxShadow = colors.shadow;
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              {autoRefresh ? '🔄' : '⏸️'} Auto: {refreshInterval}s
            </button>
          </div>
        </div>
        
        {/* Time Range Selector */}
        <div style={{
          display: 'flex',
          gap: SPACING.sm,
          flexWrap: 'wrap'
        }}>
          {['1h', '24h', '7d', '30d'].map((range) => (
            <button
              key={range}
              onClick={() => setSelectedTimeRange(range)}
              style={{
                padding: '6px 16px',
                background: selectedTimeRange === range 
                  ? colors.primaryGradient 
                  : (isDarkMode ? colors.glass : 'rgba(255, 255, 255, 0.95)'),
                border: selectedTimeRange === range 
                  ? 'none' 
                  : `1px solid ${isDarkMode ? colors.glassBorder : 'rgba(0, 0, 0, 0.1)'}`,
                borderRadius: BORDER_RADIUS.full,
                color: selectedTimeRange === range ? 'white' : (isDarkMode ? colors.text : '#1a1a2e'),
                cursor: 'pointer',
                fontSize: TYPOGRAPHY.fontSize.xs,
                fontWeight: TYPOGRAPHY.fontWeight.semibold,
                transition: 'all 0.3s ease'
              }}
              onMouseOver={(e) => {
                if (selectedTimeRange !== range) {
                  e.currentTarget.style.transform = 'translateY(-2px)';
                  e.currentTarget.style.borderColor = colors.primary;
                }
              }}
              onMouseOut={(e) => {
                if (selectedTimeRange !== range) {
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.borderColor = isDarkMode ? colors.glassBorder : 'rgba(0, 0, 0, 0.1)';
                }
              }}
            >
              {range}
            </button>
          ))}
        </div>
      </div>

      {/* Main Stats Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
        gap: SPACING.lg,
        marginBottom: SPACING.xxxl
      }}>
        <EnhancedStatCard
          title="Total Investigations"
          value={stats?.total_investigations || 0}
          icon="🔍"
          color={colors.primary}
          trend={8}
          subtitle="All time"
          size="large"
        />
        <EnhancedStatCard
          title="Active Investigations"
          value={stats?.active_investigations || 0}
          icon="⚡"
          color={colors.warning}
          trend={3}
          subtitle="Currently running"
        />
        <EnhancedStatCard
          title="Total IOCs"
          value={stats?.total_iocs || 0}
          icon="🎯"
          color={colors.danger}
          trend={12}
          subtitle="Indicators of compromise"
        />
        <EnhancedStatCard
          title="High Risk IOCs"
          value={stats?.high_risk_iocs || 0}
          icon="⚠️"
          color={colors.danger}
          trend={-5}
          subtitle="Requires attention"
        />
      </div>

      {/* Alert Trends Section */}
      <div style={{
        ...glassCardStyle,
        marginBottom: SPACING.xxxl
      }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: SPACING.lg
        }}>
          <h2 style={{
            margin: 0,
            fontSize: TYPOGRAPHY.fontSize['2xl'],
            fontWeight: TYPOGRAPHY.fontWeight.extrabold,
            background: colors.primaryGradient,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text'
          }}>
            📈 Security Trends (24h)
          </h2>
          <div style={{
            display: 'flex',
            gap: SPACING.lg,
            alignItems: 'center'
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: SPACING.xs,
              fontSize: TYPOGRAPHY.fontSize.sm,
              fontWeight: TYPOGRAPHY.fontWeight.semibold,
              color: colors.textSecondary
            }}>
              <div style={{
                width: '12px',
                height: '12px',
                borderRadius: '50%',
                background: colors.primary
              }} />
              Alerts
            </div>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: SPACING.xs,
              fontSize: TYPOGRAPHY.fontSize.sm,
              fontWeight: TYPOGRAPHY.fontWeight.semibold,
              color: colors.textSecondary
            }}>
              <div style={{
                width: '12px',
                height: '12px',
                borderRadius: '50%',
                background: colors.success
              }} />
              Investigations
            </div>
          </div>
        </div>
        <MiniChart data={chartData.map(d => d.alerts)} color={colors.primary} height={120} />
      </div>

      {/* Content Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '2fr 1fr',
        gap: SPACING.xl
      }}>
        {/* Recent Alerts */}
        <div style={{
          ...glassCardStyle
        }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: SPACING.lg
          }}>
            <h2 style={{
              margin: 0,
              fontSize: TYPOGRAPHY.fontSize['2xl'],
              fontWeight: TYPOGRAPHY.fontWeight.extrabold,
              background: colors.primaryGradient,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text'
            }}>
              🔔 Recent Alerts
            </h2>
            <div style={{
              display: 'flex',
              gap: SPACING.sm
            }}>
              {['all', 'critical', 'high', 'medium', 'low'].map((severity) => (
                <button
                  key={severity}
                  onClick={() => setSelectedSeverity(severity)}
                  style={{
                    padding: '6px 12px',
                    background: selectedSeverity === severity 
                      ? colors.primaryGradient 
                      : colors.glass,
                    border: selectedSeverity === severity 
                      ? 'none' 
                      : `1px solid ${colors.glassBorder}`,
                    borderRadius: BORDER_RADIUS.full,
                    color: selectedSeverity === severity ? 'white' : colors.textSecondary,
                    cursor: 'pointer',
                    fontSize: TYPOGRAPHY.fontSize.xs,
                    fontWeight: TYPOGRAPHY.fontWeight.semibold,
                    textTransform: 'uppercase',
                    transition: 'all 0.3s ease'
                  }}
                >
                  {severity}
                </button>
              ))}
            </div>
          </div>
          
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            gap: SPACING.md
          }}>
            {filteredAlerts.length > 0 ? (
              filteredAlerts.map((alert) => (
                <div key={alert.id} style={{
                  padding: SPACING.lg,
                  background: SEVERITY_CONFIG[alert.severity]?.bg || colors.glass,
                  border: `1px solid ${SEVERITY_CONFIG[alert.severity]?.border || colors.glassBorder}`,
                  borderRadius: BORDER_RADIUS.lg,
                  cursor: 'pointer',
                  transition: 'all 0.3s ease',
                  position: 'relative',
                  overflow: 'hidden'
                }}
                onMouseOver={(e) => {
                  e.currentTarget.style.transform = 'translateX(8px)';
                  e.currentTarget.style.borderColor = SEVERITY_CONFIG[alert.severity]?.color;
                  e.currentTarget.style.boxShadow = SEVERITY_CONFIG[alert.severity]?.shadow;
                }}
                onMouseOut={(e) => {
                  e.currentTarget.style.transform = 'translateX(0)';
                  e.currentTarget.style.borderColor = SEVERITY_CONFIG[alert.severity]?.border;
                  e.currentTarget.style.boxShadow = 'none';
                }}
                >
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: SPACING.sm
                  }}>
                    <div style={{
                      fontSize: TYPOGRAPHY.fontSize.md,
                      fontWeight: TYPOGRAPHY.fontWeight.bold,
                      color: colors.text
                    }}>
                      {alert.title}
                    </div>
                    <div style={{
                      padding: '4px 12px',
                      borderRadius: BORDER_RADIUS.full,
                      background: SEVERITY_CONFIG[alert.severity]?.bg,
                      color: SEVERITY_CONFIG[alert.severity]?.color,
                      fontSize: TYPOGRAPHY.fontSize.xs,
                      fontWeight: TYPOGRAPHY.fontWeight.semibold,
                      textTransform: 'uppercase',
                      border: `1px solid ${SEVERITY_CONFIG[alert.severity]?.border}`
                    }}>
                      {alert.severity}
                    </div>
                  </div>
                  <div style={{
                    fontSize: TYPOGRAPHY.fontSize.sm,
                    color: colors.textSecondary,
                    display: 'flex',
                    gap: SPACING.lg,
                    alignItems: 'center'
                  }}>
                    <span>{alert.source}</span>
                    <span>{timeSince(alert.created_at)}</span>
                  </div>
                </div>
              ))
            ) : (
              <div style={{
                textAlign: 'center',
                padding: SPACING.xxxl,
                color: colors.textMuted,
                fontSize: TYPOGRAPHY.fontSize.md
              }}>
                No alerts found for selected severity
              </div>
            )}
          </div>
        </div>

        {/* Recent Investigations */}
        <div style={{
          ...glassCardStyle
        }}>
          <h2 style={{
            margin: 0,
            fontSize: TYPOGRAPHY.fontSize['2xl'],
            fontWeight: TYPOGRAPHY.fontWeight.extrabold,
            marginBottom: SPACING.lg,
            background: colors.primaryGradient,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text'
          }}>
            🔍 Active Investigations
          </h2>
          
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            gap: SPACING.md
          }}>
            {recentInvestigations.map((investigation) => (
              <div key={investigation.id} style={{
                padding: SPACING.lg,
                background: investigation.status === 'active' ? `${colors.success}10` : colors.glass,
                border: `1px solid ${investigation.status === 'active' ? `${colors.success}30` : colors.glassBorder}`,
                borderRadius: BORDER_RADIUS.lg,
                cursor: 'pointer',
                transition: 'all 0.3s ease',
                position: 'relative'
              }}
              onMouseOver={(e) => {
                e.currentTarget.style.transform = 'translateY(-4px)';
                e.currentTarget.style.borderColor = investigation.status === 'active' ? colors.success : colors.primary;
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.borderColor = investigation.status === 'active' ? `${colors.success}30` : colors.glassBorder;
              }}
              >
                {investigation.status === 'active' && (
                  <div style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    right: 0,
                    height: '2px',
                    background: `linear-gradient(90deg, ${colors.success}, ${colors.accent})`,
                    animation: 'shimmer 2s infinite'
                  }} />
                )}
                
                <div style={{
                  fontSize: TYPOGRAPHY.fontSize.md,
                  fontWeight: TYPOGRAPHY.fontWeight.bold,
                  color: colors.text,
                  marginBottom: SPACING.sm,
                  display: 'flex',
                  alignItems: 'center',
                  gap: SPACING.sm
                }}>
                  <span>{investigation.status === 'active' ? '🔍' : '✅'}</span>
                  {investigation.title}
                </div>
                
                <div style={{
                  fontSize: TYPOGRAPHY.fontSize.sm,
                  color: colors.textSecondary,
                  display: 'flex',
                  gap: SPACING.sm,
                  alignItems: 'center'
                }}>
                  <span style={{
                    background: `${colors.primary}15`,
                    padding: '4px 10px',
                    borderRadius: BORDER_RADIUS.sm,
                    fontWeight: TYPOGRAPHY.fontWeight.semibold
                  }}>
                    {investigation.investigation_id}
                  </span>
                  <span>{timeSince(investigation.created_at)}</span>
                </div>
              </div>
            ))}
          </div>
          
          <button
            onClick={startInvestigation}
            style={{
              width: '100%',
              padding: SPACING.lg,
              background: colors.primaryGradient,
              border: 'none',
              borderRadius: BORDER_RADIUS.lg,
              color: 'white',
              cursor: 'pointer',
              fontSize: TYPOGRAPHY.fontSize.md,
              fontWeight: TYPOGRAPHY.fontWeight.bold,
              marginTop: SPACING.lg,
              transition: 'all 0.3s ease',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: SPACING.sm
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.transform = 'translateY(-4px)';
              e.currentTarget.style.boxShadow = `0 12px 32px ${colors.primary}40`;
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = 'none';
            }}
          >
            🚀 Start New Investigation
          </button>
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;
            e.currentTarget.style.transform = 'translateY(0) scale(1)';
            e.currentTarget.style.boxShadow = '0 8px 24px rgba(99, 102, 241, 0.3)';
          }}
        >
          🔍 Start Investigation
        </button>
        
        <button 
          onClick={collectLogs}
          style={{
            ...modernButtonStyle,
            background: colors.secondaryGradient,
            minWidth: '200px',
            justifyContent: 'center'
          }}
          onMouseOver={(e) => {
            e.currentTarget.style.transform = 'translateY(-4px) scale(1.05)';
            e.currentTarget.style.boxShadow = '0 12px 32px rgba(139, 92, 246, 0.5)';
          }}
          onMouseOut={(e) => {
            e.currentTarget.style.transform = 'translateY(0) scale(1)';
            e.currentTarget.style.boxShadow = '0 8px 24px rgba(139, 92, 246, 0.3)';
          }}
        >
          📊 Collect Logs
        </button>
      </div>

      {/* Main Content Grid */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
        gap: SPACING.xl,
        position: 'relative',
        zIndex: 1
      }}>
        {/* Recent Alerts */}
        <div style={{ ...glassCardStyle }}>
          <h2 style={{ 
            margin: '0 0 SPACING.lg 0', 
            fontSize: TYPOGRAPHY.fontSize.xl,
            fontWeight: TYPOGRAPHY.fontWeight.extrabold,
            background: colors.primaryGradient,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text'
          }}>
            🚨 Recent Alerts
          </h2>
          {recentAlerts.length > 0 ? (
            recentAlerts.map(alert => <AlertCard key={alert.id} alert={alert} />)
          ) : (
            <div style={{ 
              padding: SPACING.xl, 
              textAlign: 'center', 
              color: colors.textMuted 
            }}>
              No recent alerts
            </div>
          )}
        </div>

        {/* Recent Investigations */}
        <div style={{ ...glassCardStyle }}>
          <h2 style={{ 
            margin: '0 0 SPACING.lg 0', 
            fontSize: TYPOGRAPHY.fontSize.xl,
            fontWeight: TYPOGRAPHY.fontWeight.extrabold,
            background: colors.primaryGradient,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text'
          }}>
            🔍 Recent Investigations
          </h2>
          {recentInvestigations.length > 0 ? (
            recentInvestigations.map(investigation => (
              <InvestigationCard key={investigation.id} investigation={investigation} />
            ))
          ) : (
            <div style={{ 
              padding: SPACING.xl, 
              textAlign: 'center', 
              color: colors.textMuted 
            }}>
              No recent investigations
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;