import React, { useState, useEffect } from 'react';
import { 
  MODERN_COLORS, 
  SPACING, 
  BORDER_RADIUS, 
  TYPOGRAPHY,
  ANIMATION_CONFIG
} from '../theme/modernTheme';

const InvestigationDashboard = () => {
  const [activeTab, setActiveTab] = useState('live');
  const [investigations, setInvestigations] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');
  const [showNewInvestigationForm, setShowNewInvestigationForm] = useState(false);
  const [newInvestigation, setNewInvestigation] = useState({
    title: '',
    description: '',
    investigation_type: 'general',
    log_sources: ['windows_event'],
    time_range_hours: 24,
    priority_areas: '',
    auto_start: true
  });
  const [formLoading, setFormLoading] = useState(false);
  const [formError, setFormError] = useState(null);
  const [formSuccess, setFormSuccess] = useState(null);

  const tabs = [
    { id: 'live', label: 'Live Investigation', icon: '🔍' },
    { id: 'history', label: 'Investigation History', icon: '📜' },
    { id: 'operations', label: 'Investigation Operations', icon: '⚙️' }
  ];

  const statusFilters = [
    { value: 'all', label: 'All Status' },
    { value: 'planning', label: 'Planning' },
    { value: 'evidence_collection', label: 'Evidence Collection' },
    { value: 'ioc_extraction', label: 'IOC Extraction' },
    { value: 'threat_intel_analysis', label: 'Threat Intel' },
    { value: 'correlation_analysis', label: 'Correlation' },
    { value: 'risk_assessment', label: 'Risk Assessment' },
    { value: 'reporting', label: 'Reporting' },
    { value: 'completed', label: 'Completed' },
    { value: 'failed', label: 'Failed' }
  ];

  useEffect(() => {
    if (activeTab === 'history') {
      fetchInvestigations();
    }
  }, [activeTab, filter]);

  // Auto-refresh investigations every 10 seconds when on history tab
  useEffect(() => {
    let interval;
    if (activeTab === 'history') {
      interval = setInterval(() => {
        fetchInvestigations();
      }, 10000); // Refresh every 10 seconds
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [activeTab]);

  const fetchInvestigations = async () => {
    try {
      setLoading(true);
      const params = filter !== 'all' ? `?status=${filter}` : '';
      const response = await fetch(`/api/log-analysis/investigation${params}`);
      const data = await response.json();
      
      if (data.status === 'success') {
        setInvestigations(data.investigations);
        setError(null);
      } else {
        setError('Failed to fetch investigations');
      }
    } catch (err) {
      setError('Error connecting to server');
      console.error('Investigation fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleStartInvestigation = async (e) => {
    e.preventDefault();
    setFormLoading(true);
    setFormError(null);
    setFormSuccess(null);

    try {
      const requestBody = {
        title: newInvestigation.title,
        description: newInvestigation.description,
        investigation_type: newInvestigation.investigation_type,
        log_sources: newInvestigation.log_sources,
        time_range_hours: parseInt(newInvestigation.time_range_hours),
        priority_areas: newInvestigation.priority_areas ? newInvestigation.priority_areas.split(',').map(s => s.trim()) : null,
        auto_start: newInvestigation.auto_start
      };

      const response = await fetch('/api/log-analysis/investigation/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      const data = await response.json();

      if (data.status === 'success') {
        setFormSuccess(`Investigation ${data.investigation_id} created successfully!`);
        setNewInvestigation({
          title: '',
          description: '',
          investigation_type: 'general',
          log_sources: ['windows_event'],
          time_range_hours: 24,
          priority_areas: '',
          auto_start: true
        });
        setShowNewInvestigationForm(false);
        
        // Refresh investigations list
        setTimeout(() => {
          fetchInvestigations();
          setFormSuccess(null);
        }, 2000);
      } else {
        setFormError('Failed to create investigation');
      }
    } catch (err) {
      setFormError('Error connecting to server');
      console.error('Investigation creation error:', err);
    } finally {
      setFormLoading(false);
    }
  };

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setNewInvestigation(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleLogSourceToggle = (source) => {
    setNewInvestigation(prev => ({
      ...prev,
      log_sources: prev.log_sources.includes(source)
        ? prev.log_sources.filter(s => s !== source)
        : [...prev.log_sources, source]
    }));
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return { bg: 'rgba(16, 185, 129, 0.1)', text: '#10b981', border: 'rgba(16, 185, 129, 0.2)' };
      case 'failed': return { bg: 'rgba(239, 68, 68, 0.1)', text: '#ef4444', border: 'rgba(239, 68, 68, 0.2)' };
      case 'reporting': return { bg: 'rgba(59, 130, 246, 0.1)', text: '#3b82f6', border: 'rgba(59, 130, 246, 0.2)' };
      case 'risk_assessment': return { bg: 'rgba(168, 85, 247, 0.1)', text: '#a855f7', border: 'rgba(168, 85, 247, 0.2)' };
      case 'correlation_analysis': return { bg: 'rgba(99, 102, 241, 0.1)', text: '#6366f1', border: 'rgba(99, 102, 241, 0.2)' };
      case 'threat_intel_analysis': return { bg: 'rgba(6, 182, 212, 0.1)', text: '#06b6d4', border: 'rgba(6, 182, 212, 0.2)' };
      case 'ioc_extraction': return { bg: 'rgba(20, 184, 166, 0.1)', text: '#14b8a6', border: 'rgba(20, 184, 166, 0.2)' };
      case 'evidence_collection': return { bg: 'rgba(245, 158, 11, 0.1)', text: '#f59e0b', border: 'rgba(245, 158, 11, 0.2)' };
      case 'planning': return { bg: 'rgba(107, 114, 128, 0.1)', text: '#6b7280', border: 'rgba(107, 114, 128, 0.2)' };
      default: return { bg: 'rgba(107, 114, 128, 0.1)', text: '#6b7280', border: 'rgba(107, 114, 128, 0.2)' };
    }
  };

  const getRiskColor = (riskLevel) => {
    switch (riskLevel) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#eab308';
      case 'low': return '#22c55e';
      default: return '#6b7280';
    }
  };

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
            🔍 Investigation Operations
          </h1>
          <p style={{
            color: MODERN_COLORS.textSecondary,
            fontSize: TYPOGRAPHY.fontSize.md
          }}>
            AI-powered incident investigation and analysis
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
        overflow: 'auto'
      }}>
        {activeTab === 'live' && (
          <div style={{
            padding: `${SPACING.xl}px ${SPACING.xxl}px`,
            display: 'flex',
            flexDirection: 'column',
            gap: SPACING.xl
          }}>
            {/* Direct Investigation Box */}
            <div style={{
              background: 'linear-gradient(135deg, rgba(15,23,42,0.9), rgba(10,14,26,0.95))',
              borderRadius: BORDER_RADIUS.xl,
              padding: SPACING.xl,
              border: `1px solid rgba(99,102,241,0.2)`,
              boxShadow: '0 8px 32px rgba(0,0,0,0.4)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: SPACING.md }}>
                <div>
                  <h2 style={{ margin: 0, fontSize: '1.25rem', color: '#f8fafc', fontWeight: 800 }}>
                    ⚡ Autonomous AI Incident Investigation & Remediation
                  </h2>
                  <p style={{ margin: '4px 0 0', color: '#94a3b8', fontSize: '0.8rem' }}>
                    Trigger comprehensive agentic root-cause analysis across Wazuh telemetry, Windows event logs, and threat intelligence.
                  </p>
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 8px #10b981' }} />
                  <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#10b981' }}>ORCHESTRATOR ONLINE</span>
                </div>
              </div>

              {/* Quick Preset Buttons from Real Telemetry */}
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: SPACING.lg }}>
                <span style={{ fontSize: '0.72rem', color: '#818cf8', fontWeight: 600, alignSelf: 'center' }}>QUICK PRESETS:</span>
                {[
                  "Investigate PAM login session for user root on wazuh-server",
                  "Analyze Windows Software Protection execution on LAPTOP-RV59QQN5",
                  "Scan host 192.168.56.1 for unauthorized services and persistence",
                  "Correlate failed authentication events with brute force threat actor"
                ].map((preset, idx) => (
                  <button
                    key={idx}
                    onClick={() => {
                      setNewInvestigation(p => ({ ...p, title: preset, description: `Live autonomous investigation on ${preset}` }));
                      setShowNewInvestigationForm(true);
                    }}
                    style={{
                      background: 'rgba(99,102,241,0.1)',
                      border: '1px solid rgba(99,102,241,0.25)',
                      color: '#c4b5fd',
                      padding: '4px 12px',
                      borderRadius: 16,
                      fontSize: '0.72rem',
                      cursor: 'pointer',
                      transition: 'all 150ms ease'
                    }}
                    onMouseOver={e => e.currentTarget.style.borderColor = 'rgba(99,102,241,0.6)'}
                    onMouseOut={e => e.currentTarget.style.borderColor = 'rgba(99,102,241,0.25)'}
                  >
                    🔍 {preset}
                  </button>
                ))}
              </div>

              <div style={{ display: 'flex', gap: 12 }}>
                <button
                  onClick={() => setShowNewInvestigationForm(true)}
                  style={{
                    background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                    border: 'none',
                    borderRadius: BORDER_RADIUS.md,
                    color: '#ffffff',
                    padding: '12px 24px',
                    fontSize: '0.85rem',
                    fontWeight: 700,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    boxShadow: '0 4px 16px rgba(99,102,241,0.3)'
                  }}
                >
                  🚀 Launch Autonomous Investigation
                </button>
                <button
                  onClick={() => setActiveTab('history')}
                  style={{
                    background: 'rgba(30,41,59,0.7)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    borderRadius: BORDER_RADIUS.md,
                    color: '#e2e8f0',
                    padding: '12px 20px',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  📜 View Active Pipeline & Reports
                </button>
              </div>
            </div>

            {/* Real Pipeline Telemetry Status Card */}
            <div style={{
              background: 'rgba(15,23,42,0.6)',
              borderRadius: BORDER_RADIUS.xl,
              padding: SPACING.xl,
              border: `1px solid rgba(255,255,255,0.06)`
            }}>
              <h3 style={{ margin: '0 0 12px', fontSize: '1rem', color: '#f8fafc' }}>
                Active Telemetry & Evidence Sources
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
                {[
                  { name: 'Wazuh SIEM Manager (OVA)', status: 'Connected', ip: '192.168.56.101', icon: '🛡️', color: '#10b981' },
                  { name: 'Agent 002 (Windows11)', status: 'Active / Streaming', ip: '192.168.56.1', icon: '💻', color: '#06b6d4' },
                  { name: 'Windows Security EventChannel', status: 'Live Ingested', ip: 'Local Host', icon: '📑', color: '#8b5cf6' },
                  { name: 'MITRE ATT&CK Correlation Engine', status: 'Synchronized', ip: 'Internal AI', icon: '🎯', color: '#f59e0b' }
                ].map((src, i) => (
                  <div key={i} style={{
                    background: 'rgba(10,14,26,0.7)',
                    padding: 14,
                    borderRadius: BORDER_RADIUS.lg,
                    border: '1px solid rgba(255,255,255,0.06)'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '1.2rem' }}>{src.icon}</span>
                      <span style={{ fontSize: '0.68rem', color: src.color, fontWeight: 700 }}>● {src.status}</span>
                    </div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#f8fafc', marginTop: 8 }}>{src.name}</div>
                    <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: 2 }}>Target: {src.ip}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
        {activeTab === 'history' && (
          <div style={{
            padding: `${SPACING.xl}px ${SPACING.xxl}px`,
            overflow: 'auto'
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: SPACING.lg
            }}>
              <div>
                <h2 style={{ marginBottom: SPACING.xs }}>Investigation History</h2>
                <p style={{ color: MODERN_COLORS.textSecondary, fontSize: TYPOGRAPHY.fontSize.sm }}>
                  {investigations.length} investigations • Auto-refreshing every 10s
                </p>
              </div>
              <div style={{ display: 'flex', gap: SPACING.sm, alignItems: 'center' }}>
                <select
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  style={{
                    padding: `${SPACING.sm}px ${SPACING.md}px`,
                    borderRadius: BORDER_RADIUS.md,
                    border: `1px solid ${MODERN_COLORS.glassBorder}`,
                    background: MODERN_COLORS.surface,
                    color: MODERN_COLORS.text,
                    fontSize: TYPOGRAPHY.fontSize.sm
                  }}
                >
                  {statusFilters.map(f => (
                    <option key={f.value} value={f.value}>{f.label}</option>
                  ))}
                </select>
                <button
                  onClick={() => setActiveTab('operations')}
                  style={{
                    padding: `${SPACING.sm}px ${SPACING.md}px`,
                    borderRadius: BORDER_RADIUS.md,
                    border: 'none',
                    background: MODERN_COLORS.primaryGradient,
                    color: '#ffffff',
                    cursor: 'pointer',
                    fontSize: TYPOGRAPHY.fontSize.sm,
                    fontWeight: TYPOGRAPHY.fontWeight.semibold
                  }}
                >
                  ➕ New Investigation
                </button>
                <button
                  onClick={fetchInvestigations}
                  style={{
                    padding: `${SPACING.sm}px ${SPACING.md}px`,
                    borderRadius: BORDER_RADIUS.md,
                    border: `1px solid ${MODERN_COLORS.glassBorder}`,
                    background: MODERN_COLORS.surface,
                    color: MODERN_COLORS.text,
                    cursor: 'pointer',
                    fontSize: TYPOGRAPHY.fontSize.sm,
                    fontWeight: TYPOGRAPHY.fontWeight.semibold
                  }}
                >
                  🔄 Refresh
                </button>
              </div>
            </div>

            {error && (
              <div style={{
                padding: SPACING.lg,
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.2)',
                borderRadius: BORDER_RADIUS.lg,
                color: '#ef4444',
                marginBottom: SPACING.lg
              }}>
                {error}
              </div>
            )}

            {loading ? (
              <div style={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                padding: SPACING['2xl']
              }}>
                <div style={{
                  width: '40px',
                  height: '40px',
                  border: '3px solid rgba(99, 102, 241, 0.2)',
                  borderTopColor: '#6366f1',
                  borderRadius: '50%',
                  animation: 'spin 1s linear infinite'
                }} />
              </div>
            ) : investigations.length === 0 ? (
              <div style={{
                padding: SPACING['2xl'],
                background: MODERN_COLORS.glass,
                borderRadius: BORDER_RADIUS.xl,
                border: `1px solid ${MODERN_COLORS.glassBorder}`,
                textAlign: 'center',
                color: MODERN_COLORS.textSecondary
              }}>
                No investigations found
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: SPACING.md }}>
                {investigations.map((inv) => {
                  const statusColors = getStatusColor(inv.status);
                  return (
                    <div
                      key={inv.id}
                      style={{
                        padding: SPACING.lg,
                        background: MODERN_COLORS.glass,
                        borderRadius: BORDER_RADIUS.lg,
                        border: `1px solid ${MODERN_COLORS.glassBorder}`,
                        transition: `all ${ANIMATION_CONFIG.duration.fast} ${ANIMATION_CONFIG.easing.smooth}`,
                        cursor: 'pointer'
                      }}
                      onMouseOver={(e) => {
                        e.currentTarget.style.background = MODERN_COLORS.glassLight;
                        e.currentTarget.style.borderColor = 'rgba(99, 102, 241, 0.3)';
                      }}
                      onMouseOut={(e) => {
                        e.currentTarget.style.background = MODERN_COLORS.glass;
                        e.currentTarget.style.borderColor = MODERN_COLORS.glassBorder;
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: SPACING.sm, marginBottom: SPACING.sm }}>
                            <h3 style={{ margin: 0, fontSize: TYPOGRAPHY.fontSize.md, fontWeight: TYPOGRAPHY.fontWeight.semibold }}>
                              {inv.title}
                            </h3>
                            <span style={{
                              padding: `${SPACING.xs}px ${SPACING.sm}px`,
                              borderRadius: BORDER_RADIUS.md,
                              fontSize: TYPOGRAPHY.fontSize.xs,
                              fontWeight: TYPOGRAPHY.fontWeight.semibold,
                              background: statusColors.bg,
                              color: statusColors.text,
                              border: `1px solid ${statusColors.border}`
                            }}>
                              {inv.status.replace('_', ' ')}
                            </span>
                          </div>
                          
                          <p style={{ color: MODERN_COLORS.textSecondary, fontSize: TYPOGRAPHY.fontSize.sm, marginBottom: SPACING.md }}>
                            {inv.description || 'No description provided'}
                          </p>
                          
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: SPACING.md, fontSize: TYPOGRAPHY.fontSize.sm }}>
                            <div>
                              <p style={{ color: MODERN_COLORS.textSecondary, fontSize: TYPOGRAPHY.fontSize.xs, marginBottom: '2px' }}>Investigation ID</p>
                              <p style={{ fontWeight: TYPOGRAPHY.fontWeight.medium, fontSize: TYPOGRAPHY.fontSize.sm }}>{inv.investigation_id}</p>
                            </div>
                            <div>
                              <p style={{ color: MODERN_COLORS.textSecondary, fontSize: TYPOGRAPHY.fontSize.xs, marginBottom: '2px' }}>Type</p>
                              <p style={{ fontWeight: TYPOGRAPHY.fontWeight.medium, fontSize: TYPOGRAPHY.fontSize.sm, textTransform: 'capitalize' }}>{inv.investigation_type}</p>
                            </div>
                            <div>
                              <p style={{ color: MODERN_COLORS.textSecondary, fontSize: TYPOGRAPHY.fontSize.xs, marginBottom: '2px' }}>Risk Score</p>
                              <p style={{ fontWeight: TYPOGRAPHY.fontWeight.medium, color: getRiskColor(inv.risk_level), fontSize: TYPOGRAPHY.fontSize.sm }}>
                                {inv.risk_score}/100 ({inv.risk_level})
                              </p>
                            </div>
                            <div>
                              <p style={{ color: MODERN_COLORS.textSecondary, fontSize: TYPOGRAPHY.fontSize.xs, marginBottom: '2px' }}>Created</p>
                              <p style={{ fontWeight: TYPOGRAPHY.fontWeight.medium, fontSize: TYPOGRAPHY.fontSize.sm }}>
                                {new Date(inv.created_at).toLocaleString()}
                              </p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
        {activeTab === 'operations' && (
          <div style={{
            padding: `${SPACING.xl}px ${SPACING.xxl}px`,
            overflow: 'auto'
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: SPACING.lg
            }}>
              <div>
                <h2 style={{ marginBottom: SPACING.xs }}>Investigation Operations</h2>
                <p style={{ color: MODERN_COLORS.textSecondary, fontSize: TYPOGRAPHY.fontSize.sm }}>
                  Comprehensive investigation management with AI-powered analysis
                </p>
              </div>
              <button
                onClick={() => setShowNewInvestigationForm(true)}
                style={{
                  padding: `${SPACING.md}px ${SPACING.lg}px`,
                  borderRadius: BORDER_RADIUS.lg,
                  border: 'none',
                  background: MODERN_COLORS.primaryGradient,
                  color: '#ffffff',
                  cursor: 'pointer',
                  fontSize: TYPOGRAPHY.fontSize.sm,
                  fontWeight: TYPOGRAPHY.fontWeight.semibold,
                  display: 'flex',
                  alignItems: 'center',
                  gap: SPACING.sm
                }}
              >
                ➕ Start New Investigation
              </button>
            </div>

            {showNewInvestigationForm && (
              <div style={{
                position: 'fixed',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                background: 'rgba(0, 0, 0, 0.7)',
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                zIndex: 1000
              }}>
                <div style={{
                  background: MODERN_COLORS.surface,
                  borderRadius: BORDER_RADIUS.xl,
                  padding: SPACING.xl,
                  maxWidth: '600px',
                  width: '90%',
                  maxHeight: '90vh',
                  overflowY: 'auto',
                  border: `1px solid ${MODERN_COLORS.glassBorder}`
                }}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: SPACING.lg
                  }}>
                    <h3 style={{ margin: 0 }}>Start New Investigation</h3>
                    <button
                      onClick={() => setShowNewInvestigationForm(false)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: MODERN_COLORS.textSecondary,
                        fontSize: '24px',
                        cursor: 'pointer'
                      }}
                    >
                      ×
                    </button>
                  </div>

                  {formSuccess && (
                    <div style={{
                      padding: SPACING.md,
                      background: 'rgba(16, 185, 129, 0.1)',
                      border: '1px solid rgba(16, 185, 129, 0.2)',
                      borderRadius: BORDER_RADIUS.lg,
                      color: '#10b981',
                      marginBottom: SPACING.lg
                    }}>
                      {formSuccess}
                    </div>
                  )}

                  {formError && (
                    <div style={{
                      padding: SPACING.md,
                      background: 'rgba(239, 68, 68, 0.1)',
                      border: '1px solid rgba(239, 68, 68, 0.2)',
                      borderRadius: BORDER_RADIUS.lg,
                      color: '#ef4444',
                      marginBottom: SPACING.lg
                    }}>
                      {formError}
                    </div>
                  )}

                  <form onSubmit={handleStartInvestigation}>
                    <div style={{ marginBottom: SPACING.md }}>
                      <label style={{ display: 'block', marginBottom: SPACING.sm, fontSize: TYPOGRAPHY.fontSize.sm, fontWeight: TYPOGRAPHY.fontWeight.medium }}>
                        Investigation Title *
                      </label>
                      <input
                        type="text"
                        name="title"
                        value={newInvestigation.title}
                        onChange={handleInputChange}
                        required
                        placeholder="e.g., Suspicious Login Activity"
                        style={{
                          width: '100%',
                          padding: `${SPACING.sm}px ${SPACING.md}px`,
                          borderRadius: BORDER_RADIUS.md,
                          border: `1px solid ${MODERN_COLORS.glassBorder}`,
                          background: MODERN_COLORS.background,
                          color: MODERN_COLORS.text,
                          fontSize: TYPOGRAPHY.fontSize.sm
                        }}
                      />
                    </div>

                    <div style={{ marginBottom: SPACING.md }}>
                      <label style={{ display: 'block', marginBottom: SPACING.sm, fontSize: TYPOGRAPHY.fontSize.sm, fontWeight: TYPOGRAPHY.fontWeight.medium }}>
                        Description
                      </label>
                      <textarea
                        name="description"
                        value={newInvestigation.description}
                        onChange={handleInputChange}
                        placeholder="Describe what you want to investigate..."
                        rows={3}
                        style={{
                          width: '100%',
                          padding: `${SPACING.sm}px ${SPACING.md}px`,
                          borderRadius: BORDER_RADIUS.md,
                          border: `1px solid ${MODERN_COLORS.glassBorder}`,
                          background: MODERN_COLORS.background,
                          color: MODERN_COLORS.text,
                          fontSize: TYPOGRAPHY.fontSize.sm,
                          resize: 'vertical'
                        }}
                      />
                    </div>

                    <div style={{ marginBottom: SPACING.md }}>
                      <label style={{ display: 'block', marginBottom: SPACING.sm, fontSize: TYPOGRAPHY.fontSize.sm, fontWeight: TYPOGRAPHY.fontWeight.medium }}>
                        Investigation Type
                      </label>
                      <select
                        name="investigation_type"
                        value={newInvestigation.investigation_type}
                        onChange={handleInputChange}
                        style={{
                          width: '100%',
                          padding: `${SPACING.sm}px ${SPACING.md}px`,
                          borderRadius: BORDER_RADIUS.md,
                          border: `1px solid ${MODERN_COLORS.glassBorder}`,
                          background: MODERN_COLORS.background,
                          color: MODERN_COLORS.text,
                          fontSize: TYPOGRAPHY.fontSize.sm
                        }}
                      >
                        <option value="general">General Investigation</option>
                        <option value="threat_hunting">Threat Hunting</option>
                        <option value="incident_response">Incident Response</option>
                        <option value="compliance">Compliance Check</option>
                        <option value="forensics">Digital Forensics</option>
                      </select>
                    </div>

                    <div style={{ marginBottom: SPACING.md }}>
                      <label style={{ display: 'block', marginBottom: SPACING.sm, fontSize: TYPOGRAPHY.fontSize.sm, fontWeight: TYPOGRAPHY.fontWeight.medium }}>
                        Log Sources
                      </label>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: SPACING.sm }}>
                        {['windows_event', 'sysmon', 'defender'].map(source => (
                          <label key={source} style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: SPACING.xs,
                            padding: `${SPACING.xs}px ${SPACING.sm}px`,
                            background: newInvestigation.log_sources.includes(source)
                              ? MODERN_COLORS.primaryGradient
                              : MODERN_COLORS.glass,
                            borderRadius: BORDER_RADIUS.md,
                            fontSize: TYPOGRAPHY.fontSize.sm,
                            cursor: 'pointer',
                            border: `1px solid ${MODERN_COLORS.glassBorder}`
                          }}>
                            <input
                              type="checkbox"
                              checked={newInvestigation.log_sources.includes(source)}
                              onChange={() => handleLogSourceToggle(source)}
                              style={{ display: 'none' }}
                            />
                            {source.replace('_', ' ').toUpperCase()}
                          </label>
                        ))}
                      </div>
                    </div>

                    <div style={{ marginBottom: SPACING.md }}>
                      <label style={{ display: 'block', marginBottom: SPACING.sm, fontSize: TYPOGRAPHY.fontSize.sm, fontWeight: TYPOGRAPHY.fontWeight.medium }}>
                        Time Range (Hours)
                      </label>
                      <input
                        type="number"
                        name="time_range_hours"
                        value={newInvestigation.time_range_hours}
                        onChange={handleInputChange}
                        min="1"
                        max="168"
                        style={{
                          width: '100%',
                          padding: `${SPACING.sm}px ${SPACING.md}px`,
                          borderRadius: BORDER_RADIUS.md,
                          border: `1px solid ${MODERN_COLORS.glassBorder}`,
                          background: MODERN_COLORS.background,
                          color: MODERN_COLORS.text,
                          fontSize: TYPOGRAPHY.fontSize.sm
                        }}
                      />
                    </div>

                    <div style={{ marginBottom: SPACING.md }}>
                      <label style={{ display: 'block', marginBottom: SPACING.sm, fontSize: TYPOGRAPHY.fontSize.sm, fontWeight: TYPOGRAPHY.fontWeight.medium }}>
                        Priority Areas (comma-separated)
                      </label>
                      <input
                        type="text"
                        name="priority_areas"
                        value={newInvestigation.priority_areas}
                        onChange={handleInputChange}
                        placeholder="e.g., authentication, lateral_movement, data_exfiltration"
                        style={{
                          width: '100%',
                          padding: `${SPACING.sm}px ${SPACING.md}px`,
                          borderRadius: BORDER_RADIUS.md,
                          border: `1px solid ${MODERN_COLORS.glassBorder}`,
                          background: MODERN_COLORS.background,
                          color: MODERN_COLORS.text,
                          fontSize: TYPOGRAPHY.fontSize.sm
                        }}
                      />
                    </div>

                    <div style={{ marginBottom: SPACING.lg }}>
                      <label style={{ display: 'flex', alignItems: 'center', gap: SPACING.sm, fontSize: TYPOGRAPHY.fontSize.sm }}>
                        <input
                          type="checkbox"
                          name="auto_start"
                          checked={newInvestigation.auto_start}
                          onChange={handleInputChange}
                          style={{ cursor: 'pointer' }}
                        />
                        Auto-start investigation after creation
                      </label>
                    </div>

                    <div style={{ display: 'flex', gap: SPACING.md, justifyContent: 'flex-end' }}>
                      <button
                        type="button"
                        onClick={() => setShowNewInvestigationForm(false)}
                        disabled={formLoading}
                        style={{
                          padding: `${SPACING.md}px ${SPACING.lg}px`,
                          borderRadius: BORDER_RADIUS.lg,
                          border: `1px solid ${MODERN_COLORS.glassBorder}`,
                          background: 'transparent',
                          color: MODERN_COLORS.text,
                          cursor: formLoading ? 'not-allowed' : 'pointer',
                          fontSize: TYPOGRAPHY.fontSize.sm,
                          fontWeight: TYPOGRAPHY.fontWeight.semibold
                        }}
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        disabled={formLoading || !newInvestigation.title}
                        style={{
                          padding: `${SPACING.md}px ${SPACING.lg}px`,
                          borderRadius: BORDER_RADIUS.lg,
                          border: 'none',
                          background: formLoading ? 'rgba(99, 102, 241, 0.5)' : MODERN_COLORS.primaryGradient,
                          color: '#ffffff',
                          cursor: formLoading || !newInvestigation.title ? 'not-allowed' : 'pointer',
                          fontSize: TYPOGRAPHY.fontSize.sm,
                          fontWeight: TYPOGRAPHY.fontWeight.semibold,
                          opacity: (!newInvestigation.title) ? 0.5 : 1
                        }}
                      >
                        {formLoading ? '⏳ Creating...' : '🚀 Start Investigation'}
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            )}

            <div style={{
              marginTop: SPACING.lg,
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
              gap: SPACING.lg
            }}>
              <div style={{
                padding: SPACING.lg,
                background: MODERN_COLORS.glass,
                borderRadius: BORDER_RADIUS.lg,
                border: `1px solid ${MODERN_COLORS.glassBorder}`
              }}>
                <h3 style={{ marginBottom: SPACING.sm }}>🔍 Log Analysis</h3>
                <p style={{ fontSize: TYPOGRAPHY.fontSize.sm, color: MODERN_COLORS.textSecondary }}>
                  Collect and analyze logs from Windows Event, Sysmon, and Defender
                </p>
              </div>
              <div style={{
                padding: SPACING.lg,
                background: MODERN_COLORS.glass,
                borderRadius: BORDER_RADIUS.lg,
                border: `1px solid ${MODERN_COLORS.glassBorder}`
              }}>
                <h3 style={{ marginBottom: SPACING.sm }}>🎯 IOC Extraction</h3>
                <p style={{ fontSize: TYPOGRAPHY.fontSize.sm, color: MODERN_COLORS.textSecondary }}>
                  Automatically extract and prioritize Indicators of Compromise
                </p>
              </div>
              <div style={{
                padding: SPACING.lg,
                background: MODERN_COLORS.glass,
                borderRadius: BORDER_RADIUS.lg,
                border: `1px solid ${MODERN_COLORS.glassBorder}`
              }}>
                <h3 style={{ marginBottom: SPACING.sm }}>🌐 Threat Intelligence</h3>
                <p style={{ fontSize: TYPOGRAPHY.fontSize.sm, color: MODERN_COLORS.textSecondary }}>
                  Correlate IOCs with VirusTotal, AbuseIPDB, and MITRE ATT&CK
                </p>
              </div>
              <div style={{
                padding: SPACING.lg,
                background: MODERN_COLORS.glass,
                borderRadius: BORDER_RADIUS.lg,
                border: `1px solid ${MODERN_COLORS.glassBorder}`
              }}>
                <h3 style={{ marginBottom: SPACING.sm }}>🤖 AI Analysis</h3>
                <p style={{ fontSize: TYPOGRAPHY.fontSize.sm, color: MODERN_COLORS.textSecondary }}>
                  AI-powered investigation and automated threat detection
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default InvestigationDashboard;