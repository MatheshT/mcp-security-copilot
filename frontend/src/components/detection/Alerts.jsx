import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { getWazuhAlerts, updateAlertStatus } from '../../services/api';
import {
  MODERN_COLORS,
  SPACING,
  BORDER_RADIUS,
  TYPOGRAPHY,
} from '../../theme/modernTheme';

const SEVERITY_CONFIG = {
  Critical: { bg: 'rgba(239, 68, 68, 0.15)', border: '#ef4444', text: '#fca5a5', badge: '#dc2626' },
  High: { bg: 'rgba(249, 115, 22, 0.15)', border: '#f97316', text: '#fdba74', badge: '#ea580c' },
  Medium: { bg: 'rgba(234, 179, 8, 0.15)', border: '#eab308', text: '#fde047', badge: '#ca8a04' },
  Low: { bg: 'rgba(16, 185, 129, 0.15)', border: '#10b981', text: '#6ee7b7', badge: '#059669' },
  Info: { bg: 'rgba(6, 182, 212, 0.15)', border: '#06b6d4', text: '#67e8f9', badge: '#0891b2' },
};

const Alerts = () => {
  const [alerts, setAlerts] = useState(() => {
    try {
      const cached = localStorage.getItem('sentinel_alerts_cache');
      return cached ? JSON.parse(cached) : [];
    } catch {
      return [];
    }
  });
  const [loading, setLoading] = useState(() => {
    try {
      const cached = localStorage.getItem('sentinel_alerts_cache');
      return !cached || JSON.parse(cached).length === 0;
    } catch {
      return true;
    }
  });
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [copiedLog, setCopiedLog] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [statusMap, setStatusMap] = useState({});
  const [notesMap, setNotesMap] = useState({});
  const [newNote, setNewNote] = useState('');

  const loadAlerts = useCallback(async (isRefresh = false) => {
    try {
      if (isRefresh) setRefreshing(true);
      setError(null);

      const data = await getWazuhAlerts({ limit: 200 });

      if (data && Array.isArray(data.alerts) && data.alerts.length > 0) {
        setAlerts(data.alerts);
        try {
          localStorage.setItem('sentinel_alerts_cache', JSON.stringify(data.alerts));
        } catch {}
      } else if (!alerts.length) {
        setAlerts([]);
      }
    } catch (err) {
      console.error('Error fetching Wazuh alerts:', err);
      if (!alerts.length) {
        setError(err.message || 'Connecting to Wazuh SIEM node...');
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [alerts.length]);

  useEffect(() => {
    loadAlerts();
    // Auto refresh every 20 seconds
    const interval = setInterval(() => loadAlerts(true), 20000);
    return () => clearInterval(interval);
  }, [loadAlerts]);

  // Statistics calculation
  const stats = useMemo(() => {
    const total = alerts.length;
    const critical = alerts.filter(a => a.severity === 'Critical').length;
    const high = alerts.filter(a => a.severity === 'High').length;
    const medium = alerts.filter(a => a.severity === 'Medium').length;
    const low = alerts.filter(a => a.severity === 'Low').length;
    return { total, critical, high, medium, low };
  }, [alerts]);

  // Filtered alert list
  const filteredAlerts = useMemo(() => {
    return alerts.filter(alert => {
      // Severity filter
      if (filterSeverity !== 'all' && alert.severity?.toLowerCase() !== filterSeverity.toLowerCase()) {
        return false;
      }

      // Status filter
      const currentStatus = statusMap[alert.id] || 'Open';
      if (filterStatus !== 'all' && currentStatus.toLowerCase() !== filterStatus.toLowerCase()) {
        return false;
      }

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const ruleDesc = (alert.rule?.description || '').toLowerCase();
        const ruleId = String(alert.rule?.id || '');
        const agentName = (alert.agent?.name || '').toLowerCase();
        const fullLog = (alert.full_log || '').toLowerCase();
        const id = String(alert.id || '');
        return ruleDesc.includes(q) || ruleId.includes(q) || agentName.includes(q) || fullLog.includes(q) || id.includes(q);
      }

      return true;
    });
  }, [alerts, filterSeverity, filterStatus, searchQuery, statusMap]);

  const handleStatusChange = (alertId, newStatus) => {
    setStatusMap(prev => ({ ...prev, [alertId]: newStatus }));
    try {
      updateAlertStatus(alertId, newStatus);
    } catch (e) {
      console.warn('Backend status sync:', e);
    }
  };

  const handleAddNote = (alertId) => {
    if (!newNote.trim()) return;
    setNotesMap(prev => ({
      ...prev,
      [alertId]: [...(prev[alertId] || []), { text: newNote.trim(), time: new Date().toLocaleTimeString() }]
    }));
    setNewNote('');
  };

  const handleCopyLog = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedLog(true);
    setTimeout(() => setCopiedLog(false), 2000);
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      gap: SPACING.xl,
      background: '#060910',
      minHeight: '100%',
      fontFamily: TYPOGRAPHY.fontFamily,
      color: '#f8fafc',
    }}>
      {/* ─── Header & Telemetry Status ─── */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(15,23,42,0.85), rgba(12,17,32,0.95))',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: BORDER_RADIUS.xl,
        padding: '24px 28px',
        backdropFilter: 'blur(16px)',
        boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
        position: 'relative',
        overflow: 'hidden'
      }}>
        <div style={{
          position: 'absolute',
          top: 0,
          right: 0,
          width: 320,
          height: 120,
          background: 'radial-gradient(ellipse at top right, rgba(99,102,241,0.12), transparent 70%)',
          pointerEvents: 'none'
        }} />

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{
                width: 44,
                height: 44,
                borderRadius: BORDER_RADIUS.lg,
                background: 'linear-gradient(135deg, #ef4444, #f97316)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 22,
                boxShadow: '0 4px 20px rgba(239,68,68,0.4)'
              }}>
                🚨
              </div>
              <div>
                <h1 style={{
                  margin: 0,
                  fontSize: '1.5rem',
                  fontWeight: 800,
                  letterSpacing: '-0.02em',
                  background: 'linear-gradient(135deg, #ffffff, #cbd5e1)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent'
                }}>
                  Live Security Alerts & Incident Stream
                </h1>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 4 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{
                      width: 8,
                      height: 8,
                      borderRadius: '50%',
                      background: '#10b981',
                      boxShadow: '0 0 10px #10b981',
                      display: 'inline-block'
                    }} />
                    <span style={{ fontSize: '0.72rem', fontWeight: 600, color: '#10b981', letterSpacing: '0.05em' }}>
                      WAZUH SIEM TELEMETRY LIVE
                    </span>
                  </div>
                  <span style={{ color: 'rgba(255,255,255,0.2)' }}>•</span>
                  <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                    Node: <code style={{ color: '#67e8f9' }}>192.168.56.101</code>
                  </span>
                  <span style={{ color: 'rgba(255,255,255,0.2)' }}>•</span>
                  <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                    Source: <code style={{ color: '#a5b4fc' }}>/var/ossec/logs/alerts/alerts.log</code>
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              onClick={() => loadAlerts(true)}
              disabled={refreshing}
              style={{
                background: 'rgba(30,41,59,0.7)',
                border: '1px solid rgba(255,255,255,0.1)',
                color: '#e2e8f0',
                padding: '8px 16px',
                borderRadius: BORDER_RADIUS.md,
                fontSize: '0.78rem',
                fontWeight: 600,
                cursor: refreshing ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                transition: 'all 150ms ease'
              }}
              onMouseOver={e => e.currentTarget.style.borderColor = 'rgba(16,185,129,0.5)'}
              onMouseOut={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)'}
            >
              <span style={{ display: 'inline-block', animation: refreshing ? 'spin 1s linear infinite' : 'none' }}>🔄</span>
              {refreshing ? 'Polling...' : 'Refresh'}
            </button>
          </div>
        </div>
      </div>

      {/* ─── Metric Counter Badges ─── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: 16
      }}>
        {[
          { label: 'Total Events', count: stats.total, color: '#10b981', icon: '📊', bg: 'rgba(16,185,129,0.1)' },
          { label: 'Critical Severity', count: stats.critical, color: '#ef4444', icon: '🔴', bg: 'rgba(239,68,68,0.1)' },
          { label: 'High Severity', count: stats.high, color: '#f97316', icon: '🟠', bg: 'rgba(249,115,22,0.1)' },
          { label: 'Medium Severity', count: stats.medium, color: '#eab308', icon: '🟡', bg: 'rgba(234,179,8,0.1)' },
          { label: 'Low Severity', count: stats.low, color: '#10b981', icon: '🟢', bg: 'rgba(16,185,129,0.1)' },
        ].map(card => (
          <div
            key={card.label}
            style={{
              background: 'rgba(15,23,42,0.65)',
              border: `1px solid rgba(255,255,255,0.06)`,
              borderLeft: `3px solid ${card.color}`,
              borderRadius: BORDER_RADIUS.lg,
              padding: '16px 20px',
              backdropFilter: 'blur(12px)',
              transition: 'transform 150ms ease, box-shadow 150ms ease'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                {card.label}
              </span>
              <span style={{ fontSize: '1rem' }}>{card.icon}</span>
            </div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: card.color, marginTop: 4 }}>
              {card.count}
            </div>
          </div>
        ))}
      </div>

      {/* ─── Filter & Search Bar ─── */}
      <div style={{
        background: 'rgba(15,23,42,0.7)',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: BORDER_RADIUS.xl,
        padding: '16px 20px',
        display: 'flex',
        flexWrap: 'wrap',
        gap: 16,
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        {/* Severity Tabs */}
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {['all', 'critical', 'high', 'medium', 'low'].map(sev => {
            const isActive = filterSeverity === sev;
            return (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                style={{
                  background: isActive ? 'linear-gradient(135deg, #10b981, #059669)' : 'rgba(30,41,59,0.5)',
                  border: `1px solid ${isActive ? '#34d399' : 'rgba(16,185,129,0.2)'}`,
                  color: isActive ? '#fff' : '#94a3b8',
                  padding: '6px 14px',
                  borderRadius: BORDER_RADIUS.md,
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  textTransform: 'capitalize',
                  transition: 'all 120ms ease'
                }}
              >
                {sev}
              </button>
            );
          })}
        </div>

        {/* Search Input & Status Dropdown */}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flex: 1, maxWidth: 450, minWidth: 260 }}>
          <div style={{ position: 'relative', width: '100%' }}>
            <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', opacity: 0.5, fontSize: '0.8rem' }}>🔍</span>
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search by rule, agent, alert ID or event text..."
              style={{
                width: '100%',
                background: 'rgba(10,14,26,0.8)',
                border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: BORDER_RADIUS.md,
                padding: '8px 12px 8px 34px',
                color: '#f8fafc',
                fontSize: '0.78rem',
                outline: 'none',
                fontFamily: TYPOGRAPHY.fontFamily
              }}
              onFocus={e => e.target.style.borderColor = 'rgba(16,185,129,0.5)'}
              onBlur={e => e.target.style.borderColor = 'rgba(255,255,255,0.08)'}
            />
          </div>

          <select
            value={filterStatus}
            onChange={e => setFilterStatus(e.target.value)}
            style={{
              background: 'rgba(10,14,26,0.8)',
              border: '1px solid rgba(255,255,255,0.08)',
              color: '#94a3b8',
              borderRadius: BORDER_RADIUS.md,
              padding: '8px 12px',
              fontSize: '0.78rem',
              outline: 'none',
              cursor: 'pointer'
            }}
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="closed">Closed</option>
          </select>
        </div>
      </div>

      {/* ─── Alerts Stream Table ─── */}
      <div style={{
        background: 'rgba(15,23,42,0.7)',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: BORDER_RADIUS.xl,
        overflow: 'hidden',
        backdropFilter: 'blur(16px)',
        boxShadow: '0 8px 32px rgba(0,0,0,0.3)'
      }}>
        {loading ? (
          <div style={{ padding: '60px 20px', textAlign: 'center' }}>
            <div style={{
              width: 40,
              height: 40,
              borderRadius: '50%',
              border: '3px solid rgba(16,185,129,0.2)',
              borderTopColor: '#10b981',
              animation: 'spin 0.8s linear infinite',
              margin: '0 auto 16px'
            }} />
            <div style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Reading real-time alerts from Wazuh Node...</div>
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div style={{ padding: '60px 20px', textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', marginBottom: 12 }}>🛡️</div>
            <div style={{ color: '#f8fafc', fontWeight: 600, fontSize: '1rem', marginBottom: 6 }}>
              No Security Alerts in Current Filter
            </div>
            <div style={{ color: '#94a3b8', fontSize: '0.8rem', maxWidth: 440, margin: '0 auto' }}>
              Wazuh SIEM engine is running and monitoring live telemetry. No events match the active criteria.
            </div>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
              <thead>
                <tr style={{
                  background: 'rgba(10,14,26,0.6)',
                  borderBottom: '1px solid rgba(255,255,255,0.08)',
                  color: '#94a3b8',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  fontSize: '0.68rem'
                }}>
                  <th style={{ padding: '14px 20px' }}>Severity</th>
                  <th style={{ padding: '14px 16px' }}>Rule & Description</th>
                  <th style={{ padding: '14px 16px' }}>Agent</th>
                  <th style={{ padding: '14px 16px' }}>Rule ID</th>
                  <th style={{ padding: '14px 16px' }}>Status</th>
                  <th style={{ padding: '14px 16px' }}>Timestamp</th>
                  <th style={{ padding: '14px 20px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((alert, idx) => {
                  const sevStyle = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.Low;
                  const currentStatus = statusMap[alert.id] || 'Open';

                  return (
                    <tr
                      key={alert.id || idx}
                      onClick={() => setSelectedAlert(alert)}
                      style={{
                        borderBottom: '1px solid rgba(255,255,255,0.04)',
                        cursor: 'pointer',
                        transition: 'background 120ms ease',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(30,41,59,0.35)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <td style={{ padding: '14px 20px' }}>
                        <span style={{
                          background: sevStyle.bg,
                          border: `1px solid ${sevStyle.border}`,
                          color: sevStyle.text,
                          padding: '3px 10px',
                          borderRadius: 20,
                          fontSize: '0.68rem',
                          fontWeight: 700,
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 5
                        }}>
                          <span style={{ width: 6, height: 6, borderRadius: '50%', background: sevStyle.badge }} />
                          {alert.severity} (Lvl {alert.level})
                        </span>
                      </td>

                      <td style={{ padding: '14px 16px', maxWidth: 360 }}>
                        <div style={{ fontWeight: 600, color: '#f1f5f9', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {alert.rule?.description || 'Security Event'}
                        </div>
                        {alert.rule?.groups?.length > 0 && (
                          <div style={{ display: 'flex', gap: 4, marginTop: 4, flexWrap: 'wrap' }}>
                            {alert.rule.groups.slice(0, 3).map((g, i) => (
                              <span key={i} style={{
                                background: 'rgba(99,102,241,0.1)',
                                color: '#a5b4fc',
                                fontSize: '0.62rem',
                                padding: '1px 6px',
                                borderRadius: 4,
                                border: '1px solid rgba(16,185,129,0.2)'
                              }}>
                                {g}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>

                      <td style={{ padding: '14px 16px' }}>
                        <div style={{ fontFamily: 'monospace', color: '#67e8f9', fontWeight: 600 }}>
                          {alert.agent?.name || 'wazuh-manager'}
                        </div>
                        <div style={{ fontSize: '0.65rem', color: '#64748b' }}>
                          ID: {alert.agent?.id || '000'}
                        </div>
                      </td>

                      <td style={{ padding: '14px 16px' }}>
                        <code style={{ background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: 4, color: '#e2e8f0', fontSize: '0.72rem' }}>
                          #{alert.rule?.id || 'N/A'}
                        </code>
                      </td>

                      <td style={{ padding: '14px 16px' }}>
                        <span style={{
                          padding: '2px 8px',
                          borderRadius: 6,
                          fontSize: '0.7rem',
                          fontWeight: 600,
                          background: currentStatus === 'Closed' ? 'rgba(16,185,129,0.15)' : currentStatus === 'Investigating' ? 'rgba(234,179,8,0.15)' : 'rgba(239,68,68,0.15)',
                          color: currentStatus === 'Closed' ? '#6ee7b7' : currentStatus === 'Investigating' ? '#fde047' : '#fca5a5',
                          border: `1px solid ${currentStatus === 'Closed' ? 'rgba(16,185,129,0.3)' : currentStatus === 'Investigating' ? 'rgba(234,179,8,0.3)' : 'rgba(239,68,68,0.3)'}`
                        }}>
                          {currentStatus}
                        </span>
                      </td>

                      <td style={{ padding: '14px 16px', color: '#94a3b8', fontSize: '0.72rem' }}>
                        {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : 'Recent'}
                      </td>

                      <td style={{ padding: '14px 20px', textAlign: 'right' }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedAlert(alert);
                          }}
                          style={{
                            background: 'rgba(99,102,241,0.15)',
                            border: '1px solid rgba(99,102,241,0.3)',
                            color: '#a5b4fc',
                            padding: '4px 10px',
                            borderRadius: BORDER_RADIUS.sm,
                            fontSize: '0.7rem',
                            cursor: 'pointer',
                            fontWeight: 600
                          }}
                        >
                          Inspect ➜
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ─── Alert Details Modal ─── */}
      {selectedAlert && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.75)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: 20
        }}>
          <div style={{
            background: '#0d1322',
            border: '1px solid rgba(99,102,241,0.3)',
            borderRadius: BORDER_RADIUS.xxl,
            width: '100%',
            maxWidth: 750,
            maxHeight: '88vh',
            overflowY: 'auto',
            padding: 28,
            boxShadow: '0 24px 64px rgba(0,0,0,0.6)',
            position: 'relative'
          }}>
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
              <div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
                  <span style={{
                    background: (SEVERITY_CONFIG[selectedAlert.severity] || SEVERITY_CONFIG.Low).bg,
                    border: `1px solid ${(SEVERITY_CONFIG[selectedAlert.severity] || SEVERITY_CONFIG.Low).border}`,
                    color: (SEVERITY_CONFIG[selectedAlert.severity] || SEVERITY_CONFIG.Low).text,
                    padding: '2px 10px',
                    borderRadius: 20,
                    fontSize: '0.7rem',
                    fontWeight: 700
                  }}>
                    {selectedAlert.severity} (Level {selectedAlert.level})
                  </span>
                  <span style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'monospace' }}>
                    Alert ID: {selectedAlert.id}
                  </span>
                </div>
                <h2 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 700, color: '#f8fafc' }}>
                  {selectedAlert.rule?.description || 'Security Event Details'}
                </h2>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                style={{
                  background: 'rgba(255,255,255,0.06)',
                  border: 'none',
                  color: '#94a3b8',
                  width: 32,
                  height: 32,
                  borderRadius: '50%',
                  cursor: 'pointer',
                  fontSize: '1rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}
              >
                ✕
              </button>
            </div>

            {/* Grid properties */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(2, 1fr)',
              gap: 12,
              background: 'rgba(15,23,42,0.6)',
              padding: 16,
              borderRadius: BORDER_RADIUS.lg,
              border: '1px solid rgba(255,255,255,0.04)',
              marginBottom: 16,
              fontSize: '0.75rem'
            }}>
              <div><span style={{ color: '#64748b' }}>Agent:</span> <strong style={{ color: '#67e8f9' }}>{selectedAlert.agent?.name}</strong></div>
              <div><span style={{ color: '#64748b' }}>Location:</span> <strong style={{ color: '#e2e8f0' }}>{selectedAlert.location || 'Local'}</strong></div>
              <div><span style={{ color: '#64748b' }}>Rule ID:</span> <strong style={{ color: '#a5b4fc' }}>{selectedAlert.rule?.id || 'N/A'}</strong></div>
              <div><span style={{ color: '#64748b' }}>Timestamp:</span> <strong style={{ color: '#e2e8f0' }}>{selectedAlert.timestamp}</strong></div>
            </div>

            {/* Full log raw content */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: '0.72rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase' }}>
                  Telemetry Log Payload
                </span>
                <button
                  onClick={() => handleCopyLog(selectedAlert.full_log)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: copiedLog ? '#10b981' : '#818cf8',
                    cursor: 'pointer',
                    fontSize: '0.72rem',
                    fontWeight: 600
                  }}
                >
                  {copiedLog ? '✓ Copied!' : '⎘ Copy Log'}
                </button>
              </div>
              <pre style={{
                background: '#070a13',
                border: '1px solid rgba(255,255,255,0.06)',
                borderRadius: BORDER_RADIUS.md,
                padding: '12px 14px',
                fontSize: '0.72rem',
                color: '#67e8f9',
                fontFamily: 'JetBrains Mono, monospace',
                maxHeight: 180,
                overflowY: 'auto',
                whiteHeight: 'pre-wrap',
                wordBreak: 'break-word',
                lineHeight: 1.5
              }}>
                {selectedAlert.full_log || 'No raw log text'}
              </pre>
            </div>

            {/* Quick Actions & Status */}
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: 12,
              paddingTop: 16,
              borderTop: '1px solid rgba(255,255,255,0.06)'
            }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>Update Status:</span>
                {['Open', 'Investigating', 'Closed'].map(st => (
                  <button
                    key={st}
                    onClick={() => handleStatusChange(selectedAlert.id, st)}
                    style={{
                      background: (statusMap[selectedAlert.id] || 'Open') === st ? 'rgba(99,102,241,0.3)' : 'rgba(30,41,59,0.5)',
                      border: `1px solid ${(statusMap[selectedAlert.id] || 'Open') === st ? '#818cf8' : 'rgba(255,255,255,0.08)'}`,
                      color: (statusMap[selectedAlert.id] || 'Open') === st ? '#a5b4fc' : '#94a3b8',
                      padding: '4px 10px',
                      borderRadius: BORDER_RADIUS.sm,
                      fontSize: '0.7rem',
                      cursor: 'pointer',
                      fontWeight: 600
                    }}
                  >
                    {st}
                  </button>
                ))}
              </div>

              <button
                onClick={() => setSelectedAlert(null)}
                style={{
                  background: 'linear-gradient(135deg, #10b981, #059669)',
                  border: 'none',
                  color: '#fff',
                  padding: '8px 20px',
                  borderRadius: BORDER_RADIUS.md,
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Alerts;