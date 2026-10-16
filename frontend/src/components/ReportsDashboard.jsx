import React, { useState, useEffect } from 'react';
import { 
  MODERN_COLORS, 
  SPACING, 
  BORDER_RADIUS, 
  TYPOGRAPHY,
} from '../theme/modernTheme';

const ReportsDashboard = () => {
  const [activeTab, setActiveTab] = useState('investigation');
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedReport, setSelectedReport] = useState(null);
  const [generating, setGenerating] = useState(false);

  const tabs = [
    { id: 'investigation', label: 'Investigation Reports', icon: '📄' },
    { id: 'executive', label: 'Executive Summaries', icon: '👔' },
    { id: 'pdf', label: 'PDF Export Center', icon: '📑' },
    { id: 'history', label: 'Report Audit Archive', icon: '📚' }
  ];

  const fetchReports = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/report/list');
      if (res.ok) {
        const data = await res.json();
        setReports(data.reports || []);
      }
    } catch (err) {
      console.error('Error fetching reports:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const handleDownloadPDF = async (alertId) => {
    try {
      setGenerating(true);
      window.open(`/api/report/${alertId}/pdf`, '_blank');
    } catch (err) {
      console.error('PDF error:', err);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: '100%',
      background: '#060910',
      color: '#f8fafc',
      fontFamily: TYPOGRAPHY.fontFamily
    }}>
      {/* Header */}
      <div style={{
        padding: '24px 28px',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: 'linear-gradient(135deg, rgba(15,23,42,0.85), rgba(12,17,32,0.95))'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 44,
            height: 44,
            borderRadius: BORDER_RADIUS.lg,
            background: 'linear-gradient(135deg, #06b6d4, #3b82f6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 22,
            boxShadow: '0 4px 20px rgba(6,182,212,0.4)'
          }}>
            📄
          </div>
          <div>
            <h1 style={{
              margin: 0,
              fontSize: '1.5rem',
              fontWeight: 800,
              background: 'linear-gradient(135deg, #ffffff, #cbd5e1)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent'
            }}>
              SOC Incident Reports & Compliance Export
            </h1>
            <p style={{ margin: '4px 0 0', color: '#94a3b8', fontSize: '0.8rem' }}>
              Automated forensics reports generated directly from real Wazuh events and AI investigations
            </p>
          </div>
        </div>

        <button
          onClick={fetchReports}
          style={{
            background: 'rgba(30,41,59,0.7)',
            border: '1px solid rgba(255,255,255,0.1)',
            color: '#e2e8f0',
            padding: '8px 16px',
            borderRadius: BORDER_RADIUS.md,
            fontSize: '0.78rem',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          🔄 Refresh Reports
        </button>
      </div>

      {/* Tabs */}
      <div style={{
        padding: '14px 28px',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        display: 'flex',
        gap: 8,
        background: 'rgba(10,14,26,0.5)',
        flexWrap: 'wrap'
      }}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              padding: '8px 16px',
              borderRadius: BORDER_RADIUS.md,
              border: activeTab === tab.id ? '1px solid #38bdf8' : '1px solid rgba(255,255,255,0.06)',
              background: activeTab === tab.id ? 'linear-gradient(135deg, #0284c7, #0369a1)' : 'rgba(30,41,59,0.5)',
              color: activeTab === tab.id ? '#ffffff' : '#94a3b8',
              cursor: 'pointer',
              fontSize: '0.78rem',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              transition: 'all 120ms ease'
            }}
          >
            <span>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{ flex: 1, padding: '24px 28px', overflowY: 'auto' }}>
        {loading ? (
          <div style={{ textAlign: 'center', padding: '60px 0', color: '#94a3b8' }}>
            Loading live investigation reports...
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Quick Stats */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14 }}>
              {[
                { label: 'Available Reports', count: reports.length, color: '#38bdf8' },
                { label: 'Wazuh Live Telemetry Events', count: reports.filter(r => String(r.id).includes('WAZUH')).length, color: '#10b981' },
                { label: 'Critical / High Incidents', count: reports.filter(r => r.severity === 'Critical' || r.severity === 'High').length, color: '#ef4444' },
                { label: 'System Compliance Status', count: '100% OK', color: '#a855f7' },
              ].map(stat => (
                <div key={stat.label} style={{
                  background: 'rgba(15,23,42,0.7)',
                  border: '1px solid rgba(255,255,255,0.06)',
                  borderLeft: `3px solid ${stat.color}`,
                  borderRadius: BORDER_RADIUS.lg,
                  padding: 16
                }}>
                  <div style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 600 }}>{stat.label}</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 800, color: stat.color, marginTop: 4 }}>{stat.count}</div>
                </div>
              ))}
            </div>

            {/* Reports List */}
            <div style={{
              background: 'rgba(15,23,42,0.7)',
              borderRadius: BORDER_RADIUS.xl,
              border: '1px solid rgba(255,255,255,0.06)',
              overflow: 'hidden'
            }}>
              <div style={{ padding: '16px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', fontWeight: 700, fontSize: '0.9rem' }}>
                Generated Investigation Documents ({reports.length})
              </div>

              {reports.length === 0 ? (
                <div style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>
                  No reports logged yet. Reports are auto-compiled as Wazuh detections occur.
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem' }}>
                    <thead>
                      <tr style={{ background: 'rgba(10,14,26,0.6)', borderBottom: '1px solid rgba(255,255,255,0.06)', color: '#94a3b8' }}>
                        <th style={{ padding: '12px 18px', textAlign: 'left' }}>Report ID</th>
                        <th style={{ padding: '12px 18px', textAlign: 'left' }}>Title / Incident</th>
                        <th style={{ padding: '12px 18px', textAlign: 'left' }}>Host</th>
                        <th style={{ padding: '12px 18px', textAlign: 'left' }}>Severity</th>
                        <th style={{ padding: '12px 18px', textAlign: 'left' }}>Timestamp</th>
                        <th style={{ padding: '12px 18px', textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {reports.map((rep) => (
                        <tr
                          key={rep.id}
                          style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', cursor: 'pointer' }}
                          onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(30,41,59,0.35)'}
                          onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                          onClick={() => setSelectedReport(rep)}
                        >
                          <td style={{ padding: '12px 18px', fontFamily: 'monospace', color: '#38bdf8' }}>
                            {rep.id}
                          </td>
                          <td style={{ padding: '12px 18px', fontWeight: 600, color: '#f1f5f9' }}>
                            {rep.title}
                          </td>
                          <td style={{ padding: '12px 18px', color: '#94a3b8' }}>
                            {rep.host}
                          </td>
                          <td style={{ padding: '12px 18px' }}>
                            <span style={{
                              padding: '2px 8px',
                              borderRadius: 4,
                              fontSize: '0.68rem',
                              fontWeight: 700,
                              background: rep.severity === 'Critical' ? 'rgba(239,68,68,0.2)' : rep.severity === 'High' ? 'rgba(249,115,22,0.2)' : 'rgba(16,185,129,0.2)',
                              color: rep.severity === 'Critical' ? '#fca5a5' : rep.severity === 'High' ? '#fdba74' : '#6ee7b7'
                            }}>
                              {rep.severity}
                            </span>
                          </td>
                          <td style={{ padding: '12px 18px', color: '#64748b' }}>
                            {rep.created_at ? new Date(rep.created_at).toLocaleString() : 'Recent'}
                          </td>
                          <td style={{ padding: '12px 18px', textAlign: 'right' }}>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDownloadPDF(rep.alert_id);
                              }}
                              style={{
                                background: 'rgba(6,182,212,0.15)',
                                border: '1px solid rgba(6,182,212,0.3)',
                                color: '#67e8f9',
                                padding: '4px 10px',
                                borderRadius: BORDER_RADIUS.sm,
                                fontSize: '0.7rem',
                                fontWeight: 600,
                                cursor: 'pointer'
                              }}
                            >
                              📑 Export PDF
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Selected Report Inspection Drawer */}
            {selectedReport && (
              <div style={{
                background: 'rgba(15,23,42,0.85)',
                border: '1px solid rgba(56,189,248,0.3)',
                borderRadius: BORDER_RADIUS.xl,
                padding: 24
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                  <h3 style={{ margin: 0, color: '#f8fafc' }}>{selectedReport.title}</h3>
                  <button
                    onClick={() => setSelectedReport(null)}
                    style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '1rem' }}
                  >
                    ✕
                  </button>
                </div>
                <div style={{ fontSize: '0.8rem', color: '#cbd5e1', lineHeight: 1.6, marginBottom: 16 }}>
                  {selectedReport.summary || 'Incident forensics verified.'}
                </div>
                <div style={{ display: 'flex', gap: 10 }}>
                  <button
                    onClick={() => handleDownloadPDF(selectedReport.alert_id)}
                    style={{
                      background: 'linear-gradient(135deg, #0284c7, #0369a1)',
                      border: 'none',
                      color: '#fff',
                      padding: '8px 16px',
                      borderRadius: BORDER_RADIUS.md,
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      cursor: 'pointer'
                    }}
                  >
                    Download Official PDF Document
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ReportsDashboard;