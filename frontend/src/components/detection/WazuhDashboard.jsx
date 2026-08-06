import React, { useState, useEffect, useRef, useCallback } from 'react';
import api from '../../services/api';

/* ─── Rich mock data ─────────────────────────────────────── */
const MOCK_ALERTS = [
  { id: 1,  rule: 'SSH Brute Force',          level: 12, severity: 'Critical', agent: 'web-server-01',   timestamp: new Date(Date.now()-1*60000).toISOString(),  description: 'Multiple failed SSH login attempts from 203.0.113.47' },
  { id: 2,  rule: 'Malware Detected',         level: 10, severity: 'Critical', agent: 'workstation-15',  timestamp: new Date(Date.now()-4*60000).toISOString(),  description: 'Trojan.GenericKD detected in C:\\Users\\Public' },
  { id: 3,  rule: 'Privilege Escalation',     level: 11, severity: 'Critical', agent: 'db-server-01',    timestamp: new Date(Date.now()-9*60000).toISOString(),  description: 'Unexpected sudo usage by service account' },
  { id: 4,  rule: 'Lateral Movement',         level: 9,  severity: 'High',     agent: 'dc-01',           timestamp: new Date(Date.now()-15*60000).toISOString(), description: 'Pass-the-hash attempt detected via SMB' },
  { id: 5,  rule: 'Ransomware Behavior',      level: 10, severity: 'Critical', agent: 'file-server-01',  timestamp: new Date(Date.now()-22*60000).toISOString(), description: 'Mass file encryption pattern detected' },
  { id: 6,  rule: 'C2 Communication',         level: 9,  severity: 'High',     agent: 'workstation-08',  timestamp: new Date(Date.now()-35*60000).toISOString(), description: 'Outbound beacon to known C2 server 198.51.100.0' },
  { id: 7,  rule: 'Suspicious Process',       level: 8,  severity: 'High',     agent: 'web-server-02',   timestamp: new Date(Date.now()-50*60000).toISOString(), description: 'cmd.exe spawned by IIS worker process' },
  { id: 8,  rule: 'Data Exfiltration',        level: 8,  severity: 'High',     agent: 'laptop-hr-03',    timestamp: new Date(Date.now()-65*60000).toISOString(), description: 'Unusually large upload to external storage' },
  { id: 9,  rule: 'Rootkit Detected',         level: 9,  severity: 'High',     agent: 'mail-server',     timestamp: new Date(Date.now()-80*60000).toISOString(), description: 'Hidden process detected via syscall hook' },
  { id: 10, rule: 'Policy Violation',         level: 6,  severity: 'Medium',   agent: 'workstation-22',  timestamp: new Date(Date.now()-90*60000).toISOString(), description: 'USB storage device connected' },
  { id: 11, rule: 'Vulnerability Exploit',    level: 8,  severity: 'High',     agent: 'web-server-01',   timestamp: new Date(Date.now()-110*60000).toISOString(),description: 'CVE-2024-1234 exploitation attempt' },
  { id: 12, rule: 'File Integrity Breach',    level: 7,  severity: 'Medium',   agent: 'dc-01',           timestamp: new Date(Date.now()-120*60000).toISOString(),description: '/etc/passwd modified unexpectedly' },
  { id: 13, rule: 'DNS Tunneling',            level: 7,  severity: 'Medium',   agent: 'workstation-11',  timestamp: new Date(Date.now()-140*60000).toISOString(),description: 'Anomalous DNS query size and frequency' },
  { id: 14, rule: 'Port Scan',                level: 5,  severity: 'Low',      agent: 'external',        timestamp: new Date(Date.now()-200*60000).toISOString(),description: 'SYN scan from 192.0.2.100 on 1024 ports' },
  { id: 15, rule: 'Login Outside Hours',      level: 5,  severity: 'Medium',   agent: 'dc-01',           timestamp: new Date(Date.now()-240*60000).toISOString(),description: 'Admin login at 03:42 local time' },
];

const MOCK_AGENTS = [
  { id: '001', name: 'web-server-01',  ip: '192.168.1.10',  status: 'active',        last_keepalive: new Date(Date.now()-30000).toISOString(),  os: 'Ubuntu 22.04 LTS',        version: '4.7.3' },
  { id: '002', name: 'web-server-02',  ip: '192.168.1.11',  status: 'active',        last_keepalive: new Date(Date.now()-45000).toISOString(),  os: 'Ubuntu 22.04 LTS',        version: '4.7.3' },
  { id: '003', name: 'db-server-01',   ip: '192.168.1.20',  status: 'active',        last_keepalive: new Date(Date.now()-20000).toISOString(),  os: 'CentOS Stream 9',         version: '4.7.2' },
  { id: '004', name: 'dc-01',          ip: '192.168.1.5',   status: 'active',        last_keepalive: new Date(Date.now()-10000).toISOString(),  os: 'Windows Server 2022',     version: '4.7.3' },
  { id: '005', name: 'file-server-01', ip: '192.168.1.30',  status: 'active',        last_keepalive: new Date(Date.now()-90000).toISOString(),  os: 'Windows Server 2019',     version: '4.7.1' },
  { id: '006', name: 'mail-server',    ip: '192.168.1.40',  status: 'active',        last_keepalive: new Date(Date.now()-15000).toISOString(),  os: 'Debian 12',               version: '4.7.3' },
  { id: '007', name: 'workstation-15', ip: '192.168.2.45',  status: 'disconnected',  last_keepalive: new Date(Date.now()-3600000).toISOString(), os: 'Windows 11 Pro',         version: '4.6.0' },
  { id: '008', name: 'laptop-hr-03',   ip: '192.168.3.12',  status: 'active',        last_keepalive: new Date(Date.now()-60000).toISOString(),  os: 'macOS 14 Sonoma',        version: '4.7.3' },
];

const SEVERITY_CONFIG = {
  Critical: { color: '#ef4444', glow: 'rgba(239,68,68,0.4)',  bg: 'rgba(239,68,68,0.12)' },
  High:     { color: '#f97316', glow: 'rgba(249,115,22,0.4)', bg: 'rgba(249,115,22,0.12)' },
  Medium:   { color: '#eab308', glow: 'rgba(234,179,8,0.4)',  bg: 'rgba(234,179,8,0.12)' },
  Low:      { color: '#22c55e', glow: 'rgba(34,197,94,0.4)',  bg: 'rgba(34,197,94,0.12)' },
};

function timeSince(iso) {
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)  return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  return `${Math.floor(s/3600)}h ago`;
}

/* ─── Sub-components ─────────────────────────────────────── */
const StatCard = ({ title, value, icon, colorKey, pulse }) => {
  const cfg = SEVERITY_CONFIG[colorKey] || { color: '#6366f1', glow: 'rgba(99,102,241,0.4)', bg: 'rgba(99,102,241,0.12)' };
  return (
    <div style={{
      background: 'linear-gradient(135deg,rgba(15,23,42,0.9),rgba(30,41,59,0.8))',
      border: `1px solid ${cfg.color}40`,
      borderRadius: '14px',
      padding: '20px 24px',
      display: 'flex',
      alignItems: 'center',
      gap: '16px',
      boxShadow: pulse ? `0 0 20px ${cfg.glow}` : '0 2px 12px rgba(0,0,0,0.3)',
      transition: 'box-shadow 0.6s ease',
      animation: pulse ? 'wazPulse 2s infinite' : 'none',
    }}>
      <div style={{ fontSize: '36px', lineHeight: 1 }}>{icon}</div>
      <div>
        <div style={{ fontSize: '28px', fontWeight: 800, color: cfg.color, lineHeight: 1 }}>{value}</div>
        <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '4px', letterSpacing: '0.05em' }}>{title}</div>
      </div>
    </div>
  );
};

const SeverityBar = ({ label, count, max, colorKey }) => {
  const cfg = SEVERITY_CONFIG[colorKey] || SEVERITY_CONFIG.Low;
  const pct = max > 0 ? Math.max(4, (count / max) * 100) : 4;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '10px' }}>
      <span style={{ width: '60px', fontSize: '12px', color: '#94a3b8', fontWeight: 600 }}>{label}</span>
      <div style={{ flex: 1, background: 'rgba(255,255,255,0.06)', borderRadius: '6px', height: '10px', overflow: 'hidden' }}>
        <div style={{
          width: `${pct}%`,
          height: '100%',
          background: `linear-gradient(90deg, ${cfg.color}, ${cfg.color}99)`,
          borderRadius: '6px',
          boxShadow: `0 0 6px ${cfg.glow}`,
          transition: 'width 1s ease',
        }} />
      </div>
      <span style={{ width: '32px', fontSize: '13px', fontWeight: 700, color: cfg.color, textAlign: 'right' }}>{count}</span>
    </div>
  );
};

/* ─── Main Component ─────────────────────────────────────── */
const WazuhDashboard = () => {
  const [alerts, setAlerts]     = useState([]);
  const [agents, setAgents]     = useState([]);
  const [stats, setStats]       = useState(null);
  const [loading, setLoading]   = useState(true);
  const [isLive, setIsLive]     = useState(false);
  const [countdown, setCountdown] = useState(30);
  const [timeRange, setTimeRange] = useState('24h');
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const timerRef = useRef(null);
  const cdRef    = useRef(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [alertsData, agentsData] = await Promise.all([
        api.getWazuhAlerts(timeRange),
        api.getWazuhAgents(),
      ]);

      let useReal = false;
      if (alertsData && alertsData.total_alerts > 0) {
        useReal = true;
        setAlerts(alertsData.alerts || []);
        setStats({
          total_alerts: alertsData.total_alerts,
          severity_distribution: alertsData.severity_distribution || {},
          active_agents: agentsData?.active_agents || 0,
          total_agents: agentsData?.total_agents || 0,
        });
        setAgents(agentsData?.agents || []);
        setIsLive(true);
      }
      if (!useReal) throw new Error('No live data');
    } catch {
      // Fallback to rich mock data
      const dist = MOCK_ALERTS.reduce((acc, a) => {
        acc[a.severity] = (acc[a.severity] || 0) + 1;
        return acc;
      }, {});
      setStats({
        total_alerts: MOCK_ALERTS.length,
        severity_distribution: dist,
        active_agents: MOCK_AGENTS.filter(a => a.status === 'active').length,
        total_agents: MOCK_AGENTS.length,
      });
      setAlerts(MOCK_ALERTS);
      setAgents(MOCK_AGENTS);
      setIsLive(false);
    } finally {
      setLoading(false);
    }
  }, [timeRange]);

  useEffect(() => {
    loadData();
    timerRef.current = setInterval(() => {
      setCountdown(30);
      loadData();
    }, 30000);
    cdRef.current = setInterval(() => setCountdown(c => (c > 0 ? c - 1 : 30)), 1000);
    return () => {
      clearInterval(timerRef.current);
      clearInterval(cdRef.current);
    };
  }, [loadData]);

  const sevDist  = stats?.severity_distribution || {};
  const maxSev   = Math.max(...Object.values(sevDist), 1);
  const critical = sevDist.Critical || 0;
  const high     = sevDist.High     || 0;
  const medium   = sevDist.Medium   || 0;
  const low      = sevDist.Low      || 0;

  const tabs = ['overview', 'alerts', 'agents'];

  if (loading && alerts.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '60vh', gap: '16px' }}>
        <div style={{ fontSize: '48px', animation: 'spin 1s linear infinite' }}>🛡️</div>
        <div style={{ color: '#6366f1', fontSize: '16px', fontWeight: 600 }}>Loading Wazuh Dashboard…</div>
        <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      </div>
    );
  }

  return (
    <div style={{ padding: '0', fontFamily: 'Inter,Segoe UI,sans-serif', color: '#e2e8f0', height: '100%', overflowY: 'auto' }}>
      <style>{`
        @keyframes wazPulse{0%,100%{opacity:1}50%{opacity:0.7}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
        .waz-tab{background:transparent;border:none;color:#64748b;padding:10px 20px;cursor:pointer;font-size:13px;font-weight:600;border-bottom:2px solid transparent;transition:all .2s;letter-spacing:.04em}
        .waz-tab.active{color:#6366f1;border-bottom-color:#6366f1}
        .waz-tab:hover{color:#a5b4fc}
        .waz-row{transition:background .15s;cursor:pointer}
        .waz-row:hover{background:rgba(99,102,241,0.07)!important}
        .waz-badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.04em}
        .waz-card{background:linear-gradient(135deg,rgba(15,23,42,0.95),rgba(20,30,50,0.9));border:1px solid rgba(99,102,241,0.15);border-radius:14px;padding:20px;animation:fadeIn .4s ease}
      `}</style>

      {/* ── Header ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '28px' }}>🛡️</span>
          <div>
            <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 800, color: '#f1f5f9' }}>Wazuh Security Dashboard</h2>
            <div style={{ fontSize: '12px', color: '#64748b', marginTop: '2px' }}>
              {isLive
                ? <span style={{ color: '#22c55e' }}>● LIVE — refreshes in {countdown}s</span>
                : <span style={{ color: '#f59e0b' }}>⚠ Demo data — Wazuh not reachable · refreshes in {countdown}s</span>}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <select
            value={timeRange}
            onChange={e => setTimeRange(e.target.value)}
            style={{ padding: '8px 12px', borderRadius: '8px', border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(15,23,42,0.8)', color: '#e2e8f0', fontSize: '13px', cursor: 'pointer' }}
          >
            <option value="1h">Last 1h</option>
            <option value="24h">Last 24h</option>
            <option value="7d">Last 7d</option>
            <option value="30d">Last 30d</option>
          </select>
          <button
            onClick={loadData}
            style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid rgba(99,102,241,0.4)', background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', fontSize: '13px', fontWeight: 600, cursor: 'pointer' }}
          >
            ↻ Refresh
          </button>
        </div>
      </div>

      {/* ── Stat Cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(160px,1fr))', gap: '14px', marginBottom: '24px' }}>
        <StatCard title="TOTAL ALERTS"   value={stats?.total_alerts || 0}              icon="🚨" colorKey="info"     pulse={false} />
        <StatCard title="CRITICAL"        value={critical}                               icon="🔴" colorKey="Critical" pulse={critical > 0} />
        <StatCard title="HIGH"            value={high}                                   icon="🟠" colorKey="High"     pulse={false} />
        <StatCard title="ACTIVE AGENTS"  value={stats?.active_agents || 0}             icon="🖥️" colorKey="Low"      pulse={false} />
        <StatCard title="TOTAL AGENTS"   value={stats?.total_agents || 0}              icon="📡" colorKey="info"     pulse={false} />
      </div>

      {/* ── Tabs ── */}
      <div style={{ display: 'flex', borderBottom: '1px solid rgba(99,102,241,0.2)', marginBottom: '20px' }}>
        {tabs.map(t => (
          <button key={t} className={`waz-tab${activeTab === t ? ' active' : ''}`} onClick={() => setActiveTab(t)}>
            {t === 'overview' ? '📊 Overview' : t === 'alerts' ? '🚨 Alerts' : '🖥️ Agents'}
          </button>
        ))}
      </div>

      {/* ── Overview Tab ── */}
      {activeTab === 'overview' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(320px,1fr))', gap: '16px' }}>
          {/* Severity Distribution */}
          <div className="waz-card">
            <h3 style={{ margin: '0 0 16px', fontSize: '14px', color: '#94a3b8', fontWeight: 700, letterSpacing: '.06em' }}>SEVERITY DISTRIBUTION</h3>
            <SeverityBar label="Critical" count={critical} max={maxSev} colorKey="Critical" />
            <SeverityBar label="High"     count={high}     max={maxSev} colorKey="High" />
            <SeverityBar label="Medium"   count={medium}   max={maxSev} colorKey="Medium" />
            <SeverityBar label="Low"      count={low}      max={maxSev} colorKey="Low" />
          </div>

          {/* Top Rules */}
          <div className="waz-card">
            <h3 style={{ margin: '0 0 16px', fontSize: '14px', color: '#94a3b8', fontWeight: 700, letterSpacing: '.06em' }}>TOP ATTACK RULES</h3>
            {Object.entries(
              alerts.reduce((acc, a) => { acc[a.rule] = (acc[a.rule] || 0) + 1; return acc; }, {})
            ).sort((a,b) => b[1]-a[1]).slice(0, 6).map(([rule, cnt], i) => (
              <div key={rule} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '7px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                <span style={{ fontSize: '13px', color: '#cbd5e1' }}><span style={{ color: '#6366f1', marginRight: '8px', fontWeight: 700 }}>#{i+1}</span>{rule}</span>
                <span style={{ fontSize: '12px', fontWeight: 700, color: '#6366f1', background: 'rgba(99,102,241,0.15)', padding: '2px 8px', borderRadius: '12px' }}>{cnt}</span>
              </div>
            ))}
          </div>

          {/* Recent 5 Alerts */}
          <div className="waz-card" style={{ gridColumn: '1 / -1' }}>
            <h3 style={{ margin: '0 0 16px', fontSize: '14px', color: '#94a3b8', fontWeight: 700, letterSpacing: '.06em' }}>RECENT ALERTS</h3>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                    {['RULE', 'SEVERITY', 'LEVEL', 'AGENT', 'WHEN'].map(h => (
                      <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: '#475569', fontWeight: 700, letterSpacing: '.05em', fontSize: '11px' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {alerts.slice(0, 8).map(alert => {
                    const cfg = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.Low;
                    return (
                      <tr key={alert.id} className="waz-row" style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }} onClick={() => { setSelectedAlert(alert); setActiveTab('alerts'); }}>
                        <td style={{ padding: '10px 12px' }}>
                          <div style={{ fontWeight: 600, color: '#e2e8f0' }}>{alert.rule}</div>
                          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>{alert.description}</div>
                        </td>
                        <td style={{ padding: '10px 12px' }}>
                          <span className="waz-badge" style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40` }}>{alert.severity}</span>
                        </td>
                        <td style={{ padding: '10px 12px', color: '#94a3b8', fontFamily: 'monospace' }}>{alert.level}</td>
                        <td style={{ padding: '10px 12px', color: '#a5b4fc' }}>{alert.agent}</td>
                        <td style={{ padding: '10px 12px', color: '#64748b', whiteSpace: 'nowrap' }}>{timeSince(alert.timestamp)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Alerts Tab ── */}
      {activeTab === 'alerts' && (
        <div style={{ display: 'grid', gridTemplateColumns: selectedAlert ? '1fr 380px' : '1fr', gap: '16px', animation: 'fadeIn .3s ease' }}>
          <div className="waz-card" style={{ padding: '0', overflow: 'hidden' }}>
            <div style={{ overflowX: 'auto', maxHeight: 'calc(100vh - 300px)', overflowY: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                <thead style={{ position: 'sticky', top: 0, background: 'rgba(15,23,42,0.97)', zIndex: 2 }}>
                  <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                    {['#', 'RULE / DESCRIPTION', 'SEVERITY', 'LVL', 'AGENT', 'TIME'].map(h => (
                      <th key={h} style={{ padding: '12px 16px', textAlign: 'left', color: '#475569', fontWeight: 700, letterSpacing: '.05em', fontSize: '11px' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((alert, idx) => {
                    const cfg = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.Low;
                    const isSelected = selectedAlert?.id === alert.id;
                    return (
                      <tr
                        key={alert.id}
                        className="waz-row"
                        style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', background: isSelected ? 'rgba(99,102,241,0.12)' : '' }}
                        onClick={() => setSelectedAlert(isSelected ? null : alert)}
                      >
                        <td style={{ padding: '10px 16px', color: '#475569', fontFamily: 'monospace', fontSize: '11px' }}>{idx+1}</td>
                        <td style={{ padding: '10px 16px' }}>
                          <div style={{ fontWeight: 600, color: '#e2e8f0' }}>{alert.rule}</div>
                          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>{alert.description}</div>
                        </td>
                        <td style={{ padding: '10px 16px' }}>
                          <span className="waz-badge" style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40` }}>{alert.severity}</span>
                        </td>
                        <td style={{ padding: '10px 16px', color: '#94a3b8', fontFamily: 'monospace', fontWeight: 700 }}>{alert.level}</td>
                        <td style={{ padding: '10px 16px', color: '#a5b4fc', fontWeight: 500 }}>{alert.agent}</td>
                        <td style={{ padding: '10px 16px', color: '#64748b', fontSize: '12px', whiteSpace: 'nowrap' }}>{timeSince(alert.timestamp)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {selectedAlert && (() => {
            const cfg = SEVERITY_CONFIG[selectedAlert.severity] || SEVERITY_CONFIG.Low;
            return (
              <div className="waz-card" style={{ animation: 'fadeIn .25s ease' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                  <h3 style={{ margin: 0, fontSize: '15px', color: '#f1f5f9', fontWeight: 700 }}>Alert Detail</h3>
                  <button onClick={() => setSelectedAlert(null)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: '16px' }}>✕</button>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                  <div>
                    <div style={{ color: '#475569', fontSize: '11px', fontWeight: 700, letterSpacing: '.06em', marginBottom: '4px' }}>RULE</div>
                    <div style={{ color: '#e2e8f0', fontWeight: 600 }}>{selectedAlert.rule}</div>
                  </div>
                  <div>
                    <div style={{ color: '#475569', fontSize: '11px', fontWeight: 700, letterSpacing: '.06em', marginBottom: '4px' }}>DESCRIPTION</div>
                    <div style={{ color: '#cbd5e1' }}>{selectedAlert.description}</div>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                    <div>
                      <div style={{ color: '#475569', fontSize: '11px', fontWeight: 700, letterSpacing: '.06em', marginBottom: '4px' }}>SEVERITY</div>
                      <span className="waz-badge" style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40` }}>{selectedAlert.severity}</span>
                    </div>
                    <div>
                      <div style={{ color: '#475569', fontSize: '11px', fontWeight: 700, letterSpacing: '.06em', marginBottom: '4px' }}>LEVEL</div>
                      <div style={{ color: cfg.color, fontWeight: 800, fontSize: '20px' }}>{selectedAlert.level}</div>
                    </div>
                  </div>
                  <div>
                    <div style={{ color: '#475569', fontSize: '11px', fontWeight: 700, letterSpacing: '.06em', marginBottom: '4px' }}>AGENT</div>
                    <div style={{ color: '#a5b4fc', fontFamily: 'monospace' }}>{selectedAlert.agent}</div>
                  </div>
                  <div>
                    <div style={{ color: '#475569', fontSize: '11px', fontWeight: 700, letterSpacing: '.06em', marginBottom: '4px' }}>TIMESTAMP</div>
                    <div style={{ color: '#64748b' }}>{new Date(selectedAlert.timestamp).toLocaleString()}</div>
                  </div>
                  <div style={{ marginTop: '8px', padding: '12px', background: 'rgba(99,102,241,0.08)', borderRadius: '8px', border: '1px solid rgba(99,102,241,0.2)' }}>
                    <div style={{ color: '#6366f1', fontSize: '12px', fontWeight: 700, marginBottom: '6px' }}>🧠 AI RECOMMENDATION</div>
                    <div style={{ color: '#94a3b8', fontSize: '12px', lineHeight: 1.6 }}>
                      {selectedAlert.severity === 'Critical'
                        ? 'Immediate action required. Isolate the affected agent, collect forensic evidence, and escalate to Tier-2 SOC.'
                        : selectedAlert.severity === 'High'
                        ? 'Investigate within 1 hour. Review agent logs, correlate with other alerts, and apply containment measures.'
                        : 'Schedule investigation. Document the incident and monitor for escalation patterns.'}
                    </div>
                  </div>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* ── Agents Tab ── */}
      {activeTab === 'agents' && (
        <div className="waz-card" style={{ animation: 'fadeIn .3s ease', padding: '0', overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)', background: 'rgba(15,23,42,0.6)' }}>
                  {['ID', 'NAME', 'IP ADDRESS', 'STATUS', 'OS', 'VERSION', 'LAST KEEPALIVE'].map(h => (
                    <th key={h} style={{ padding: '12px 16px', textAlign: 'left', color: '#475569', fontWeight: 700, letterSpacing: '.05em', fontSize: '11px' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {agents.map(agent => {
                  const active = agent.status === 'active';
                  return (
                    <tr key={agent.id} className="waz-row" style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <td style={{ padding: '12px 16px', color: '#64748b', fontFamily: 'monospace', fontSize: '12px' }}>{agent.id}</td>
                      <td style={{ padding: '12px 16px', color: '#e2e8f0', fontWeight: 600 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: active ? '#22c55e' : '#ef4444', boxShadow: active ? '0 0 6px #22c55e' : 'none', display: 'inline-block', flexShrink: 0 }} />
                          {agent.name}
                        </div>
                      </td>
                      <td style={{ padding: '12px 16px', color: '#a5b4fc', fontFamily: 'monospace' }}>{agent.ip}</td>
                      <td style={{ padding: '12px 16px' }}>
                        <span className="waz-badge" style={{ background: active ? 'rgba(34,197,94,0.12)' : 'rgba(239,68,68,0.12)', color: active ? '#22c55e' : '#ef4444', border: `1px solid ${active ? '#22c55e' : '#ef4444'}40` }}>
                          {agent.status}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px', color: '#94a3b8' }}>{agent.os}</td>
                      <td style={{ padding: '12px 16px', color: '#64748b', fontFamily: 'monospace', fontSize: '12px' }}>{agent.version || 'N/A'}</td>
                      <td style={{ padding: '12px 16px', color: '#64748b', fontSize: '12px' }}>{timeSince(agent.last_keepalive)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default WazuhDashboard;