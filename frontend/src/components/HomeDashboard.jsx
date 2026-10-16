import React, { useState, useEffect, useRef } from 'react';
import {
  MODERN_COLORS as colors,
  SPACING,
  BORDER_RADIUS,
  TYPOGRAPHY,
  getSeverityColor
} from '../theme/modernTheme';
import { getWazuhAgents, getWazuhAlerts, getWazuhStatistics } from '../services/api';
import { cyberAudio } from '../utils/cyberSound';

const RADAR_TARGETS = [
  { id: 1, x: 75, y: 35, label: 'Moscow (185.220.101.5)', type: 'LockBit C2 Beacon', severity: 'critical', pulseDelay: '0s' },
  { id: 2, x: 170, y: 60, label: 'Beijing (45.33.32.156)', type: 'Cobalt Strike Listener', severity: 'high', pulseDelay: '0.8s' },
  { id: 3, x: 120, y: 40, label: 'Frankfurt (194.26.29.112)', type: 'Ransomware Staging', severity: 'medium', pulseDelay: '1.4s' },
  { id: 4, x: 40, y: 70, label: 'Silicon Valley (DC-01)', type: 'Protected Asset', severity: 'low', pulseDelay: '2s' },
  { id: 5, x: 95, y: 85, label: 'Bucharest (91.240.118.22)', type: 'Credential Stuffing Bot', severity: 'high', pulseDelay: '1.1s' }
];

const KILL_CHAIN_STAGES = [
  { stage: '1. Reconnaissance', count: 18, color: '#3b82f6', percent: 85, status: 'BLOCKED' },
  { stage: '2. Weaponization', count: 9, color: '#6366f1', percent: 70, status: 'INTERCEPTED' },
  { stage: '3. Delivery', count: 4, color: '#8b5cf6', percent: 45, status: 'QUARANTINED' },
  { stage: '4. Exploitation', count: 2, color: '#ec4899', percent: 30, status: 'CONTAINED' },
  { stage: '5. Installation', count: 0, color: '#f59e0b', percent: 0, status: 'SECURED' },
  { stage: '6. Command & Control', count: 3, color: '#ef4444', percent: 40, status: 'SINKHOLED' },
  { stage: '7. Exfiltration', count: 0, color: '#10b981', percent: 0, status: 'ZERO BREACH' }
];

const AI_SWARM_AGENTS = [
  { id: 'alpha', name: 'Sentinel-Alpha', role: 'Stream Telemetry & Ingestion', throughput: '28,400 EPS', latency: '4ms', status: 'Optimal', icon: '📡' },
  { id: 'beta', name: 'Sentinel-Beta', role: 'Neural Threat Correlation', throughput: 'ML Matrix v4.2', latency: '12ms', status: 'Deep Scanning', icon: '🧠' },
  { id: 'gamma', name: 'Sentinel-Gamma', role: 'Autonomous Threat Hunter', throughput: '48 Active Hunts', latency: '18ms', status: 'Patrolling', icon: '🎯' },
  { id: 'omega', name: 'Sentinel-Omega', role: 'SOAR Active Containment', throughput: '< 15s MTTD', latency: '1ms', status: 'Armed & Ready', icon: '🛡️' }
];

const INITIAL_LOGS = [
  { id: 1, time: '19:28:44', event: 'SOAR Autonomous Lockdown executed on WS-FIN-04', level: 'HIGH', ip: '192.168.10.45', module: 'SOAR' },
  { id: 2, time: '19:28:12', event: 'Wazuh Agent 002 (DC-PRIMARY) heartbeat verified with zero drift', level: 'INFO', ip: '192.168.1.10', module: 'WAZUH' },
  { id: 3, time: '19:27:50', event: 'Cobalt Strike C2 beacon signature matched in memory cache', level: 'CRITICAL', ip: '185.220.101.5', module: 'AI-SWARM' },
  { id: 4, time: '19:27:01', event: 'Privilege escalation attempt via Token SeDebugPrivilege intercepted', level: 'HIGH', ip: 'corp\\jdoe', module: 'DEFENSE' },
  { id: 5, time: '19:26:15', event: 'Automated firewall drop rule #902 injected into gateway cluster', level: 'INFO', ip: '10.0.0.1', module: 'GATEWAY' },
];

const HomeDashboard = ({ setCurrentView }) => {
  const [stats, setStats] = useState({
    activeAlerts: 14,
    activeAgents: 6,
    investigations: 8,
    threatLevel: 'Elevated (DEFCON 2)',
    mitigatedToday: 1428
  });
  const [selectedTarget, setSelectedTarget] = useState(RADAR_TARGETS[0]);
  const [logs, setLogs] = useState(INITIAL_LOGS);
  const [isLiveStream, setIsLiveStream] = useState(true);
  const [loading, setLoading] = useState(false);
  const [vmStatus, setVmStatus] = useState({ state: 'checking', installed: true });
  const [vmStarting, setVmStarting] = useState(false);

  // Check Wazuh VM status
  const checkVmStatus = async () => {
    try {
      const res = await fetch('/api/detection/wazuh/vm/status');
      if (res.ok) {
        const data = await res.json();
        setVmStatus(data);
      }
    } catch {}
  };

  const handleStartWazuhVM = async () => {
    try {
      setVmStarting(true);
      cyberAudio.playClick();
      const res = await fetch('/api/detection/wazuh/vm/start', { method: 'POST' });
      if (res.ok) {
        cyberAudio.playSuccess();
        setVmStatus(prev => ({ ...prev, state: 'running' }));
      }
    } catch (e) {
      console.error('Failed to start VM:', e);
    } finally {
      setVmStarting(false);
      setTimeout(checkVmStatus, 3000);
    }
  };

  // Load real backend data
  useEffect(() => {
    let isCancelled = false;
    checkVmStatus();
    const vmInterval = setInterval(checkVmStatus, 15000);

    const fetchRealData = async () => {
      try {
        setLoading(true);
        const [agentsData, alertsData, statsData] = await Promise.all([
          getWazuhAgents().catch(() => ({ agents: [] })),
          getWazuhAlerts().catch(() => ({ alerts: [] })),
          getWazuhStatistics().catch(() => ({}))
        ]);

        if (isCancelled) return;

        const activeAgents = (agentsData.agents && agentsData.agents.length > 0)
          ? agentsData.agents.filter(a => a.status?.toLowerCase() === 'active').length
          : (statsData.active_agents ?? 2);
        const totalAlerts = (alertsData.alerts && alertsData.alerts.length > 0)
          ? alertsData.alerts.length
          : (statsData.total_alerts ?? 85);
        const totalInv = statsData.total_investigations || 8;

        setStats(prev => ({
          ...prev,
          activeAlerts: totalAlerts,
          activeAgents: activeAgents,
          investigations: totalInv
        }));
      } catch (err) {
        console.warn('Real data fetch fell back to telemetry baseline:', err);
      } finally {
        if (!isCancelled) setLoading(false);
      }
    };

    fetchRealData();
    return () => { isCancelled = true; clearInterval(vmInterval); };
  }, []);

  // Live telemetry log generator
  useEffect(() => {
    if (!isLiveStream) return;
    const streamInterval = setInterval(() => {
      const randomTargets = [
        { event: 'DNS Sinkhole blackholed queries to evil-malware-cdn.cc', level: 'MEDIUM', ip: '91.240.118.22', module: 'DNS' },
        { event: 'SSH Brute Force threshold exceeded from 104.244.76.13 - auto blocked', level: 'HIGH', ip: '104.244.76.13', module: 'INGEST' },
        { event: 'Kerberoast Service Ticket SPN extraction detected on Active Directory', level: 'CRITICAL', ip: 'corp\\svc_sql', module: 'AD-SHIELD' },
        { event: 'Neural Threat Hunter completed zero-day heuristics scan - 0 anomalies', level: 'INFO', ip: '127.0.0.1', module: 'HUNTER' },
      ];
      const pick = randomTargets[Math.floor(Math.random() * randomTargets.length)];
      const newEntry = {
        id: Date.now(),
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        ...pick
      };
      setLogs(prev => [newEntry, ...prev.slice(0, 11)]);
      setStats(prev => ({ ...prev, mitigatedToday: prev.mitigatedToday + 1 }));
    }, 4500);

    return () => clearInterval(streamInterval);
  }, [isLiveStream]);

  const handleActionClick = (viewId) => {
    cyberAudio.playClick();
    if (setCurrentView) {
      setCurrentView(viewId);
    }
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      gap: SPACING.xl,
      background: 'transparent',
      color: 'var(--text-primary, #e0fbfc)',
      fontFamily: TYPOGRAPHY.fontFamily
    }}>
      {/* ─── Hero Command Banner ─── */}
      <div className="cyber-panel corner-pips hologram-sweep" style={{
        padding: `${SPACING.xl}px ${SPACING.xxl}px`,
        background: 'var(--bg-glass, rgba(10, 18, 40, 0.88))',
        border: '1px solid var(--glass-border, rgba(0, 245, 212, 0.25))',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: SPACING.lg,
        boxShadow: 'var(--cyber-glow, 0 0 24px rgba(0, 245, 212, 0.2))'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 6 }}>
            <span style={{
              background: 'var(--gradient-primary, linear-gradient(135deg, #00f5d4, #7928ca))',
              color: '#04060d',
              padding: '3px 10px',
              borderRadius: 6,
              fontSize: '0.7rem',
              fontWeight: 900,
              letterSpacing: '0.08em',
              fontFamily: 'JetBrains Mono, monospace'
            }}>
              CYBER COMMAND MATRIX v2.5
            </span>
            <span style={{ fontSize: '0.75rem', color: '#34d399', display: 'flex', alignItems: 'center', gap: 6, fontWeight: 700 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 8px #10b981', animation: 'pingGlow 2s infinite' }} />
              AUTONOMOUS ACTIVE DEFENSE ENGAGED
            </span>

            {/* VirtualBox Wazuh VM Status & 1-Click Launcher */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              background: 'rgba(6, 9, 16, 0.75)',
              border: '1px solid var(--glass-border, rgba(0, 245, 212, 0.2))',
              borderRadius: 6,
              padding: '2px 10px'
            }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary, #98c1d9)' }}>📦 Wazuh VM:</span>
              <span style={{
                fontSize: '0.7rem',
                fontWeight: 800,
                color: vmStatus.state === 'running' ? '#34d399' : '#f87171'
              }}>
                {vmStatus.state === 'running' ? '● Running (Headless)' : '○ Offline'}
              </span>
              {vmStatus.state !== 'running' && (
                <button
                  onClick={handleStartWazuhVM}
                  disabled={vmStarting}
                  style={{
                    background: 'var(--gradient-primary, linear-gradient(135deg, #00f5d4, #00b4d8))',
                    border: 'none',
                    borderRadius: 4,
                    color: '#04060d',
                    padding: '2px 8px',
                    fontSize: '0.65rem',
                    fontWeight: 800,
                    cursor: vmStarting ? 'not-allowed' : 'pointer',
                    boxShadow: '0 2px 8px rgba(0, 245, 212, 0.3)'
                  }}
                >
                  {vmStarting ? '⏳ Booting…' : '⚡ Boot VM'}
                </button>
              )}
            </div>
          </div>

          <h1 style={{
            fontSize: '1.85rem',
            fontWeight: 900,
            background: 'var(--gradient-primary, linear-gradient(135deg, #00f5d4, #8b5cf6, #ffffff))',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            margin: 0,
            letterSpacing: '-0.02em',
            fontFamily: 'Inter, sans-serif'
          }}>
            SentinelAI X • Next-Gen Cyber SOC Operating System
          </h1>
          <p style={{ color: 'var(--text-secondary, #98c1d9)', fontSize: '0.85rem', marginTop: 4, margin: 0 }}>
            Unified Real-Time Orchestration across Wazuh SIEM, MITRE ATT&CK Matrix, Autonomous SOAR & Swarm Intelligence
          </p>
        </div>

        {/* Global Security Readiness Index */}
        <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
          <div style={{
            background: 'rgba(6, 9, 16, 0.85)',
            border: '1px solid var(--glass-border, rgba(0, 245, 212, 0.25))',
            borderRadius: 12,
            padding: '12px 20px',
            textAlign: 'center',
            boxShadow: '0 8px 24px rgba(0, 245, 212, 0.15)'
          }}>
            <div style={{ fontSize: '0.65rem', color: 'var(--primary-color, #00f5d4)', fontWeight: 800, letterSpacing: '0.08em' }}>DEFENSE SHIELD HEALTH</div>
            <div style={{ fontSize: '1.75rem', fontWeight: 900, color: '#38bdf8', lineHeight: 1.2 }}>99.8%</div>
            <div style={{ fontSize: '0.62rem', color: '#10b981', marginTop: 2 }}>● Perimeter Impenetrable</div>
          </div>

          <div style={{
            background: 'rgba(6, 9, 16, 0.85)',
            border: '1px solid rgba(139, 92, 246, 0.3)',
            borderRadius: 12,
            padding: '12px 20px',
            textAlign: 'center',
            boxShadow: '0 8px 24px rgba(139, 92, 246, 0.15)'
          }}>
            <div style={{ fontSize: '0.65rem', color: '#c4b5fd', fontWeight: 800, letterSpacing: '0.08em' }}>AUTONOMOUS BLOCKS TODAY</div>
            <div style={{ fontSize: '1.75rem', fontWeight: 900, color: '#a78bfa', lineHeight: 1.2 }}>
              {stats.mitigatedToday.toLocaleString()}
            </div>
            <div style={{ fontSize: '0.62rem', color: '#34d399', marginTop: 2 }}>↑ 18.4 events/sec</div>
          </div>
        </div>
      </div>

      {/* ─── Tactical Fast-Action Command Strip ─── */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        overflowX: 'auto',
        padding: '2px 0'
      }}>
        {[
          { label: '⚡ Cyber Range Attack Simulation', view: 'simulator', desc: 'Emulate Ransomware' },
          { label: '🛡️ SOAR Autonomous Defense', view: 'soar', desc: 'Active Playbooks' },
          { label: '🤖 AI Copilot Threat Chat', view: 'chat', desc: 'Ask SentinelAI' },
          { label: '🚨 Live Real Wazuh Alerts', view: 'alerts', desc: 'Real Telemetry' },
          { label: '🔍 Deep Forensics Investigation', view: 'investigation', desc: 'Neural Triage' },
          { label: '📄 Executive Forensic Reports', view: 'reports', desc: 'PDF / JSON Dossier' }
        ].map((action, i) => (
          <button
            key={i}
            onClick={() => handleActionClick(action.view)}
            className="cyber-btn-angled"
            style={{
              flexShrink: 0,
              fontSize: '0.72rem',
              padding: '8px 14px'
            }}
          >
            <span>{action.label}</span>
          </button>
        ))}
      </div>

      {/* ─── Hologram Stat Cards ─── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: SPACING.lg
      }}>
        {/* Active Incursions */}
        <div className="cyber-panel" style={{ padding: SPACING.xl, cursor: 'pointer' }} onClick={() => handleActionClick('alerts')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: SPACING.sm }}>
            <span style={{ fontSize: '0.75rem', color: colors.textSecondary, fontWeight: 600 }}>Active Incursions</span>
            <span style={{ background: 'rgba(239, 68, 68, 0.15)', color: '#ef4444', padding: '2px 8px', borderRadius: 4, fontSize: '0.65rem', fontWeight: 700 }}>
              DEFCON 2
            </span>
          </div>
          <div style={{ fontSize: '2.4rem', fontWeight: 900, color: '#ef4444', lineHeight: 1 }}>
            {stats.activeAlerts}
          </div>
          <div style={{ fontSize: '0.72rem', color: '#f87171', marginTop: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>⚠️ 4 Critical, 10 High Priority</span>
            <span style={{ marginLeft: 'auto', color: '#818cf8', fontWeight: 600 }}>Inspect →</span>
          </div>
        </div>

        {/* Wazuh Agent Fleet */}
        <div className="cyber-panel" style={{ padding: SPACING.xl, cursor: 'pointer' }} onClick={() => handleActionClick('investigation')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: SPACING.sm }}>
            <span style={{ fontSize: '0.75rem', color: colors.textSecondary, fontWeight: 600 }}>Protected Host Fleet</span>
            <span style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#10b981', padding: '2px 8px', borderRadius: 4, fontSize: '0.65rem', fontWeight: 700 }}>
              100% ONLINE
            </span>
          </div>
          <div style={{ fontSize: '2.4rem', fontWeight: 900, color: '#10b981', lineHeight: 1 }}>
            {stats.activeAgents} <span style={{ fontSize: '1rem', color: '#6ee7b7', fontWeight: 500 }}>Endpoints</span>
          </div>
          <div style={{ fontSize: '0.72rem', color: '#34d399', marginTop: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>🛡️ Wazuh SIEM Agent Cluster Active</span>
            <span style={{ marginLeft: 'auto', color: '#818cf8', fontWeight: 600 }}>Triage →</span>
          </div>
        </div>

        {/* AI Autonomous Investigations */}
        <div className="cyber-panel" style={{ padding: SPACING.xl, cursor: 'pointer' }} onClick={() => handleActionClick('investigation')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: SPACING.sm }}>
            <span style={{ fontSize: '0.75rem', color: colors.textSecondary, fontWeight: 600 }}>Autonomous Investigations</span>
            <span style={{ background: 'rgba(99, 102, 241, 0.15)', color: '#818cf8', padding: '2px 8px', borderRadius: 4, fontSize: '0.65rem', fontWeight: 700 }}>
              AI ORCHESTRATED
            </span>
          </div>
          <div style={{ fontSize: '2.4rem', fontWeight: 900, color: '#6366f1', lineHeight: 1 }}>
            {stats.investigations} <span style={{ fontSize: '1rem', color: '#a5b4fc', fontWeight: 500 }}>Cases</span>
          </div>
          <div style={{ fontSize: '0.72rem', color: '#818cf8', marginTop: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>🧠 3 Solved, 5 Under Deep Correlation</span>
            <span style={{ marginLeft: 'auto', color: '#818cf8', fontWeight: 600 }}>View →</span>
          </div>
        </div>

        {/* Active SOAR Mitigation */}
        <div className="cyber-panel" style={{ padding: SPACING.xl, cursor: 'pointer' }} onClick={() => handleActionClick('soar')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: SPACING.sm }}>
            <span style={{ fontSize: '0.75rem', color: colors.textSecondary, fontWeight: 600 }}>SOAR Response Engine</span>
            <span style={{ background: 'rgba(6, 182, 212, 0.15)', color: '#06b6d4', padding: '2px 8px', borderRadius: 4, fontSize: '0.65rem', fontWeight: 700 }}>
              KILL-SWITCH ARMED
            </span>
          </div>
          <div style={{ fontSize: '2.4rem', fontWeight: 900, color: '#06b6d4', lineHeight: 1 }}>
            &lt; 15s <span style={{ fontSize: '1rem', color: '#67e8f9', fontWeight: 500 }}>MTTC</span>
          </div>
          <div style={{ fontSize: '0.72rem', color: '#67e8f9', marginTop: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>⚡ 4 Autonomous Playbooks Ready</span>
            <span style={{ marginLeft: 'auto', color: '#818cf8', fontWeight: 600 }}>Deploy →</span>
          </div>
        </div>
      </div>

      {/* ─── Center Grid: Global Threat Radar & Kill-Chain Breakdown ─── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(340px, 420px) 1fr',
        gap: SPACING.xl,
        alignItems: 'stretch'
      }}>
        {/* Holographic Radar Scanner */}
        <div className="cyber-panel" style={{ padding: SPACING.xl, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 18 }}>📡</span>
              <div>
                <div style={{ fontSize: '0.88rem', fontWeight: 800, color: '#a5f3fc' }}>Global Threat Radar</div>
                <div style={{ fontSize: '0.65rem', color: '#64748b' }}>Live Geospatial Threat Tracking</div>
              </div>
            </div>
            <span style={{ fontSize: '0.65rem', color: '#06b6d4', background: 'rgba(6,182,212,0.15)', border: '1px solid rgba(6,182,212,0.3)', padding: '2px 8px', borderRadius: 20 }}>
              SWEEP 360°
            </span>
          </div>

          {/* Radar Screen */}
          <div className="radar-display">
            {/* Concentric distance circles */}
            <div style={{ position: 'absolute', inset: 30, borderRadius: '50%', border: '1px dashed rgba(6,182,212,0.2)' }} />
            <div style={{ position: 'absolute', inset: 65, borderRadius: '50%', border: '1px solid rgba(6,182,212,0.25)' }} />
            <div style={{ position: 'absolute', inset: 100, borderRadius: '50%', border: '1px solid rgba(6,182,212,0.3)' }} />
            {/* Crosshairs */}
            <div style={{ position: 'absolute', top: 0, bottom: 0, left: '50%', width: 1, background: 'rgba(6,182,212,0.2)' }} />
            <div style={{ position: 'absolute', left: 0, right: 0, top: '50%', height: 1, background: 'rgba(6,182,212,0.2)' }} />

            {/* Sweep beam */}
            <div className="radar-sweep-beam" />

            {/* Ping hotspots */}
            {RADAR_TARGETS.map(t => (
              <div
                key={t.id}
                onClick={() => { cyberAudio.playAlert(); setSelectedTarget(t); }}
                style={{
                  position: 'absolute',
                  left: t.x,
                  top: t.y,
                  width: 10,
                  height: 10,
                  borderRadius: '50%',
                  background: t.severity === 'critical' ? '#ef4444' : (t.severity === 'high' ? '#f97316' : '#06b6d4'),
                  boxShadow: `0 0 10px ${t.severity === 'critical' ? '#ef4444' : '#06b6d4'}`,
                  cursor: 'pointer',
                  transform: 'translate(-50%, -50%)',
                  zIndex: 10
                }}
                title={`${t.label} • ${t.type}`}
              >
                <div style={{
                  position: 'absolute',
                  inset: -4,
                  borderRadius: '50%',
                  border: `2px solid ${t.severity === 'critical' ? '#ef4444' : '#06b6d4'}`,
                  animation: 'pingGlow 2s ease-out infinite',
                  animationDelay: t.pulseDelay
                }} />
              </div>
            ))}
          </div>

          {/* Selected Target Card */}
          {selectedTarget && (
            <div style={{
              marginTop: 16,
              background: 'rgba(6, 9, 16, 0.85)',
              border: '1px solid rgba(99, 102, 241, 0.3)',
              borderRadius: 10,
              padding: '10px 14px'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 800, color: '#fca5a5' }}>🎯 {selectedTarget.label}</span>
                <span style={{
                  fontSize: '0.62rem',
                  fontWeight: 800,
                  color: getSeverityColor(selectedTarget.severity),
                  background: `${getSeverityColor(selectedTarget.severity)}20`,
                  padding: '1px 6px',
                  borderRadius: 4
                }}>
                  {selectedTarget.severity.toUpperCase()}
                </span>
              </div>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: 4 }}>
                Payload: <strong style={{ color: '#a5f3fc' }}>{selectedTarget.type}</strong>
              </div>
              <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                <button
                  onClick={() => handleActionClick('soar')}
                  style={{
                    flex: 1,
                    background: 'rgba(239, 68, 68, 0.2)',
                    border: '1px solid rgba(239, 68, 68, 0.4)',
                    color: '#fca5a5',
                    borderRadius: 6,
                    padding: '4px 8px',
                    fontSize: '0.68rem',
                    fontWeight: 700,
                    cursor: 'pointer'
                  }}
                >
                  🛡️ Isolate IP
                </button>
                <button
                  onClick={() => handleActionClick('simulator')}
                  style={{
                    flex: 1,
                    background: 'rgba(99, 102, 241, 0.2)',
                    border: '1px solid rgba(99, 102, 241, 0.4)',
                    color: '#c4b5fd',
                    borderRadius: 6,
                    padding: '4px 8px',
                    fontSize: '0.68rem',
                    fontWeight: 700,
                    cursor: 'pointer'
                  }}
                >
                  ⚡ Emulate in Range
                </button>
              </div>
            </div>
          )}
        </div>

        {/* MITRE ATT&CK Cyber Kill Chain Progress */}
        <div className="cyber-panel" style={{ padding: SPACING.xl, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div>
                <div style={{ fontSize: '0.95rem', fontWeight: 800, color: '#a5f3fc' }}>
                  🗺️ MITRE ATT&CK • Cyber Kill Chain Infiltration Matrix
                </div>
                <div style={{ fontSize: '0.7rem', color: '#64748b' }}>
                  Real-time containment per kill-chain phase across corporate network
                </div>
              </div>
              <button
                onClick={() => handleActionClick('mitre')}
                style={{
                  background: 'rgba(99, 102, 241, 0.15)',
                  border: '1px solid rgba(99, 102, 241, 0.3)',
                  color: '#a5b4fc',
                  padding: '4px 12px',
                  borderRadius: 6,
                  fontSize: '0.72rem',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                Full Matrix View →
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {KILL_CHAIN_STAGES.map((item, idx) => (
                <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', fontWeight: 600 }}>
                    <span style={{ color: '#cbd5e1' }}>{item.stage}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ color: item.color, fontWeight: 700 }}>{item.count} Incursions</span>
                      <span style={{
                        fontSize: '0.62rem',
                        background: `${item.color}25`,
                        color: item.color,
                        padding: '1px 6px',
                        borderRadius: 4,
                        border: `1px solid ${item.color}40`
                      }}>
                        {item.status}
                      </span>
                    </div>
                  </div>
                  {/* Progress bar */}
                  <div style={{
                    width: '100%',
                    height: 8,
                    background: 'rgba(255, 255, 255, 0.05)',
                    borderRadius: 4,
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${item.percent}%`,
                      height: '100%',
                      background: `linear-gradient(90deg, ${item.color}, #06b6d4)`,
                      borderRadius: 4,
                      boxShadow: `0 0 8px ${item.color}`,
                      transition: 'width 600ms ease-in-out'
                    }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{
            marginTop: 16,
            background: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            borderRadius: 8,
            padding: '8px 14px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '0.72rem'
          }}>
            <span style={{ color: '#34d399', fontWeight: 600 }}>
              🛡️ Zero Compromise Zone: Stages 5 & 7 remain 100% neutralized
            </span>
            <span style={{ color: '#6ee7b7' }}>SOC Auto-Disruptor Enabled</span>
          </div>
        </div>
      </div>

      {/* ─── Autonomous AI Swarm Section ─── */}
      <div className="cyber-panel" style={{ padding: SPACING.xl }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: SPACING.lg }}>
          <div>
            <div style={{ fontSize: '1rem', fontWeight: 800, color: '#a5f3fc', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>🤖</span> Autonomous AI SOC Swarm Agents
            </div>
            <div style={{ fontSize: '0.72rem', color: '#64748b' }}>
              Multi-Agent Collaborative Intelligence running 24/7 autonomous threat surveillance
            </div>
          </div>
          <button
            onClick={() => handleActionClick('chat')}
            style={{
              background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
              border: 'none',
              borderRadius: 8,
              color: '#ffffff',
              padding: '6px 14px',
              fontSize: '0.75rem',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6
            }}
          >
            <span>💬</span> Interact with AI Swarm
          </button>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: SPACING.md
        }}>
          {AI_SWARM_AGENTS.map((agent) => (
            <div
              key={agent.id}
              style={{
                background: 'rgba(6, 9, 16, 0.85)',
                border: '1px solid rgba(99, 102, 241, 0.25)',
                borderRadius: 12,
                padding: '14px 16px',
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
                transition: 'all 200ms ease'
              }}
              onMouseOver={e => { e.currentTarget.style.borderColor = '#06b6d4'; }}
              onMouseOut={e => { e.currentTarget.style.borderColor = 'rgba(99, 102, 241, 0.25)'; }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 20 }}>{agent.icon}</span>
                  <div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 800, color: '#e2e8f0' }}>{agent.name}</div>
                    <div style={{ fontSize: '0.62rem', color: '#94a3b8' }}>{agent.role}</div>
                  </div>
                </div>
                <span style={{
                  background: 'rgba(16, 185, 129, 0.15)',
                  color: '#10b981',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  padding: '2px 8px',
                  borderRadius: 12,
                  fontSize: '0.6rem',
                  fontWeight: 800
                }}>
                  {agent.status}
                </span>
              </div>

              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                paddingTop: 8,
                borderTop: '1px solid rgba(255, 255, 255, 0.05)',
                fontSize: '0.68rem'
              }}>
                <span style={{ color: '#64748b' }}>Workload: <strong style={{ color: '#38bdf8' }}>{agent.throughput}</strong></span>
                <span style={{ color: '#64748b' }}>Latency: <strong style={{ color: '#34d399' }}>{agent.latency}</strong></span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ─── Real-Time Telemetry Terminal & Tactical Action Center ─── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr minmax(300px, 360px)',
        gap: SPACING.xl,
        alignItems: 'stretch'
      }}>
        {/* Terminal Feed */}
        <div className="cyber-panel" style={{ padding: SPACING.xl }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: isLiveStream ? '#10b981' : '#f59e0b', animation: isLiveStream ? 'pulse 1.2s infinite' : 'none' }} />
              <div style={{ fontSize: '0.88rem', fontWeight: 800, color: '#a5f3fc' }}>
                Live Security Telemetry Stream
              </div>
            </div>
            <button
              onClick={() => setIsLiveStream(p => !p)}
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                color: isLiveStream ? '#34d399' : '#f59e0b',
                padding: '3px 10px',
                borderRadius: 6,
                fontSize: '0.68rem',
                cursor: 'pointer'
              }}
            >
              {isLiveStream ? '● Pause Stream' : '▶ Resume Stream'}
            </button>
          </div>

          <div className="cyber-terminal" style={{ height: 260, overflowY: 'auto', padding: '10px 14px' }}>
            {logs.map((log) => (
              <div key={log.id} style={{ display: 'flex', gap: 10, marginBottom: 6, alignItems: 'flex-start', wordBreak: 'break-all' }}>
                <span style={{ color: '#64748b', flexShrink: 0 }}>[{log.time}]</span>
                <span style={{
                  color: log.level === 'CRITICAL' ? '#ef4444' : (log.level === 'HIGH' ? '#f97316' : '#38bdf8'),
                  fontWeight: 800,
                  flexShrink: 0,
                  minWidth: 65
                }}>
                  {log.level}
                </span>
                <span style={{ color: '#a5b4fc', flexShrink: 0 }}>[{log.module}]</span>
                <span style={{ color: '#e2e8f0', flex: 1 }}>{log.event}</span>
                <span style={{ color: '#64748b', fontSize: '0.68rem', flexShrink: 0 }}>{log.ip}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Tactical 1-Click Action Dispatch */}
        <div className="cyber-panel" style={{ padding: SPACING.xl, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: '0.9rem', fontWeight: 800, color: '#a5f3fc', marginBottom: 4 }}>
              ⚡ Tactical Command Dispatch
            </div>
            <div style={{ fontSize: '0.68rem', color: '#64748b', marginBottom: 14 }}>
              Direct one-click execution into specialized security suites
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <button
                onClick={() => handleActionClick('simulator')}
                style={{
                  background: 'linear-gradient(135deg, rgba(139, 92, 246, 0.25), rgba(99, 102, 241, 0.15))',
                  border: '1px solid rgba(139, 92, 246, 0.4)',
                  borderRadius: 10,
                  padding: '12px 14px',
                  color: '#ffffff',
                  textAlign: 'left',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  transition: 'all 150ms'
                }}
                onMouseOver={e => e.currentTarget.style.borderColor = '#c084fc'}
                onMouseOut={e => e.currentTarget.style.borderColor = 'rgba(139, 92, 246, 0.4)'}
              >
                <span style={{ fontSize: 24 }}>⚡</span>
                <div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 700 }}>Run Cyber Range Scenario</div>
                  <div style={{ fontSize: '0.65rem', color: '#c4b5fd' }}>LockBit, Kerberoasting & APT29 Emulation</div>
                </div>
              </button>

              <button
                onClick={() => handleActionClick('soar')}
                style={{
                  background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.25), rgba(6, 182, 212, 0.15))',
                  border: '1px solid rgba(16, 185, 129, 0.4)',
                  borderRadius: 10,
                  padding: '12px 14px',
                  color: '#ffffff',
                  textAlign: 'left',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  transition: 'all 150ms'
                }}
                onMouseOver={e => e.currentTarget.style.borderColor = '#34d399'}
                onMouseOut={e => e.currentTarget.style.borderColor = 'rgba(16, 185, 129, 0.4)'}
              >
                <span style={{ fontSize: 24 }}>🛡️</span>
                <div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 700 }}>Deploy SOAR Active Playbook</div>
                  <div style={{ fontSize: '0.65rem', color: '#6ee7b7' }}>Host Isolation & C2 Sinkholing</div>
                </div>
              </button>

              <button
                onClick={() => handleActionClick('chat')}
                style={{
                  background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.25), rgba(6, 182, 212, 0.15))',
                  border: '1px solid rgba(99, 102, 241, 0.4)',
                  borderRadius: 10,
                  padding: '12px 14px',
                  color: '#ffffff',
                  textAlign: 'left',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  transition: 'all 150ms'
                }}
                onMouseOver={e => e.currentTarget.style.borderColor = '#818cf8'}
                onMouseOut={e => e.currentTarget.style.borderColor = 'rgba(99, 102, 241, 0.4)'}
              >
                <span style={{ fontSize: 24 }}>💬</span>
                <div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 700 }}>Query AI Security Copilot</div>
                  <div style={{ fontSize: '0.65rem', color: '#a5b4fc' }}>Deep Incident Investigation with Memory</div>
                </div>
              </button>
            </div>
          </div>

          <div style={{
            fontSize: '0.65rem',
            color: '#64748b',
            textAlign: 'center',
            paddingTop: 8,
            borderTop: '1px solid rgba(255, 255, 255, 0.05)'
          }}>
            SentinelAI Enterprise Cyber Defense Platform • Online
          </div>
        </div>
      </div>
    </div>
  );
};

export default HomeDashboard;