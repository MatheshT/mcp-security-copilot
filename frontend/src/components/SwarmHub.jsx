import React, { useState, useEffect, useRef, useCallback } from 'react';
import { MODERN_COLORS, SPACING, BORDER_RADIUS, TYPOGRAPHY } from '../theme/modernTheme';
import { cyberAudio } from '../utils/cyberSound';

const SwarmHub = () => {
  const [agents, setAgents] = useState([]);
  const [loadingAgents, setLoadingAgents] = useState(true);
  const [orchestrating, setOrchestrating] = useState(false);
  const [swarmResult, setSwarmResult] = useState(null);
  const [stixBundle, setStixBundle] = useState(null);
  const [targetIp, setTargetIp] = useState('185.220.101.45');
  const [targetHost, setTargetHost] = useState('Windows11');
  const [taxiiToast, setTaxiiToast] = useState(null);
  const radarCanvasRef = useRef(null);

  const getApiUrl = useCallback((path) => {
    const base = import.meta.env.VITE_API_URL?.trim();
    return base ? `${base.replace(/\/$/, '')}${path}` : path;
  }, []);

  // Fetch agents on mount
  useEffect(() => {
    fetch(getApiUrl('/api/swarm/agents'))
      .then(res => res.json())
      .then(data => {
        if (data.agents) setAgents(data.agents);
      })
      .catch(() => {})
      .finally(() => setLoadingAgents(false));
  }, [getApiUrl]);

  // Procedural 2D Cyber Threat Radar Animation
  useEffect(() => {
    const canvas = radarCanvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let angle = 0;
    let animId;

    const blips = [
      { r: 45, theta: 0.8, life: 1, label: '185.220.101.45 (C2)' },
      { r: 90, theta: 2.4, life: 0.8, label: 'APT29 Probe' },
      { r: 65, theta: 4.1, life: 0.6, label: 'Port Scan' },
      { r: 110, theta: 5.5, life: 0.9, label: 'Tor Exit Node' },
    ];

    const render = () => {
      const w = canvas.width;
      const h = canvas.height;
      const cx = w / 2;
      const cy = h / 2;
      const maxR = Math.min(cx, cy) - 10;

      ctx.clearRect(0, 0, w, h);

      // Radar concentric rings
      ctx.strokeStyle = 'rgba(0, 245, 212, 0.2)';
      ctx.lineWidth = 1;
      for (let r = maxR / 4; r <= maxR; r += maxR / 4) {
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Crosshairs
      ctx.beginPath();
      ctx.moveTo(cx - maxR, cy);
      ctx.lineTo(cx + maxR, cy);
      ctx.moveTo(cx, cy - maxR);
      ctx.lineTo(cx, cy + maxR);
      ctx.stroke();

      // Sweep line
      angle += 0.035;
      const sweepX = cx + Math.cos(angle) * maxR;
      const sweepY = cy + Math.sin(angle) * maxR;

      const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, maxR);
      grad.addColorStop(0, 'rgba(0, 245, 212, 0.25)');
      grad.addColorStop(1, 'rgba(0, 245, 212, 0.0)');

      ctx.save();
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, maxR, angle - 0.5, angle);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.restore();

      // Blips
      blips.forEach(b => {
        const bx = cx + Math.cos(b.theta) * b.r;
        const by = cy + Math.sin(b.theta) * b.r;
        ctx.beginPath();
        ctx.arc(bx, by, 4, 0, Math.PI * 2);
        ctx.fillStyle = '#ef4444';
        ctx.shadowColor = '#ef4444';
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;

        ctx.font = '9px JetBrains Mono, monospace';
        ctx.fillStyle = '#38bdf8';
        ctx.fillText(b.label, bx + 6, by - 4);
      });

      animId = requestAnimationFrame(render);
    };

    render();
    return () => cancelAnimationFrame(animId);
  }, []);

  const handleLaunchSwarm = async () => {
    cyberAudio.playWarp();
    setOrchestrating(true);
    setSwarmResult(null);

    try {
      const res = await fetch(getApiUrl('/api/swarm/orchestrate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: `Investigate active threat targeting ${targetHost} from IP ${targetIp}`,
          target_ip: targetIp,
          target_host: targetHost
        })
      });
      const data = await res.json();
      setSwarmResult(data);
      cyberAudio.playSuccess();
    } catch {
      cyberAudio.playAlert();
    } finally {
      setOrchestrating(false);
    }
  };

  const handleFetchStix = async () => {
    cyberAudio.playClick();
    try {
      const res = await fetch(getApiUrl(`/api/stix/export?ip=${targetIp}&technique=T1059.001`));
      const data = await res.json();
      setStixBundle(data);

      // Trigger download
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `STIX-2.1-Threat-Bundle-${targetIp}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      cyberAudio.playAlert();
    }
  };

  const handlePublishTaxii = async () => {
    cyberAudio.playWarp();
    try {
      const res = await fetch(getApiUrl('/api/stix/taxii/publish'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator_ip: targetIp })
      });
      const data = await res.json();
      setTaxiiToast(data.message);
      cyberAudio.playSuccess();
      setTimeout(() => setTaxiiToast(null), 5000);
    } catch {
      cyberAudio.playAlert();
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, paddingBottom: 40 }}>
      {/* Toast */}
      {taxiiToast && (
        <div style={{
          position: 'fixed',
          top: 24,
          right: 24,
          background: 'linear-gradient(135deg, rgba(16,185,129,0.95), rgba(5,150,105,0.95))',
          color: '#ffffff',
          padding: '12px 20px',
          borderRadius: 12,
          boxShadow: '0 8px 32px rgba(16,185,129,0.4)',
          zIndex: 9999,
          fontSize: '0.8rem',
          fontWeight: 700,
          animation: 'fadeIn 200ms ease'
        }}>
          ✓ {taxiiToast}
        </div>
      )}

      {/* Top Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(15,23,42,0.9), rgba(6,9,18,0.95))',
        border: '1px solid rgba(0, 245, 212, 0.3)',
        borderRadius: 16,
        padding: '24px 28px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: 16,
        boxShadow: '0 8px 32px rgba(0,0,0,0.4)'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: '1.8rem' }}>🤖</span>
            <div>
              <h1 style={{
                margin: 0,
                fontSize: '1.5rem',
                fontWeight: 900,
                background: 'linear-gradient(135deg, #00f5d4, #38bdf8, #8b5cf6)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                letterSpacing: '-0.02em'
              }}>
                Autonomous SOC Agent Swarm & STIX 2.1 Sharing Hub
              </h1>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: 4 }}>
                Multi-Agent Collaborative Intelligence • OASIS STIX 2.1 / TAXII 2.1 Threat Exchange • Real-Time C2 Interception
              </div>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            onClick={handleLaunchSwarm}
            disabled={orchestrating}
            style={{
              background: orchestrating
                ? 'rgba(0, 245, 212, 0.3)'
                : 'linear-gradient(135deg, #00f5d4, #06b6d4)',
              border: 'none',
              borderRadius: 12,
              color: '#02040a',
              padding: '10px 20px',
              fontWeight: 800,
              fontSize: '0.8rem',
              cursor: orchestrating ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              boxShadow: orchestrating ? 'none' : '0 0 20px rgba(0, 245, 212, 0.4)',
              transition: 'all 200ms ease'
            }}
          >
            {orchestrating ? '⏳' : '⚡'} {orchestrating ? 'Swarm Consensus in Progress…' : 'Trigger Swarm Consensus'}
          </button>

          <button
            onClick={handleFetchStix}
            style={{
              background: 'rgba(139, 92, 246, 0.18)',
              border: '1px solid rgba(139, 92, 246, 0.4)',
              borderRadius: 12,
              color: '#c4b5fd',
              padding: '10px 18px',
              fontWeight: 700,
              fontSize: '0.8rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6
            }}
          >
            <span>📄</span> Export STIX 2.1
          </button>

          <button
            onClick={handlePublishTaxii}
            style={{
              background: 'rgba(16, 185, 129, 0.18)',
              border: '1px solid rgba(16, 185, 129, 0.4)',
              borderRadius: 12,
              color: '#6ee7b7',
              padding: '10px 18px',
              fontWeight: 700,
              fontSize: '0.8rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6
            }}
          >
            <span>🌐</span> Publish to TAXII
          </button>
        </div>
      </div>

      {/* Grid: Agent Roster + Live Radar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 20 }}>
        {/* Left: Swarm Agent Ensemble */}
        <div style={{
          gridColumn: 'span 2',
          display: 'flex',
          flexDirection: 'column',
          gap: 14
        }}>
          <h2 style={{ margin: 0, fontSize: '1rem', fontWeight: 800, color: '#38bdf8', letterSpacing: '0.04em' }}>
            ACTIVE AUTONOMOUS SOC SPECIALISTS ({agents.length || 5})
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
            {(agents.length > 0 ? agents : [
              { name: 'Sentinel Alpha', role: 'Triage & Alert Deduplication', avatar: '🛡️', specialty: 'CVSS v3.1 / EPSS scoring', model: 'Claude-3.5' },
              { name: 'Hunter Beta', role: 'Host Forensics & Sysmon', avatar: '🔍', specialty: 'Process lineage & token theft', model: 'GPT-4o' },
              { name: 'Specter Gamma', role: 'Cyber Threat Intelligence', avatar: '🌐', specialty: 'VirusTotal & AbuseIPDB consensus', model: 'Gemini-1.5' },
              { name: 'Aegis Delta', role: 'Autonomous Active Defense', avatar: '⚡', specialty: 'SOAR containment & microsegmentation', model: 'Claude-3.5' },
              { name: 'Lexis Epsilon', role: 'GRC & Governance', avatar: '📜', specialty: 'NIST CSF 2.0 & ISO 27001 mapping', model: 'GPT-4o' },
            ]).map((ag, idx) => (
              <div key={idx} style={{
                background: 'rgba(10, 15, 30, 0.85)',
                border: '1px solid rgba(99, 102, 241, 0.25)',
                borderRadius: 14,
                padding: '16px',
                position: 'relative',
                overflow: 'hidden',
                transition: 'all 200ms ease'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                  <div style={{
                    width: 36,
                    height: 36,
                    borderRadius: 10,
                    background: 'rgba(99,102,241,0.2)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: 20
                  }}>
                    {ag.avatar}
                  </div>
                  <div>
                    <div style={{ fontSize: '0.85rem', fontWeight: 800, color: '#f8fafc' }}>{ag.name}</div>
                    <div style={{ fontSize: '0.65rem', color: '#00f5d4', fontWeight: 600 }}>{ag.role}</div>
                  </div>
                </div>

                <div style={{ fontSize: '0.7rem', color: '#94a3b8', lineHeight: 1.5, marginBottom: 8 }}>
                  {ag.specialty}
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.62rem', color: '#64748b' }}>
                  <span>Engine: {ag.model}</span>
                  <span style={{ color: '#10b981', fontWeight: 700 }}>● STANDBY</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Real-Time Cyber Threat Radar */}
        <div style={{
          background: 'rgba(10, 15, 30, 0.9)',
          border: '1px solid rgba(0, 245, 212, 0.3)',
          borderRadius: 16,
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          boxShadow: '0 8px 32px rgba(0,0,0,0.4)'
        }}>
          <div style={{ width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 800, color: '#00f5d4', letterSpacing: '0.06em' }}>
              GLOBAL THREAT RADAR
            </span>
            <span style={{ fontSize: '0.65rem', color: '#10b981', fontWeight: 700 }}>
              ● 360° SWEEP ACTIVE
            </span>
          </div>

          <canvas
            ref={radarCanvasRef}
            width={280}
            height={280}
            style={{ borderRadius: '50%', background: 'rgba(4, 7, 17, 0.95)', border: '1px solid rgba(0,245,212,0.2)' }}
          />

          <div style={{ width: '100%', marginTop: 14, display: 'flex', justifyContent: 'space-between', fontSize: '0.68rem', color: '#94a3b8' }}>
            <span>Target IP: <strong style={{ color: '#38bdf8' }}>{targetIp}</strong></span>
            <span>Target Host: <strong style={{ color: '#00f5d4' }}>{targetHost}</strong></span>
          </div>
        </div>
      </div>

      {/* Swarm Consensus Results (Live Display) */}
      {swarmResult && (
        <div style={{
          background: 'rgba(8, 12, 24, 0.95)',
          border: '1px solid rgba(0, 245, 212, 0.4)',
          borderRadius: 16,
          padding: '24px',
          boxShadow: '0 12px 48px rgba(0, 245, 212, 0.15)',
          animation: 'fadeIn 300ms ease'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
            <div>
              <div style={{ fontSize: '0.68rem', color: '#94a3b8', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                AUTONOMOUS CONSENSUS REPORT • ID: {swarmResult.orchestration_id}
              </div>
              <h3 style={{ margin: '4px 0 0', fontSize: '1.2rem', fontWeight: 900, color: '#f8fafc' }}>
                {swarmResult.swarm_verdict}
              </h3>
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <span style={{
                background: 'rgba(239, 68, 68, 0.2)',
                color: '#f87171',
                border: '1px solid rgba(239, 68, 68, 0.4)',
                padding: '4px 12px',
                borderRadius: 20,
                fontSize: '0.72rem',
                fontWeight: 800
              }}>
                SEVERITY: {swarmResult.consensus_severity}
              </span>
              <span style={{
                background: 'rgba(0, 245, 212, 0.2)',
                color: '#00f5d4',
                border: '1px solid rgba(0, 245, 212, 0.4)',
                padding: '4px 12px',
                borderRadius: 20,
                fontSize: '0.72rem',
                fontWeight: 800
              }}>
                THREAT SCORE: {swarmResult.overall_threat_score}/100
              </span>
            </div>
          </div>

          {/* Individual Agent Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12, marginBottom: 16 }}>
            {swarmResult.agent_findings?.map((f, idx) => (
              <div key={idx} style={{
                background: 'rgba(15, 23, 42, 0.7)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: 12,
                padding: '14px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <strong style={{ fontSize: '0.78rem', color: '#38bdf8' }}>{f.agent}</strong>
                  <span style={{ fontSize: '0.65rem', color: '#10b981', fontWeight: 700 }}>Confidence: {f.confidence}</span>
                </div>
                <div style={{ fontSize: '0.72rem', color: '#f1f5f9', fontWeight: 600, marginBottom: 4 }}>
                  {f.verdict}
                </div>
                <div style={{ fontSize: '0.68rem', color: '#94a3b8', lineHeight: 1.5, marginBottom: 8 }}>
                  {f.details}
                </div>
                <div style={{ fontSize: '0.65rem', color: '#fde047', background: 'rgba(234, 179, 8, 0.1)', padding: '4px 8px', borderRadius: 6 }}>
                  Action: {f.action_item}
                </div>
              </div>
            ))}
          </div>

          {/* Unified Action Plan */}
          <div style={{
            background: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            borderRadius: 12,
            padding: '14px 18px'
          }}>
            <div style={{ fontSize: '0.72rem', fontWeight: 800, color: '#34d399', marginBottom: 8 }}>
              ⚡ CONSENSUS REMEDIATION DIRECTIVES:
            </div>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              {swarmResult.consensus_actions?.map((act, idx) => (
                <div key={idx} style={{
                  background: 'rgba(0,0,0,0.4)',
                  padding: '6px 12px',
                  borderRadius: 8,
                  fontSize: '0.72rem',
                  color: '#e2e8f0',
                  border: '1px solid rgba(16,185,129,0.2)'
                }}>
                  {act}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SwarmHub;
