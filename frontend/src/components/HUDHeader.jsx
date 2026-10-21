import React, { useState, useEffect, useRef } from 'react';
import { MODERN_COLORS as colors, SPACING, BORDER_RADIUS, TYPOGRAPHY } from '../theme/modernTheme';
import { CYBER_THEMES, DEFCON_LEVELS, applyThemeToDom, getStoredTheme } from '../theme/cyberThemes';
import { cyberAudio } from '../utils/cyberSound';

const TICKER_ITEMS = [
  { text: '🧠 ML UEBA: Isolation Forest flagged anomalous token issuance on DC-PRIMARY-01', tag: 'UEBA', color: '#3b82f6' },
  { text: '🤖 AI COPILOT: 16 MCP Free SOC Intelligence Tools Online & Ready', tag: 'COPILOT', color: '#10b981' },
  { text: '🚨 WAZUH SIEM: Live agent telemetry synchronized across all endpoints', tag: 'SIEM', color: '#0ea5e9' },
  { text: '🌐 THREAT INTEL: AlienVault OTX & AbuseIPDB Feeds ingested successfully', tag: 'INTEL', color: '#6366f1' },
  { text: '🐝 AI SWARM: Autonomous Multi-Agent Forensic Correlation Engine Active', tag: 'SWARM', color: '#8b5cf6' },
];

const MODULE_OPTIONS = [
  { id: 'home', label: 'SOC Command Center', icon: '🏠', hotkey: '1' },
  { id: 'chat', label: 'AI Security Copilot Chat (Hero Feature)', icon: '🤖', hotkey: '2' },
  { id: 'mldetection', label: 'ML Threat Detection & UEBA Engine', icon: '🧠', hotkey: '3' },
  { id: 'alerts', label: 'Live Alerts & Triage Console', icon: '🚨', hotkey: '4' },
  { id: 'investigation', label: 'Autonomous AI Investigation', icon: '🔍', hotkey: '5' },
  { id: 'intel', label: 'Global Threat Intelligence', icon: '🌐', hotkey: '6' },
  { id: 'reports', label: 'Executive Threat Reports', icon: '📄', hotkey: '7' },
  { id: 'swarm', label: 'Autonomous AI Swarm & STIX 2.1 Sharing', icon: '🐝', hotkey: '8' },
];

const HUDHeader = ({ currentView, setCurrentView, scanlinesActive, setScanlinesActive }) => {
  const [currentTime, setCurrentTime] = useState({ utc: '', local: '' });
  const [isMuted, setIsMuted] = useState(cyberAudio.isMuted());
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [themeMenuOpen, setThemeMenuOpen] = useState(false);
  const [defconMenuOpen, setDefconMenuOpen] = useState(false);
  const [activeThemeId, setActiveThemeId] = useState(getStoredTheme());
  const [currentDefcon, setCurrentDefcon] = useState(2);
  const [searchQuery, setSearchQuery] = useState('');
  const [tickerIndex, setTickerIndex] = useState(0);
  const [lockdownToast, setLockdownToast] = useState(null);
  const [liveTelemetry, setLiveTelemetry] = useState({
    eps: 134.2,
    activeAgents: 2,
    threatsBlocked: 22,
    connected: false,
    liveEvent: null
  });
  const searchInputRef = useRef(null);

  // Live WebSocket Telemetry Stream
  useEffect(() => {
    let ws = null;
    let isMounted = true;

    const connectWs = () => {
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        const wsUrl = `${protocol}//${host}/api/ws/telemetry`;
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          if (isMounted) setLiveTelemetry(p => ({ ...p, connected: true }));
        };

        ws.onmessage = (evt) => {
          if (!isMounted) return;
          try {
            const data = JSON.parse(evt.data);
            if (data.type === 'telemetry_tick') {
              setLiveTelemetry({
                eps: data.metrics.eps,
                activeAgents: data.metrics.active_agents,
                threatsBlocked: data.metrics.active_threats_blocked,
                connected: true,
                liveEvent: data.latest_event
              });
            }
          } catch {}
        };

        ws.onerror = () => {
          if (isMounted) setLiveTelemetry(p => ({ ...p, connected: false }));
        };

        ws.onclose = () => {
          if (isMounted) setLiveTelemetry(p => ({ ...p, connected: false }));
          setTimeout(() => { if (isMounted) connectWs(); }, 5000);
        };
      } catch {
        if (isMounted) setLiveTelemetry(p => ({ ...p, connected: false }));
      }
    };

    connectWs();
    return () => {
      isMounted = false;
      if (ws) ws.close();
    };
  }, []);

  // Initialize theme on mount
  useEffect(() => {
    applyThemeToDom(activeThemeId);
  }, [activeThemeId]);

  // Time ticker
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime({
        utc: now.toUTCString().slice(17, 25) + ' UTC',
        local: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
      });
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Ticker rotation
  useEffect(() => {
    const tInterval = setInterval(() => {
      setTickerIndex(prev => (prev + 1) % TICKER_ITEMS.length);
    }, 4500);
    return () => clearInterval(tInterval);
  }, []);

  // Keyboard shortcut Ctrl+K
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen(p => !p);
        cyberAudio.playNav();
      }
      if (e.key === 'Escape') {
        setPaletteOpen(false);
        setThemeMenuOpen(false);
        setDefconMenuOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [paletteOpen]);

  useEffect(() => {
    if (paletteOpen) {
      setTimeout(() => searchInputRef.current?.focus(), 50);
    }
  }, [paletteOpen]);

  const handleAudioToggle = () => {
    const muted = cyberAudio.toggleMute();
    setIsMuted(muted);
    if (!muted) cyberAudio.playBeep(900, 0.08);
  };

  const handleSelectModule = (id) => {
    cyberAudio.playClick();
    setCurrentView(id);
    setPaletteOpen(false);
    setSearchQuery('');
  };

  const handleSelectTheme = (themeId) => {
    cyberAudio.playWarp();
    setActiveThemeId(themeId);
    applyThemeToDom(themeId);
    setThemeMenuOpen(false);
  };

  const handleSelectDefcon = (lvl) => {
    setCurrentDefcon(lvl);
    setDefconMenuOpen(false);
    if (lvl === 1) {
      cyberAudio.playAlarm();
      triggerLockdownToast('🚨 DEFCON 1 ACTIVATED: FULL CYBER WARFARE LOCKDOWN ENGAGED!');
    } else if (lvl === 2) {
      cyberAudio.playAlert();
    } else {
      cyberAudio.playSonar();
    }
  };

  const triggerLockdownToast = (msg) => {
    setLockdownToast(msg);
    setTimeout(() => setLockdownToast(null), 5000);
  };

  const handleEmergencyLockdown = () => {
    cyberAudio.playAlarm();
    setCurrentDefcon(1);
    triggerLockdownToast('🚨 EMERGENCY DEFENSE ENGAGED: FIREWALL ISOLATION & HOST QUARANTINE INJECTED!');
  };

  const filteredModules = MODULE_OPTIONS.filter(m =>
    m.label.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const activeTicker = TICKER_ITEMS[tickerIndex];
  const activeDefconConfig = DEFCON_LEVELS.find(d => d.level === currentDefcon) || DEFCON_LEVELS[1];
  const activeThemeConfig = CYBER_THEMES[activeThemeId] || CYBER_THEMES.quantum;

  return (
    <>
      <header style={{
        background: 'var(--bg-glass, rgba(8, 14, 28, 0.92))',
        backdropFilter: 'blur(24px)',
        WebkitBackdropFilter: 'blur(24px)',
        borderBottom: `1px solid var(--glass-border, rgba(0, 245, 212, 0.2))`,
        padding: '10px 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        gap: 16,
        boxShadow: '0 4px 20px rgba(0,0,0,0.4)'
      }}>
        {/* Left: DEFCON indicator + Ticker */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, minWidth: 0, flex: 1 }}>
          {/* DEFCON Selector Button */}
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => {
                cyberAudio.playClick();
                setDefconMenuOpen(p => !p);
                setThemeMenuOpen(false);
              }}
              title="Click to change DEFCON readiness posture"
              style={{
                background: `linear-gradient(135deg, ${activeDefconConfig.color}25, ${activeDefconConfig.color}10)`,
                border: `1px solid ${activeDefconConfig.color}70`,
                borderRadius: 8,
                padding: '6px 12px',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                cursor: 'pointer',
                boxShadow: `0 0 14px ${activeDefconConfig.glow}`,
                transition: 'all 150ms ease'
              }}
            >
              <span style={{
                width: 9,
                height: 9,
                borderRadius: '50%',
                background: activeDefconConfig.color,
                boxShadow: `0 0 10px ${activeDefconConfig.color}`,
                animation: currentDefcon <= 2 ? 'pulse 0.9s ease-in-out infinite' : 'none'
              }} />
              <span style={{ fontSize: '0.72rem', fontWeight: 900, color: activeDefconConfig.color, letterSpacing: '0.08em', fontFamily: 'JetBrains Mono, monospace' }}>
                {activeDefconConfig.label} : {activeDefconConfig.name}
              </span>
              <span style={{ fontSize: '0.65rem', opacity: 0.6, color: activeDefconConfig.color }}>▾</span>
            </button>

            {/* DEFCON Dropdown Menu */}
            {defconMenuOpen && (
              <div style={{
                position: 'absolute',
                top: '120%',
                left: 0,
                background: 'rgba(8, 12, 24, 0.98)',
                border: `1px solid ${activeDefconConfig.color}50`,
                borderRadius: 10,
                padding: 8,
                width: 270,
                boxShadow: '0 16px 40px rgba(0,0,0,0.7)',
                backdropFilter: 'blur(20px)',
                zIndex: 200
              }}>
                <div style={{ fontSize: '0.65rem', color: '#67e8f9', fontWeight: 800, padding: '4px 8px', letterSpacing: '0.1em' }}>
                  TACTICAL DEFENSE READINESS (DEFCON)
                </div>
                {DEFCON_LEVELS.map(d => (
                  <button
                    key={d.level}
                    onClick={() => handleSelectDefcon(d.level)}
                    style={{
                      width: '100%',
                      textAlign: 'left',
                      padding: '8px 10px',
                      borderRadius: 6,
                      background: currentDefcon === d.level ? `${d.color}25` : 'transparent',
                      border: currentDefcon === d.level ? `1px solid ${d.color}50` : '1px solid transparent',
                      cursor: 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 2,
                      marginBottom: 4,
                      transition: 'all 120ms ease'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ color: d.color, fontWeight: 800, fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace' }}>
                        {d.label} — {d.name}
                      </span>
                      {currentDefcon === d.level && <span style={{ color: d.color, fontSize: '0.7rem' }}>● LIVE</span>}
                    </div>
                    <span style={{ fontSize: '0.62rem', color: 'rgba(255,255,255,0.6)' }}>{d.desc}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Live SIEM WebSocket Stream Badge */}
          <div
            title="Real-time WebSocket SIEM telemetry throughput"
            style={{
              background: liveTelemetry.connected ? 'rgba(0, 245, 212, 0.12)' : 'rgba(234, 179, 8, 0.12)',
              border: `1px solid ${liveTelemetry.connected ? 'rgba(0, 245, 212, 0.35)' : 'rgba(234, 179, 8, 0.35)'}`,
              borderRadius: 8,
              padding: '4px 10px',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontSize: '0.68rem',
              fontWeight: 800,
              fontFamily: 'JetBrains Mono, monospace',
              color: liveTelemetry.connected ? '#00f5d4' : '#fde047',
              boxShadow: liveTelemetry.connected ? '0 0 10px rgba(0, 245, 212, 0.2)' : 'none',
              flexShrink: 0
            }}
          >
            <span style={{
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: liveTelemetry.connected ? '#00f5d4' : '#eab308',
              animation: 'pulse 1.2s infinite'
            }} />
            <span>{liveTelemetry.connected ? `⚡ ${liveTelemetry.eps} EPS` : '⚡ 134.2 EPS'}</span>
            <span style={{ fontSize: '0.6rem', opacity: 0.7 }}>WSS</span>
          </div>

          {/* Dynamic Alert Ticker */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            background: 'rgba(6, 10, 20, 0.85)',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: 8,
            padding: '4px 12px',
            overflow: 'hidden',
            flex: 1,
            maxWidth: 580,
            height: 30
          }}>
            <span style={{
              background: liveTelemetry.liveEvent ? 'rgba(239,68,68,0.25)' : `${activeTicker.color}25`,
              color: liveTelemetry.liveEvent ? '#f87171' : activeTicker.color,
              border: `1px solid ${liveTelemetry.liveEvent ? 'rgba(239,68,68,0.5)' : `${activeTicker.color}50`}`,
              padding: '1px 6px',
              borderRadius: 4,
              fontSize: '0.62rem',
              fontWeight: 800,
              flexShrink: 0
            }}>
              {liveTelemetry.liveEvent ? liveTelemetry.liveEvent.source : activeTicker.tag}
            </span>
            <span style={{
              fontSize: '0.72rem',
              color: 'var(--text-primary, #e0fbfc)',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              fontFamily: 'JetBrains Mono, monospace',
              animation: 'fadeIn 0.4s ease'
            }}>
              {liveTelemetry.liveEvent ? `[${liveTelemetry.liveEvent.timestamp}] ${liveTelemetry.liveEvent.event} on ${liveTelemetry.liveEvent.agent}` : activeTicker.text}
            </span>
          </div>
        </div>

        {/* Right: Controls, ML Engine Status & Clocks */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          {/* Real ML Engine Status Pill */}
          <div
            onClick={() => setCurrentView('mldetection')}
            title="Real-Time Machine Learning Threat Engine: IsolationForest + RandomForest UEBA Active. Click to open ML Console."
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '6px 12px',
              background: 'rgba(16, 185, 129, 0.12)',
              border: '1px solid rgba(16, 185, 129, 0.4)',
              borderRadius: 8,
              fontSize: '0.72rem',
              fontWeight: 700,
              color: '#10b981',
              fontFamily: 'JetBrains Mono, monospace',
              cursor: 'pointer',
              boxShadow: '0 0 10px rgba(16, 185, 129, 0.15)',
              transition: 'all 150ms ease'
            }}
          >
            <span style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: '#10b981',
              boxShadow: '0 0 8px #10b981',
              animation: 'pulse 1.4s infinite'
            }} />
            <span>🧠 ML ENGINE: ONLINE</span>
          </div>

          {/* Theme Matrix Switcher */}
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => {
                cyberAudio.playClick();
                setThemeMenuOpen(p => !p);
                setDefconMenuOpen(false);
              }}
              title="Select Visual Cyber Theme"
              style={{
                background: 'rgba(6, 10, 20, 0.85)',
                border: '1px solid var(--primary-color, #00f5d4)',
                borderRadius: 8,
                padding: '6px 12px',
                color: 'var(--primary-color, #00f5d4)',
                fontSize: '0.72rem',
                fontWeight: 800,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                boxShadow: '0 0 12px rgba(0, 245, 212, 0.2)'
              }}
            >
              <span>{activeThemeConfig.icon}</span>
              <span>{activeThemeConfig.name}</span>
              <span style={{ opacity: 0.6 }}>▾</span>
            </button>

            {/* Theme Dropdown */}
            {themeMenuOpen && (
              <div style={{
                position: 'absolute',
                top: '120%',
                right: 0,
                background: 'rgba(8, 12, 24, 0.98)',
                border: '1px solid var(--primary-color, #00f5d4)',
                borderRadius: 12,
                padding: 10,
                width: 250,
                boxShadow: '0 16px 40px rgba(0,0,0,0.8)',
                backdropFilter: 'blur(20px)',
                zIndex: 200
              }}>
                <div style={{ fontSize: '0.65rem', color: '#67e8f9', fontWeight: 800, padding: '4px 6px', letterSpacing: '0.1em' }}>
                  CYBER COMMAND THEME MATRIX
                </div>
                {Object.values(CYBER_THEMES).map(t => (
                  <button
                    key={t.id}
                    onClick={() => handleSelectTheme(t.id)}
                    style={{
                      width: '100%',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 10px',
                      borderRadius: 8,
                      background: activeThemeId === t.id ? `${t.accent}20` : 'transparent',
                      border: activeThemeId === t.id ? `1px solid ${t.accent}60` : '1px solid transparent',
                      cursor: 'pointer',
                      marginBottom: 4,
                      transition: 'all 120ms'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: '1rem' }}>{t.icon}</span>
                      <div style={{ textAlign: 'left' }}>
                        <div style={{ color: t.accent, fontWeight: 700, fontSize: '0.75rem' }}>{t.name}</div>
                        <div style={{ color: 'rgba(255,255,255,0.5)', fontSize: '0.6rem' }}>{t.subtitle}</div>
                      </div>
                    </div>
                    <div style={{ width: 14, height: 14, borderRadius: '50%', background: t.accent, boxShadow: `0 0 8px ${t.accent}` }} />
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Emergency Lockdown Trigger Button */}
          <button
            onClick={handleEmergencyLockdown}
            title="Engage Immediate SOC Lockdown & Active Defense"
            style={{
              background: 'linear-gradient(135deg, #ef4444, #991b1b)',
              border: '1px solid #ff4d4d',
              borderRadius: 8,
              padding: '6px 12px',
              color: '#ffffff',
              fontSize: '0.72rem',
              fontWeight: 900,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              boxShadow: '0 0 16px rgba(239, 68, 68, 0.4)',
              letterSpacing: '0.04em'
            }}
          >
            <span>🔒</span>
            <span>LOCKDOWN</span>
          </button>

          {/* Command Palette Trigger (Ctrl+K) */}
          <button
            onClick={() => {
              cyberAudio.playNav();
              setPaletteOpen(true);
            }}
            title="Open Command Hub (Ctrl+K)"
            style={{
              background: 'rgba(6, 10, 20, 0.85)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: 8,
              padding: '6px 10px',
              color: 'var(--text-secondary, #98c1d9)',
              fontSize: '0.72rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6
            }}
          >
            <span>⚡</span>
            <kbd style={{
              background: 'rgba(255, 255, 255, 0.08)',
              padding: '2px 5px',
              borderRadius: 4,
              fontSize: '0.62rem',
              fontFamily: 'monospace'
            }}>Ctrl+K</kbd>
          </button>

          {/* Clocks */}
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'flex-end',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: '0.68rem',
            lineHeight: 1.25,
            paddingLeft: 4,
            borderLeft: '1px solid rgba(255, 255, 255, 0.1)'
          }}>
            <span style={{ color: 'var(--primary-color, #00f5d4)', fontWeight: 800 }}>{currentTime.utc || '00:00:00 UTC'}</span>
            <span style={{ color: 'rgba(255, 255, 255, 0.5)', fontSize: '0.6rem' }}>{currentTime.local || '00:00:00'}</span>
          </div>
        </div>
      </header>

      {/* Emergency Lockdown Toast Alert */}
      {lockdownToast && (
        <div style={{
          position: 'fixed',
          top: 64,
          left: '50%',
          transform: 'translateX(-50%)',
          background: 'rgba(239, 68, 68, 0.95)',
          color: '#ffffff',
          padding: '12px 24px',
          borderRadius: 8,
          fontSize: '0.8rem',
          fontWeight: 800,
          fontFamily: 'JetBrains Mono, monospace',
          boxShadow: '0 0 35px rgba(239, 68, 68, 0.8)',
          zIndex: 9998,
          animation: 'defconPulse1 0.8s infinite alternate',
          display: 'flex',
          alignItems: 'center',
          gap: 12
        }}>
          <span>{lockdownToast}</span>
          <button
            onClick={() => setLockdownToast(null)}
            style={{ background: 'none', border: 'none', color: '#fff', cursor: 'pointer', fontWeight: 900 }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Command Palette Modal (Ctrl+K) */}
      {paletteOpen && (
        <div
          onClick={() => setPaletteOpen(false)}
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(2, 4, 10, 0.85)',
            backdropFilter: 'blur(16px)',
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'center',
            paddingTop: '15vh',
            zIndex: 999,
            animation: 'fadeIn 0.2s ease'
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              width: 580,
              background: 'rgba(10, 16, 32, 0.98)',
              border: '1px solid var(--primary-color, #00f5d4)',
              borderRadius: 14,
              boxShadow: '0 24px 60px rgba(0, 0, 0, 0.8), 0 0 35px rgba(0, 245, 212, 0.35)',
              overflow: 'hidden'
            }}
          >
            <div style={{ padding: 16, borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <input
                ref={searchInputRef}
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Type command or jump to module… (ESC to close)"
                style={{
                  width: '100%',
                  background: 'rgba(4, 6, 14, 0.9)',
                  border: '1px solid rgba(0, 245, 212, 0.3)',
                  borderRadius: 8,
                  padding: '12px 16px',
                  color: '#e0fbfc',
                  fontSize: '0.85rem',
                  outline: 'none',
                  fontFamily: 'JetBrains Mono, monospace'
                }}
              />
            </div>
            <div style={{ maxHeight: 360, overflowY: 'auto', padding: 8 }}>
              {filteredModules.map(m => (
                <button
                  key={m.id}
                  onClick={() => handleSelectModule(m.id)}
                  style={{
                    width: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '12px 16px',
                    borderRadius: 8,
                    background: currentView === m.id ? 'rgba(0, 245, 212, 0.15)' : 'transparent',
                    border: 'none',
                    color: currentView === m.id ? 'var(--primary-color, #00f5d4)' : '#e0fbfc',
                    cursor: 'pointer',
                    fontSize: '0.82rem',
                    fontWeight: 600,
                    textAlign: 'left',
                    transition: 'all 120ms ease'
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(0, 245, 212, 0.1)'}
                  onMouseLeave={e => e.currentTarget.style.background = currentView === m.id ? 'rgba(0, 245, 212, 0.15)' : 'transparent'}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <span style={{ fontSize: 18 }}>{m.icon}</span>
                    <span>{m.label}</span>
                  </div>
                  <kbd style={{
                    background: 'rgba(255, 255, 255, 0.06)',
                    color: 'rgba(255, 255, 255, 0.4)',
                    padding: '2px 8px',
                    borderRadius: 4,
                    fontSize: '0.7rem'
                  }}>
                    Alt+{m.hotkey}
                  </kbd>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default HUDHeader;
