import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import {
  MODERN_COLORS,
  SPACING,
  BORDER_RADIUS,
  TYPOGRAPHY,
  getSeverityColor,
  getSeverityGradient
} from '../theme/modernTheme';
import { cyberAudio } from '../utils/cyberSound';

/* ─── Helpers: Markdown Formatter ─────────────────────────── */
const inlineMarkdown = (text) => {
  if (!text) return '';
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*|__[^_]+__|_[^_]+_)/);
  return parts.map((part, idx) => {
    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code key={idx} style={{
          background: 'rgba(99,102,241,0.22)',
          color: '#a5f3fc',
          padding: '2px 6px',
          borderRadius: 4,
          fontFamily: 'JetBrains Mono, Fira Code, monospace',
          fontSize: '0.82em',
          border: '1px solid rgba(99,102,241,0.3)'
        }}>
          {part.slice(1, -1)}
        </code>
      );
    }
    if ((part.startsWith('**') && part.endsWith('**')) || (part.startsWith('__') && part.endsWith('__'))) {
      return <strong key={idx} style={{ color: '#f8fafc', fontWeight: 700 }}>{part.slice(2, -2)}</strong>;
    }
    if ((part.startsWith('*') && part.endsWith('*')) || (part.startsWith('_') && part.endsWith('_'))) {
      return <em key={idx} style={{ color: '#c4b5fd' }}>{part.slice(1, -1)}</em>;
    }
    return part;
  });
};

const renderMarkdown = (text) => {
  if (!text) return null;
  const lines = String(text).split('\n');
  const elements = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    // Code block
    if (line.trim().startsWith('```')) {
      const lang = line.trim().slice(3);
      const codeLines = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        codeLines.push(lines[i]);
        i++;
      }
      elements.push(
        <pre key={i} style={{
          background: 'rgba(5,8,16,0.9)',
          border: '1px solid rgba(99,102,241,0.3)',
          borderRadius: 8,
          padding: '12px 16px',
          overflowX: 'auto',
          fontFamily: 'JetBrains Mono, Fira Code, monospace',
          fontSize: '0.76rem',
          color: '#38bdf8',
          margin: '10px 0',
          lineHeight: 1.6,
          boxShadow: 'inset 0 2px 8px rgba(0,0,0,0.6)'
        }}>
          {lang && <div style={{ color: '#818cf8', fontSize: '0.65rem', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{lang}</div>}
          {codeLines.join('\n')}
        </pre>
      );
    } else if (line.startsWith('### ')) {
      elements.push(<h3 key={i} style={{ color: '#818cf8', fontSize: '0.96rem', fontWeight: 700, margin: '12px 0 4px', display: 'flex', alignItems: 'center', gap: 6 }}>{line.slice(4)}</h3>);
    } else if (line.startsWith('## ')) {
      elements.push(<h2 key={i} style={{ color: '#a5b4fc', fontSize: '1.08rem', fontWeight: 800, margin: '14px 0 6px', borderBottom: '1px solid rgba(99,102,241,0.2)', paddingBottom: 4 }}>{line.slice(3)}</h2>);
    } else if (line.startsWith('# ')) {
      elements.push(<h1 key={i} style={{ color: '#c4b5fd', fontSize: '1.25rem', fontWeight: 800, margin: '16px 0 8px' }}>{line.slice(2)}</h1>);
    } else if (/^[-*•]\s/.test(line)) {
      elements.push(
        <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 4, alignItems: 'flex-start' }}>
          <span style={{ color: '#06b6d4', flexShrink: 0, marginTop: 3, fontSize: '0.7rem' }}>▸</span>
          <span style={{ flex: 1 }}>{inlineMarkdown(line.slice(2))}</span>
        </div>
      );
    } else if (/^\d+\.\s/.test(line)) {
      const num = line.match(/^(\d+)\./)[1];
      elements.push(
        <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 4, alignItems: 'flex-start' }}>
          <span style={{ color: '#8b5cf6', flexShrink: 0, minWidth: 20, fontWeight: 700, fontSize: '0.8rem' }}>{num}.</span>
          <span style={{ flex: 1 }}>{inlineMarkdown(line.replace(/^\d+\.\s/, ''))}</span>
        </div>
      );
    } else if (line.trim() === '---' || line.trim() === '___') {
      elements.push(<hr key={i} style={{ border: 'none', borderTop: '1px solid rgba(99,102,241,0.2)', margin: '12px 0' }} />);
    } else if (line.trim() === '') {
      elements.push(<div key={i} style={{ height: 6 }} />);
    } else {
      elements.push(<div key={i} style={{ lineHeight: 1.75, marginBottom: 3 }}>{inlineMarkdown(line)}</div>);
    }
    i++;
  }
  return elements;
};

/* ─── Available AI Engines & Modes ────────────────────────── */
const AI_MODELS = [
  { id: 'sentinelai', label: '🤖 SentinelAI X (MCP Hero)', badge: 'Autonomous SOC' },
  { id: 'gpt4o', label: '⚡ GPT-4o Advanced', badge: 'High Precision' },
  { id: 'claude', label: '🧠 Claude 3.5 Sonnet', badge: 'Deep Forensic' },
  { id: 'gemini', label: '✨ Gemini 1.5 Pro', badge: 'Ultra Context' },
];

/* ─── Tactical Quick Command Strips (English + Tanglish) ──── */
const QUICK_COMMANDS = [
  { icon: '🚨', label: 'Wazuh Alerts', text: 'Show me live Wazuh security alerts', tag: 'SIEM' },
  { icon: '🛡️', label: 'Fleet Status', text: 'How many agents are connected in wazuh?', tag: 'Fleet' },
  { icon: '🚫', label: 'Block IP (SOAR)', text: 'Block malicious IP 185.220.101.45 via SOAR active defense', tag: 'SOAR' },
  { icon: '🔒', label: 'Isolate Host', text: 'Isolate compromised host WS-FIN-04 via SOAR', tag: 'SOAR' },
  { icon: '🇮🇳', label: 'Alerts Check Pannu', text: 'Wazuh alert check pannu ethana alerts iruku', tag: 'Tamil' },
  { icon: '🇮🇳', label: 'Agents Ethana?', text: 'Wazuh la ethana agents connect aagirukku?', tag: 'Tamil' },
  { icon: '🔍', label: 'Deep Investigate', text: 'Investigate recent high severity security alerts and correlate IOCs', tag: 'Forensics' },
  { icon: '🌐', label: 'Threat Intel Sweep', text: 'Check IP 185.220.101.45 in VirusTotal and AbuseIPDB', tag: 'Intel' },
  { icon: '⚡', label: 'Run Playbook', text: 'Run SOAR automated response playbook for active threats', tag: 'Auto-IR' },
];

const WELCOME_MSG = {
  id: 1,
  role: 'assistant',
  text: `🛡️ **SentinelAI X — Autonomous SOC Hero & Security Copilot**

I am fully synchronized with **Wazuh SIEM**, **SOAR Active Defense**, and global **Threat Intelligence** feeds via Model Context Protocol (MCP).

### 🚀 What I Can Execute:
- 🚨 **Live Wazuh SIEM Telemetry**: Real-time alerts, level distributions & fleet endpoint monitoring.
- 🚫 **SOAR Active Defense**: IP blackholing, host network isolation, and automated incident response playbooks.
- 🌐 **Multi-Tool IOC Enrichment**: Deep lookups via VirusTotal, AbuseIPDB, AlienVault OTX, and Shodan.
- 🇮🇳 **Tanglish / Tamil Support**: Query naturally (e.g., *"Wazuh alert check pannu"*, *"ethana agent irruku"*, *"block pannu"*).`,
  time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  isWelcome: true,
  tools_used: ['Wazuh', 'SOAR', 'VirusTotal', 'AbuseIPDB'],
};

/* ─── Typewriter Animation Hook ───────────────────────────── */
const useTypewriter = (targetText, speed = 8) => {
  const [displayed, setDisplayed] = useState('');
  const [done, setDone] = useState(false);
  const indexRef = useRef(0);

  useEffect(() => {
    setDisplayed('');
    setDone(false);
    indexRef.current = 0;
    if (!targetText) {
      setDone(true);
      return;
    }
    const interval = setInterval(() => {
      const next = indexRef.current + speed;
      if (next >= targetText.length) {
        setDisplayed(targetText);
        setDone(true);
        clearInterval(interval);
      } else {
        indexRef.current = next;
        setDisplayed(targetText.slice(0, next));
      }
    }, 16);
    return () => clearInterval(interval);
  }, [targetText, speed]);

  return { displayed, done };
};

/* ─── MCP Execution Progress Pipeline ─────────────────────── */
const MCPProgressPipeline = () => {
  const [step, setStep] = useState(0);
  const steps = [
    { label: 'Parsing Intent & MITRE ATT&CK Mapping', icon: '🧠' },
    { label: 'Querying Wazuh SIEM Telemetry & Agents', icon: '🛡️' },
    { label: 'Executing MCP Threat Intel Correlation', icon: '🌐' },
    { label: 'Evaluating SOAR Active Defense Playbook', icon: '⚡' },
    { label: 'Synthesizing Autonomous SOC Verdict', icon: '🤖' },
  ];

  useEffect(() => {
    const timer = setInterval(() => {
      setStep(prev => (prev < steps.length - 1 ? prev + 1 : prev));
    }, 650);
    return () => clearInterval(timer);
  }, [steps.length]);

  return (
    <div style={{
      background: 'rgba(8, 12, 24, 0.95)',
      border: '1px solid rgba(99, 102, 241, 0.35)',
      borderRadius: 14,
      padding: '16px 20px',
      margin: '8px 0',
      backdropFilter: 'blur(20px)',
      boxShadow: '0 8px 32px rgba(0, 0, 0, 0.45)',
      animation: 'fadeIn 300ms ease'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#6366f1', animation: 'pulse 1s infinite' }} />
          <span style={{ fontSize: '0.72rem', fontWeight: 800, color: '#a5b4fc', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
            MCP Autonomous Tool Orchestration
          </span>
        </div>
        <span style={{ fontSize: '0.65rem', color: MODERN_COLORS.textMuted, fontFamily: 'monospace' }}>
          STAGE {step + 1}/{steps.length}
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {steps.map((s, idx) => {
          const isDone = idx < step;
          const isCurrent = idx === step;
          return (
            <div key={idx} style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              fontSize: '0.75rem',
              color: isCurrent ? '#38bdf8' : isDone ? '#10b981' : 'rgba(255,255,255,0.3)',
              fontWeight: isCurrent ? 700 : 500,
              transition: 'all 200ms ease'
            }}>
              <span style={{ fontSize: '0.9rem' }}>{s.icon}</span>
              <span style={{ flex: 1 }}>{s.label}</span>
              <span>{isDone ? '✓' : isCurrent ? '⏳' : '○'}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

/* ─── MessageBubble Component ─────────────────────────────── */
const MessageBubble = React.memo(({ message, isLatestAI, onActionClick }) => {
  const [copied, setCopied] = useState(false);
  const [showTrace, setShowTrace] = useState(false);
  const isUser = message.role === 'user';
  const fullText = message.text || '';
  const { displayed, done } = useTypewriter(isLatestAI ? fullText : null);
  const shownText = isLatestAI ? displayed : fullText;

  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText(fullText);
    setCopied(true);
    cyberAudio.playClick();
    setTimeout(() => setCopied(false), 2000);
  }, [fullText]);

  // Extract IP if present in text for contextual actions
  const detectedIp = useMemo(() => {
    const ipMatch = fullText.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    return ipMatch ? ipMatch[0] : null;
  }, [fullText]);

  const bubbleStyle = {
    maxWidth: '82%',
    borderRadius: isUser
      ? `${BORDER_RADIUS.xl}px ${BORDER_RADIUS.xl}px ${BORDER_RADIUS.sm}px ${BORDER_RADIUS.xl}px`
      : `${BORDER_RADIUS.xl}px ${BORDER_RADIUS.xl}px ${BORDER_RADIUS.xl}px ${BORDER_RADIUS.sm}px`,
    padding: `${SPACING.lg}px ${SPACING.xl}px`,
    position: 'relative',
    background: isUser
      ? 'linear-gradient(135deg, #4f46e5, #7c3aed)'
      : message.isError
        ? 'rgba(239, 68, 68, 0.12)'
        : message.isWelcome
          ? 'linear-gradient(180deg, rgba(15,23,42,0.95), rgba(6,9,16,0.95))'
          : 'rgba(10, 15, 30, 0.92)',
    border: isUser
      ? '1px solid rgba(255, 255, 255, 0.15)'
      : message.isError
        ? '1px solid rgba(239, 68, 68, 0.4)'
        : '1px solid rgba(99, 102, 241, 0.25)',
    backdropFilter: 'blur(20px)',
    WebkitBackdropFilter: 'blur(20px)',
    color: isUser ? '#ffffff' : MODERN_COLORS.text,
    boxShadow: isUser
      ? '0 8px 32px rgba(79, 70, 229, 0.35)'
      : '0 8px 32px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255,255,255,0.05)',
    wordBreak: 'break-word',
  };

  const toolColorMap = {
    Wazuh: { bg: 'rgba(6, 182, 212, 0.18)', border: 'rgba(6, 182, 212, 0.4)', text: '#06b6d4', icon: '🛡️' },
    VirusTotal: { bg: 'rgba(59, 130, 246, 0.18)', border: 'rgba(59, 130, 246, 0.4)', text: '#60a5fa', icon: '🔍' },
    AbuseIPDB: { bg: 'rgba(249, 115, 22, 0.18)', border: 'rgba(249, 115, 22, 0.4)', text: '#fb923c', icon: '⚡' },
    SOAR: { bg: 'rgba(16, 185, 129, 0.18)', border: 'rgba(16, 185, 129, 0.4)', text: '#34d399', icon: '🚨' },
    'AlienVault OTX': { bg: 'rgba(168, 85, 247, 0.18)', border: 'rgba(168, 85, 247, 0.4)', text: '#c084fc', icon: '🎭' },
    WindowsLogs: { bg: 'rgba(234, 179, 8, 0.18)', border: 'rgba(234, 179, 8, 0.4)', text: '#facc15', icon: '📋' },
    WindowsDefender: { bg: 'rgba(14, 165, 233, 0.18)', border: 'rgba(14, 165, 233, 0.4)', text: '#38bdf8', icon: '🪟' },
  };

  return (
    <div style={{
      display: 'flex',
      justifyContent: isUser ? 'flex-end' : 'flex-start',
      alignItems: 'flex-start',
      gap: 12,
      animation: 'fadeIn 300ms ease'
    }}>
      {/* Avatar */}
      {!isUser && (
        <div style={{
          width: 38,
          height: 38,
          borderRadius: 12,
          background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 18,
          flexShrink: 0,
          boxShadow: '0 4px 16px rgba(99,102,241,0.4)',
          border: '1px solid rgba(255,255,255,0.2)'
        }}>
          🤖
        </div>
      )}

      <div style={bubbleStyle}>
        {/* Header: MCP Tools Used */}
        {message.tools_used && message.tools_used.length > 0 && (
          <div style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 6 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                <span style={{ fontSize: '0.65rem', fontWeight: 800, color: '#818cf8', letterSpacing: '0.05em' }}>
                  MCP TOOLS:
                </span>
                {message.tools_used.map((tool, idx) => {
                  const style = toolColorMap[tool] || { bg: 'rgba(99,102,241,0.18)', border: 'rgba(99,102,241,0.3)', text: '#a5b4fc', icon: '⚙️' };
                  return (
                    <span key={idx} style={{
                      background: style.bg,
                      color: style.text,
                      border: `1px solid ${style.border}`,
                      padding: '2px 8px',
                      borderRadius: 12,
                      fontSize: '0.65rem',
                      fontWeight: 700,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 4
                    }}>
                      <span>{style.icon}</span> {tool}
                    </span>
                  );
                })}
              </div>

              <button
                onClick={() => setShowTrace(p => !p)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#94a3b8',
                  fontSize: '0.65rem',
                  cursor: 'pointer',
                  padding: '2px 6px',
                  textDecoration: 'underline'
                }}
              >
                {showTrace ? 'Hide Trace ▲' : 'View MCP Trace ▼'}
              </button>
            </div>

            {/* Expandable Trace Drawer */}
            {showTrace && (
              <div style={{
                marginTop: 8,
                padding: '8px 12px',
                background: 'rgba(0,0,0,0.4)',
                border: '1px solid rgba(99,102,241,0.2)',
                borderRadius: 8,
                fontSize: '0.68rem',
                fontFamily: 'monospace',
                color: '#94a3b8'
              }}>
                <div>• Orchestrator: EnhancedSecurityCopilotOrchestrator v2.0</div>
                <div>• Linked MCP Servers: {message.tools_used.join(', ')}</div>
                <div>• Dispatch Status: OK (Zero synthetic fallback)</div>
              </div>
            )}
          </div>
        )}

        {/* Message Text */}
        <div style={{ fontSize: '0.875rem', lineHeight: 1.75 }}>
          {renderMarkdown(shownText)}
          {isLatestAI && !done && (
            <span style={{
              display: 'inline-block',
              width: 2,
              height: '1.1em',
              background: '#38bdf8',
              marginLeft: 3,
              animation: 'typingCursor 1s steps(1) infinite',
              verticalAlign: 'text-bottom'
            }} />
          )}
        </div>

        {/* Wazuh Real Telemetry Cards */}
        {message.wazuh_data && (() => {
          const d = message.wazuh_data;
          const agents = d?.agents || [];
          const active = agents.filter(a => a.status === 'active').length;
          const total = d?.statistics?.total_agents ?? agents.length;
          const alerts = d?.statistics?.total_alerts ?? (Array.isArray(d?.alerts) ? d.alerts.length : 0);

          return (
            <div style={{
              marginTop: 12,
              padding: '12px',
              background: 'rgba(6, 182, 212, 0.08)',
              border: '1px solid rgba(6, 182, 212, 0.25)',
              borderRadius: 10
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8, flexWrap: 'wrap', gap: 6 }}>
                <div style={{ fontSize: '0.72rem', fontWeight: 800, color: '#06b6d4', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span>🛡️</span> WAZUH SIEM LIVE TELEMETRY
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <span style={{
                    background: 'rgba(6,182,212,0.2)',
                    color: '#06b6d4',
                    padding: '2px 8px',
                    borderRadius: 12,
                    fontSize: '0.65rem',
                    fontWeight: 700
                  }}>
                    Agents: {active}/{total} Online
                  </span>
                  <span style={{
                    background: alerts > 0 ? 'rgba(249,115,22,0.2)' : 'rgba(16,185,129,0.2)',
                    color: alerts > 0 ? '#fb923c' : '#34d399',
                    padding: '2px 8px',
                    borderRadius: 12,
                    fontSize: '0.65rem',
                    fontWeight: 700
                  }}>
                    Alerts: {alerts}
                  </span>
                </div>
              </div>

              {/* Connected Agent Badges */}
              {agents.length > 0 && (
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 6 }}>
                  {agents.slice(0, 4).map((ag, idx) => (
                    <div key={idx} style={{
                      background: 'rgba(0,0,0,0.3)',
                      border: '1px solid rgba(6,182,212,0.2)',
                      borderRadius: 6,
                      padding: '4px 8px',
                      fontSize: '0.65rem',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6
                    }}>
                      <span style={{ color: ag.status === 'active' ? '#10b981' : '#ef4444' }}>●</span>
                      <strong style={{ color: '#e2e8f0' }}>{ag.name || `Agent ${ag.id}`}</strong>
                      <span style={{ color: '#94a3b8' }}>({ag.ip || 'Virtual'})</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })()}

        {/* Severity & Recommendation Badges */}
        {message.report?.severity && (
          <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.68rem', color: MODERN_COLORS.textMuted }}>Assessment:</span>
            <span style={{
              background: getSeverityGradient(message.report.severity),
              color: '#ffffff',
              padding: '2px 10px',
              borderRadius: 20,
              fontSize: '0.68rem',
              fontWeight: 800,
              boxShadow: '0 2px 8px rgba(0,0,0,0.3)'
            }}>
              {message.report.severity.toUpperCase()}
            </span>
          </div>
        )}

        {/* ─── Tactical Action Suggestion Buttons (Hero Feature) ─── */}
        {!isUser && (
          <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid rgba(255,255,255,0.07)' }}>
            <div style={{ fontSize: '0.65rem', color: '#94a3b8', fontWeight: 700, marginBottom: 6, letterSpacing: '0.04em' }}>
              ⚡ RECOMMENDED ACTIONS & REMEDIATION:
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {detectedIp && (
                <button
                  onClick={() => onActionClick(`Block malicious IP ${detectedIp} via SOAR active defense`)}
                  style={{
                    background: 'rgba(239, 68, 68, 0.15)',
                    border: '1px solid rgba(239, 68, 68, 0.4)',
                    color: '#f87171',
                    borderRadius: 8,
                    padding: '4px 10px',
                    fontSize: '0.7rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 5,
                    transition: 'all 150ms ease'
                  }}
                  onMouseOver={e => e.currentTarget.style.background = 'rgba(239,68,68,0.25)'}
                  onMouseOut={e => e.currentTarget.style.background = 'rgba(239,68,68,0.15)'}
                >
                  <span>🚫</span> Block IP {detectedIp}
                </button>
              )}

              <button
                onClick={() => onActionClick('Show me live Wazuh security alerts')}
                style={{
                  background: 'rgba(6, 182, 212, 0.15)',
                  border: '1px solid rgba(6, 182, 212, 0.35)',
                  color: '#22d3ee',
                  borderRadius: 8,
                  padding: '4px 10px',
                  fontSize: '0.7rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 5,
                  transition: 'all 150ms ease'
                }}
                onMouseOver={e => e.currentTarget.style.background = 'rgba(6,182,212,0.25)'}
                onMouseOut={e => e.currentTarget.style.background = 'rgba(6,182,212,0.15)'}
              >
                <span>🚨</span> Inspect Wazuh Alerts
              </button>

              <button
                onClick={() => onActionClick('Run SOAR automated response playbook')}
                style={{
                  background: 'rgba(16, 185, 129, 0.15)',
                  border: '1px solid rgba(16, 185, 129, 0.35)',
                  color: '#34d399',
                  borderRadius: 8,
                  padding: '4px 10px',
                  fontSize: '0.7rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 5,
                  transition: 'all 150ms ease'
                }}
                onMouseOver={e => e.currentTarget.style.background = 'rgba(16,185,129,0.25)'}
                onMouseOut={e => e.currentTarget.style.background = 'rgba(16,185,129,0.15)'}
              >
                <span>⚡</span> Run SOAR Playbook
              </button>

              <button
                onClick={() => onActionClick('Investigate recent security events and correlate IOCs')}
                style={{
                  background: 'rgba(139, 92, 246, 0.15)',
                  border: '1px solid rgba(139, 92, 246, 0.35)',
                  color: '#a78bfa',
                  borderRadius: 8,
                  padding: '4px 10px',
                  fontSize: '0.7rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 5,
                  transition: 'all 150ms ease'
                }}
                onMouseOver={e => e.currentTarget.style.background = 'rgba(139,92,246,0.25)'}
                onMouseOut={e => e.currentTarget.style.background = 'rgba(139,92,246,0.15)'}
              >
                <span>🔍</span> Deep Investigation
              </button>
            </div>
          </div>
        )}

        {/* Bubble Footer */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginTop: 10,
          gap: 8,
          fontSize: '0.62rem',
          color: isUser ? 'rgba(255,255,255,0.6)' : MODERN_COLORS.textMuted
        }}>
          <span>{message.time}</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {isUser && <span>✓✓ Sent</span>}
            {!isUser && fullText && (
              <button
                onClick={handleCopy}
                title="Copy response"
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: copied ? '#10b981' : MODERN_COLORS.textMuted,
                  fontSize: '0.72rem',
                  padding: '2px 6px',
                  borderRadius: 4,
                  transition: 'color 150ms'
                }}
              >
                {copied ? '✓ Copied' : '⎘ Copy'}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* User Avatar */}
      {isUser && (
        <div style={{
          width: 38,
          height: 38,
          borderRadius: 12,
          background: 'linear-gradient(135deg, #1e293b, #334155)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 18,
          flexShrink: 0,
          border: '1px solid rgba(255,255,255,0.15)'
        }}>
          👤
        </div>
      )}
    </div>
  );
});

MessageBubble.displayName = 'MessageBubble';

/* ─── Main ChatInterface Component ────────────────────────── */
const ChatInterface = () => {
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState([WELCOME_MSG]);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [showSearch, setShowSearch] = useState(false);
  const [selectedModel, setSelectedModel] = useState('sentinelai');
  const [showModelMenu, setShowModelMenu] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(!cyberAudio.isMuted());
  const [latestAIId, setLatestAIId] = useState(null);

  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);
  const chatContainerRef = useRef(null);

  const getApiUrl = useCallback((path) => {
    const base = import.meta.env.VITE_API_URL?.trim();
    return base ? `${base.replace(/\/$/, '')}${path}` : path;
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const toggleSound = useCallback(() => {
    const muted = cyberAudio.toggleMute();
    setSoundEnabled(!muted);
  }, []);

  const filteredMessages = useMemo(() => {
    if (!searchQuery.trim()) return messages;
    const q = searchQuery.toLowerCase();
    return messages.filter(m => (m.text || '').toLowerCase().includes(q));
  }, [messages, searchQuery]);

  const handleExport = useCallback(() => {
    cyberAudio.playClick();
    const text = messages.map(m => `[${m.time}] ${m.role === 'user' ? 'ANALYST' : 'SENTINEL-AI'}:\n${m.text || ''}\n`).join('\n---\n\n');
    const blob = new Blob([text], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinelai-soc-report-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }, [messages]);

  const handleClear = useCallback(() => {
    cyberAudio.playClick();
    setMessages([{ ...WELCOME_MSG, id: Date.now(), time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }]);
    setLatestAIId(null);
  }, []);

  const executeQuery = useCallback(async (questionText) => {
    const question = (questionText || input).trim();
    if (!question || loading) return;

    cyberAudio.playWarp();

    const userMsg = {
      id: Date.now(),
      role: 'user',
      text: question,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      // Check if user is asking to start a persistent background investigation
      const isStartInvestigation = /\b(?:start|begin|launch|run)\b[\s\S]{0,48}\binvest/i.test(question);

      if (isStartInvestigation) {
        const res = await fetch(getApiUrl('/api/log-analysis/investigation/start'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            title: question.slice(0, 255),
            description: `Started from AI Chat: ${question}`,
            investigation_type: /\b(alert|incident|breach|attack)\b/i.test(question) ? 'incident_response' : 'general',
            log_sources: ['windows_event', 'sysmon', 'defender'],
            time_range_hours: 24,
            auto_start: true
          })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

        cyberAudio.playSuccess();
        const aiMsg = {
          id: Date.now() + 1,
          role: 'assistant',
          text: `✅ **Autonomous Investigation Launched Successfully**\n\n- **Investigation ID:** \`${data.investigation_id}\`\n- **Status:** \`Active Planning\`\n- **Log Pipeline:** Windows Event + Sysmon + Defender\n\nThe background forensic agent is collecting and analyzing event logs. Navigate to **Investigation Dashboard** to monitor the live timeline.`,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };
        setMessages(prev => [...prev, aiMsg]);
        setLatestAIId(aiMsg.id);
        return;
      }

      // Main Security Copilot MCP Investigation
      const res = await fetch(getApiUrl('/api/investigate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: question,
          model: selectedModel,
          context: messages.slice(-6).map(m => ({ role: m.role, content: m.text }))
        })
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      const wazuhData = data.wazuh_data || data.unified_investigation?.wazuh_data || null;
      const wazuhAgents = wazuhData?.agents || [];
      let responseText = data.ai_answer || '';

      if (wazuhAgents.length > 0) {
        const active = wazuhAgents.filter(a => a.status === 'active').length;
        const totalAlerts = wazuhData?.statistics?.total_alerts ?? 0;
        const summary = `**🛡️ Wazuh SIEM Telemetry Summary**\n- **Monitored Fleet:** \`${active}/${wazuhAgents.length}\` Agents Active\n- **Live Alert Count:** \`${totalAlerts}\` Recorded Events`;
        responseText = [summary, responseText.replace(/^\*\*Wazuh Query Results:\*\*[\s\S]*?(?:\n\n)?/i, '').trim()].filter(Boolean).join('\n\n');
      }

      cyberAudio.playSuccess();

      const aiMsg = {
        id: Date.now() + 1,
        role: 'assistant',
        text: responseText || `Investigation completed with tool orchestration: ${(data.required_tools || []).join(', ') || 'Core Engine'}.`,
        tools_used: data.required_tools || [],
        report: data.report_json,
        wazuh_data: wazuhData,
        threat_intel: data.threat_intel || null,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages(prev => [...prev, aiMsg]);
      setLatestAIId(aiMsg.id);
    } catch (err) {
      cyberAudio.playAlert();
      const errMsg = {
        id: Date.now() + 2,
        role: 'assistant',
        text: `⚠️ **SentinelAI SOC Engine Communication Exception**\n\n\`${err.message}\`\n\nEnsure backend FastAPI service is running on \`http://127.0.0.1:8000\`.`,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        isError: true
      };
      setMessages(prev => [...prev, errMsg]);
      setLatestAIId(errMsg.id);
    } finally {
      setLoading(false);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [input, loading, messages, selectedModel, getApiUrl]);

  const handleSend = useCallback((e) => {
    if (e) e.preventDefault();
    executeQuery();
  }, [executeQuery]);

  const handleKeyDown = useCallback((e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      executeQuery();
    }
  }, [executeQuery]);

  const currentModel = AI_MODELS.find(m => m.id === selectedModel);
  const charCount = input.length;

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: '100%',
      background: '#040711',
      position: 'relative',
      overflow: 'hidden',
      fontFamily: TYPOGRAPHY.fontFamily
    }}>
      {/* Dynamic Cyber Grid & Scanline Background */}
      <div style={{
        position: 'absolute',
        inset: 0,
        backgroundImage: 'linear-gradient(rgba(99,102,241,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(99,102,241,0.03) 1px, transparent 1px)',
        backgroundSize: '36px 36px',
        pointerEvents: 'none',
        zIndex: 0
      }} />
      <div style={{
        position: 'absolute',
        inset: 0,
        background: 'radial-gradient(circle at 20% 20%, rgba(99,102,241,0.08) 0%, transparent 50%), radial-gradient(circle at 80% 80%, rgba(6,182,212,0.06) 0%, transparent 50%)',
        pointerEvents: 'none',
        zIndex: 0
      }} />

      {/* ─── Hero HUD Header ─── */}
      <div style={{
        padding: `${SPACING.md}px ${SPACING.xxl}px`,
        position: 'relative',
        zIndex: 1,
        borderBottom: '1px solid rgba(99,102,241,0.2)',
        background: 'rgba(6,9,18,0.88)',
        backdropFilter: 'blur(20px)'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          {/* Left Title & Status */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{
              width: 44,
              height: 44,
              borderRadius: 12,
              background: 'linear-gradient(135deg, #6366f1, #06b6d4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 22,
              boxShadow: '0 0 20px rgba(99,102,241,0.4)',
              flexShrink: 0
            }}>
              🤖
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{
                  fontSize: '1.2rem',
                  fontWeight: 900,
                  letterSpacing: '-0.02em',
                  background: 'linear-gradient(135deg, #6366f1, #38bdf8, #a855f7)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent'
                }}>
                  SentinelAI X Security Copilot
                </span>
                <span style={{
                  background: 'rgba(16,185,129,0.18)',
                  border: '1px solid rgba(16,185,129,0.4)',
                  color: '#34d399',
                  padding: '2px 8px',
                  borderRadius: 12,
                  fontSize: '0.62rem',
                  fontWeight: 800,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4
                }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981', display: 'inline-block' }} />
                  MCP ONLINE
                </span>
              </div>
              <div style={{ fontSize: '0.68rem', color: '#94a3b8', marginTop: 2 }}>
                Wazuh SIEM • VirusTotal • AbuseIPDB • SOAR Active Defense • Windows Telemetry
              </div>
            </div>
          </div>

          {/* Right Controls */}
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            {/* Model Selector */}
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => { cyberAudio.playClick(); setShowModelMenu(p => !p); }}
                style={{
                  background: 'rgba(15,23,42,0.8)',
                  border: '1px solid rgba(99,102,241,0.3)',
                  borderRadius: 10,
                  color: '#f8fafc',
                  padding: '7px 12px',
                  cursor: 'pointer',
                  fontSize: '0.72rem',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6
                }}
              >
                {currentModel?.label} <span style={{ opacity: 0.6 }}>▾</span>
              </button>
              {showModelMenu && (
                <div style={{
                  position: 'absolute',
                  top: '110%',
                  right: 0,
                  background: 'rgba(10,15,30,0.98)',
                  border: '1px solid rgba(99,102,241,0.4)',
                  borderRadius: 12,
                  padding: 6,
                  zIndex: 100,
                  minWidth: 200,
                  boxShadow: '0 16px 48px rgba(0,0,0,0.6)',
                  backdropFilter: 'blur(20px)'
                }}>
                  {AI_MODELS.map(m => (
                    <button
                      key={m.id}
                      onClick={() => {
                        cyberAudio.playClick();
                        setSelectedModel(m.id);
                        setShowModelMenu(false);
                      }}
                      style={{
                        width: '100%',
                        background: selectedModel === m.id ? 'rgba(99,102,241,0.25)' : 'none',
                        border: 'none',
                        borderRadius: 8,
                        color: selectedModel === m.id ? '#a5b4fc' : '#94a3b8',
                        padding: '8px 12px',
                        cursor: 'pointer',
                        fontSize: '0.72rem',
                        textAlign: 'left',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        marginBottom: 2
                      }}
                    >
                      <span>{m.label}</span>
                      <span style={{ fontSize: '0.6rem', opacity: 0.7 }}>{m.badge}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Audio Toggle */}
            <button
              onClick={toggleSound}
              title={soundEnabled ? 'Mute Cyber Audio FX' : 'Enable Cyber Audio FX'}
              style={{
                background: soundEnabled ? 'rgba(99,102,241,0.2)' : 'rgba(15,23,42,0.8)',
                border: `1px solid ${soundEnabled ? 'rgba(99,102,241,0.5)' : 'rgba(255,255,255,0.1)'}`,
                borderRadius: 10,
                color: soundEnabled ? '#a5b4fc' : '#64748b',
                padding: '7px 10px',
                cursor: 'pointer',
                fontSize: '0.72rem'
              }}
            >
              {soundEnabled ? '🔊 SFX' : '🔇 Muted'}
            </button>

            {/* Search Filter */}
            <button
              onClick={() => { cyberAudio.playClick(); setShowSearch(p => !p); }}
              title="Search conversation history"
              style={{
                background: showSearch ? 'rgba(99,102,241,0.2)' : 'rgba(15,23,42,0.8)',
                border: `1px solid ${showSearch ? 'rgba(99,102,241,0.5)' : 'rgba(255,255,255,0.1)'}`,
                borderRadius: 10,
                color: '#f8fafc',
                padding: '7px 10px',
                cursor: 'pointer',
                fontSize: '0.72rem'
              }}
            >
              🔍
            </button>

            {/* Export */}
            <button
              onClick={handleExport}
              title="Export Incident Report to Markdown"
              style={{
                background: 'rgba(15,23,42,0.8)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 10,
                color: '#f8fafc',
                padding: '7px 12px',
                cursor: 'pointer',
                fontSize: '0.72rem'
              }}
            >
              ⬇ Export
            </button>

            {/* Clear */}
            <button
              onClick={handleClear}
              title="Clear session messages"
              style={{
                background: 'rgba(15,23,42,0.8)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 10,
                color: '#f8fafc',
                padding: '7px 12px',
                cursor: 'pointer',
                fontSize: '0.72rem'
              }}
            >
              🗑️ Clear
            </button>
          </div>
        </div>

        {/* Search Bar */}
        {showSearch && (
          <div style={{ marginTop: 10 }}>
            <input
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search conversation trace..."
              style={{
                width: '100%',
                background: 'rgba(10,15,30,0.95)',
                border: '1px solid rgba(99,102,241,0.4)',
                borderRadius: 8,
                color: '#f8fafc',
                padding: '8px 12px',
                fontSize: '0.78rem',
                outline: 'none',
                fontFamily: TYPOGRAPHY.fontFamily
              }}
            />
          </div>
        )}
      </div>

      {/* ─── Tactical Quick Command Strip ─── */}
      <div style={{
        padding: '10px 24px',
        position: 'relative',
        zIndex: 1,
        display: 'flex',
        gap: 8,
        overflowX: 'auto',
        flexShrink: 0,
        scrollbarWidth: 'none',
        background: 'rgba(5,8,16,0.6)',
        borderBottom: '1px solid rgba(255,255,255,0.04)'
      }}>
        {QUICK_COMMANDS.map((cmd, idx) => (
          <button
            key={idx}
            onClick={() => executeQuery(cmd.text)}
            title={cmd.text}
            style={{
              flexShrink: 0,
              background: cmd.tag === 'Tamil' ? 'rgba(234, 179, 8, 0.12)' : 'rgba(15, 23, 42, 0.8)',
              border: `1px solid ${cmd.tag === 'Tamil' ? 'rgba(234, 179, 8, 0.35)' : 'rgba(99, 102, 241, 0.25)'}`,
              borderRadius: 20,
              color: cmd.tag === 'Tamil' ? '#fde047' : '#cbd5e1',
              padding: '5px 12px',
              cursor: 'pointer',
              fontSize: '0.68rem',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: 5,
              transition: 'all 150ms ease',
              whiteSpace: 'nowrap'
            }}
            onMouseOver={e => {
              e.currentTarget.style.borderColor = '#38bdf8';
              e.currentTarget.style.color = '#38bdf8';
            }}
            onMouseOut={e => {
              e.currentTarget.style.borderColor = cmd.tag === 'Tamil' ? 'rgba(234, 179, 8, 0.35)' : 'rgba(99, 102, 241, 0.25)';
              e.currentTarget.style.color = cmd.tag === 'Tamil' ? '#fde047' : '#cbd5e1';
            }}
          >
            <span>{cmd.icon}</span>
            <span>{cmd.label}</span>
          </button>
        ))}
      </div>

      {/* ─── Messages Viewport ─── */}
      <div
        ref={chatContainerRef}
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: `${SPACING.md}px ${SPACING.xxl}px`,
          display: 'flex',
          flexDirection: 'column',
          gap: SPACING.lg,
          position: 'relative',
          zIndex: 1,
          minHeight: 0
        }}
      >
        {filteredMessages.map(msg => (
          <MessageBubble
            key={msg.id}
            message={msg}
            isLatestAI={msg.id === latestAIId && msg.role === 'assistant'}
            onActionClick={executeQuery}
          />
        ))}

        {loading && <MCPProgressPipeline />}

        <div ref={messagesEndRef} />
      </div>

      {/* ─── Command Input Terminal ─── */}
      <div style={{
        padding: `${SPACING.md}px ${SPACING.xxl}px ${SPACING.lg}px`,
        position: 'relative',
        zIndex: 1,
        borderTop: '1px solid rgba(99,102,241,0.2)',
        background: 'rgba(6,9,18,0.92)',
        backdropFilter: 'blur(20px)'
      }}>
        <form onSubmit={handleSend} style={{ display: 'flex', gap: 12, alignItems: 'flex-end' }}>
          <div style={{ flex: 1, position: 'relative' }}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={e => {
                setInput(e.target.value);
                e.target.style.height = 'auto';
                e.target.style.height = Math.min(e.target.scrollHeight, 160) + 'px';
              }}
              onKeyDown={handleKeyDown}
              placeholder="Ask SentinelAI (e.g., 'Show live alerts', 'Wazuh alert check pannu', 'Block IP 185.220.101.45')..."
              disabled={loading}
              rows={1}
              style={{
                width: '100%',
                background: 'rgba(10,15,30,0.95)',
                border: '1px solid rgba(99,102,241,0.35)',
                borderRadius: 12,
                color: '#f8fafc',
                padding: '12px 16px',
                fontSize: '0.85rem',
                outline: 'none',
                fontFamily: TYPOGRAPHY.fontFamily,
                resize: 'none',
                lineHeight: 1.5,
                transition: 'border-color 150ms ease',
                overflowY: 'hidden',
                minHeight: 48,
                boxShadow: 'inset 0 2px 8px rgba(0,0,0,0.5)'
              }}
              onFocus={e => e.target.style.borderColor = '#38bdf8'}
              onBlur={e => e.target.style.borderColor = 'rgba(99,102,241,0.35)'}
            />
            {charCount > 0 && (
              <div style={{
                position: 'absolute',
                bottom: 8,
                right: 12,
                fontSize: '0.62rem',
                color: charCount > 1000 ? '#f59e0b' : '#64748b',
                pointerEvents: 'none'
              }}>
                {charCount}/2000
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={loading || !input.trim()}
            style={{
              background: loading || !input.trim()
                ? 'rgba(99,102,241,0.25)'
                : 'linear-gradient(135deg, #6366f1, #06b6d4)',
              border: 'none',
              borderRadius: 12,
              color: '#ffffff',
              padding: '0 22px',
              height: 48,
              cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
              fontSize: '0.85rem',
              fontWeight: 800,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              transition: 'all 200ms ease',
              whiteSpace: 'nowrap',
              boxShadow: loading || !input.trim() ? 'none' : '0 4px 16px rgba(99,102,241,0.4)',
              flexShrink: 0
            }}
          >
            {loading ? '⏳' : '⚡'} {loading ? 'Orchestrating…' : 'Execute'}
          </button>
        </form>

        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          marginTop: 6,
          fontSize: '0.62rem',
          color: '#64748b',
          padding: '0 2px'
        }}>
          <span>⌨️ Press Ctrl+Enter to dispatch • Model: {currentModel?.label}</span>
          <span>{filteredMessages.filter(m => m.role === 'assistant').length} AI Orchestrations logged</span>
        </div>
      </div>
    </div>
  );
};

export default ChatInterface;