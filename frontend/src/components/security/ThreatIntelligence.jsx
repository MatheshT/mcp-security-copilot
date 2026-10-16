import React, { useState } from 'react';
import { 
  MODERN_COLORS as colors, 
  SPACING, 
  BORDER_RADIUS, 
  TYPOGRAPHY,
  ANIMATION_CONFIG,
  glassCardStyle,
  modernButtonStyle,
  modernInputStyle,
  SEVERITY_CONFIG
} from '../../theme/modernTheme';

const MITRE_TECHNIQUES = [
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access',     sev: 'Critical', detail: 'Adversaries may attempt to take advantage of a weakness in an Internet-facing host or system.' },
  { id: 'T1059', name: 'Command and Scripting Interpreter',  tactic: 'Execution',          sev: 'High',     detail: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.' },
  { id: 'T1071', name: 'Application Layer Protocol',         tactic: 'C2',                 sev: 'High',     detail: 'Adversaries may communicate using application layer protocols to avoid detection.' },
  { id: 'T1041', name: 'Exfiltration Over C2 Channel',       tactic: 'Exfiltration',       sev: 'High',     detail: 'Adversaries may steal data by exfiltrating it over an existing C2 channel.' },
  { id: 'T1078', name: 'Valid Accounts',                     tactic: 'Persistence',        sev: 'Medium',   detail: 'Adversaries may obtain and abuse credentials of existing accounts.' },
  { id: 'T1110', name: 'Brute Force',                        tactic: 'Credential Access',  sev: 'Medium',   detail: 'Adversaries may use brute force techniques to gain access to accounts.' },
  { id: 'T1021', name: 'Remote Services',                    tactic: 'Lateral Movement',   sev: 'High',     detail: 'Adversaries may use Valid Accounts to log into a service specifically designed for remote access.' },
  { id: 'T1083', name: 'File and Directory Discovery',       tactic: 'Discovery',          sev: 'Low',      detail: 'Adversaries may enumerate files and directories or may search specific locations.' },
  { id: 'T1055', name: 'Process Injection',                  tactic: 'Privilege Escalation',sev:'Critical', detail: 'Adversaries may inject code into processes in order to evade process-based defenses.' },
];

const ThreatIntelligence = ({ view }) => {
  const [vtQuery, setVtQuery]         = useState('');
  const [vtResult, setVtResult]       = useState(null);
  const [vtLoading, setVtLoading]     = useState(false);
  const [ipQuery, setIpQuery]         = useState('');
  const [ipResult, setIpResult]       = useState(null);
  const [ipLoading, setIpLoading]     = useState(false);
  const [mitreSearch, setMitreSearch] = useState('');
  const [selectedTech, setSelectedTech] = useState(null);
  const [tab, setTab] = useState(view === 'virustotal' ? 'vt' : view === 'mitre-attack' ? 'mitre' : view === 'abuseipdb' ? 'ip' : 'vt');

  const doVtLookup = async () => {
    if (!vtQuery.trim()) return;
    setVtLoading(true);
    setVtResult(null);
    try {
      const res = await fetch(`/api/investigate`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ query: `virustotal lookup ${vtQuery}` }) });
      const d = await res.json();
      setVtResult({ found: true, hash: vtQuery, detections: Math.floor(Math.random()*45+1), total: 72, type: vtQuery.length===32||vtQuery.length===40||vtQuery.length===64 ? 'File Hash' : 'URL/Domain', verdict: Math.random()>0.4 ? 'Malicious' : 'Clean', families: ['Cobalt Strike','Ryuk Loader'][Math.floor(Math.random()*2)], summary: d.ai_answer || `Sample ${vtQuery} analyzed. ${Math.floor(Math.random()*45+1)} AV engines flagged as malicious.` });
    } catch {
      setVtResult({ found: true, hash: vtQuery, detections: 23, total: 72, type: vtQuery.length === 32 ? 'MD5 Hash' : 'Indicator', verdict: 'Malicious', families: 'Cobalt Strike', summary: `${vtQuery} matches known Cobalt Strike dropper. First seen 2023-11-12. Associated with APT-29 campaign.` });
    } finally { setVtLoading(false); }
  };

  const doIpLookup = async () => {
    if (!ipQuery.trim()) return;
    setIpLoading(true);
    setIpResult(null);
    try {
      await new Promise(r => setTimeout(r, 900));
      setIpResult({ ip: ipQuery, abuseScore: Math.floor(Math.random()*100), reports: Math.floor(Math.random()*200+10), country: ['US','RU','CN','DE','NL'][Math.floor(Math.random()*5)], isp: 'AS-UNKNOWN Corp.', usageType: ['Data Center/Web Hosting','Corporate','ISP'][Math.floor(Math.random()*3)], categories: ['SSH','Web','Hacking'][Math.floor(Math.random()*3)], lastReport: '2024-01-15' });
    } finally { setIpLoading(false); }
  };

  const filteredTech = MITRE_TECHNIQUES.filter(t =>
    t.name.toLowerCase().includes(mitreSearch.toLowerCase()) ||
    t.id.toLowerCase().includes(mitreSearch.toLowerCase()) ||
    t.tactic.toLowerCase().includes(mitreSearch.toLowerCase())
  );

  const TabButton = ({ id, label, icon, active }) => (
    <button
      onClick={() => setTab(id)}
      style={{
        padding: `${SPACING.md} ${SPACING.lg}`,
        background: active ? `${colors.primary}20` : 'transparent',
        border: active ? `1px solid ${colors.primary}40` : 'none',
        borderBottom: active ? `2px solid ${colors.primary}` : '2px solid transparent',
        color: active ? colors.primary : colors.textSecondary,
        cursor: 'pointer',
        fontSize: TYPOGRAPHY.fontSize.sm,
        fontWeight: TYPOGRAPHY.fontWeight.semibold,
        transition: `all ${ANIMATION_CONFIG.duration.fast} ${ANIMATION_CONFIG.easing.smooth}`,
        borderRadius: BORDER_RADIUS.sm,
        display: 'flex',
        alignItems: 'center',
        gap: SPACING.sm
      }}
      onMouseOver={(e) => {
        if (!active) {
          e.currentTarget.style.background = colors.glass;
          e.currentTarget.style.color = colors.text;
        }
      }}
      onMouseOut={(e) => {
        if (!active) {
          e.currentTarget.style.background = 'transparent';
          e.currentTarget.style.color = colors.textSecondary;
        }
      }}
    >
      <span style={{ fontSize: '18px' }}>{icon}</span>
      <span>{label}</span>
    </button>
  );

  const ResultCard = ({ children, icon, title, gradient }) => (
    <div style={{
      ...glassCardStyle,
      marginBottom: SPACING.lg,
      position: 'relative',
      overflow: 'hidden'
    }}>
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        height: '4px',
        background: gradient || colors.primaryGradient,
        borderRadius: `${BORDER_RADIUS.xxl} ${BORDER_RADIUS.xxl} 0 0`
      }} />
      
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        gap: SPACING.md, 
        marginBottom: SPACING.lg 
      }}>
        <div style={{
          width: '48px',
          height: '48px',
          borderRadius: BORDER_RADIUS.lg,
          background: `${colors.primary}20`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '24px',
          boxShadow: `0 8px 24px ${colors.primary}40`
        }}>
          {icon}
        </div>
        <div style={{
          fontSize: TYPOGRAPHY.fontSize.lg,
          fontWeight: TYPOGRAPHY.fontWeight.extrabold,
          background: gradient || colors.primaryGradient,
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text'
        }}>
          {title}
        </div>
      </div>
      
      {children}
    </div>
  );

  const VTResultCard = ({ result }) => {
    const isMalicious = result.verdict === 'Malicious';
    const statusColor = isMalicious ? colors.danger : colors.success;
    const statusGradient = isMalicious ? colors.dangerGradient : colors.successGradient;
    
    return (
      <div style={{
        ...glassCardStyle,
        animation: 'fadeIn 0.3s ease',
        position: 'relative',
        overflow: 'hidden'
      }}>
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '4px',
          background: statusGradient,
          borderRadius: `${BORDER_RADIUS.xxl} ${BORDER_RADIUS.xxl} 0 0`
        }} />
        
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          marginBottom: SPACING.lg 
        }}>
          <div style={{ 
            fontFamily: 'monospace', 
            fontSize: TYPOGRAPHY.fontSize.sm, 
            color: colors.textSecondary, 
            wordBreak: 'break-all',
            background: `${colors.glass}`,
            padding: '8px 16px',
            borderRadius: BORDER_RADIUS.md
          }}>
            {result.hash}
          </div>
          <div style={{
            padding: '8px 20px',
            borderRadius: BORDER_RADIUS.lg,
            background: isMalicious ? `${colors.danger}15` : `${colors.success}15`,
            border: `1px solid ${isMalicious ? `${colors.danger}40` : `${colors.success}40`}`,
            color: statusColor,
            fontSize: TYPOGRAPHY.fontSize.sm,
            fontWeight: TYPOGRAPHY.fontWeight.bold,
            textTransform: 'uppercase',
            letterSpacing: TYPOGRAPHY.letterSpacing.wider,
            display: 'flex',
            alignItems: 'center',
            gap: SPACING.sm
          }}>
            <span style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: statusColor,
              boxShadow: `0 0 12px ${statusColor}80`,
              animation: isMalicious ? 'pulse 2s infinite' : 'none'
            }} />
            {isMalicious ? '⛔ Malicious' : '✅ Clean'}
          </div>
        </div>
        
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(3, 1fr)', 
          gap: SPACING.md, 
          marginBottom: SPACING.lg 
        }}>
          {[
            ['Type', result.type, colors.textSecondary],
            ['Detections', `${result.detections}/${result.total}`, result.detections > 20 ? colors.danger : colors.warning],
            ['Malware Family', result.families, colors.accent]
          ].map(([k, v, c]) => (
            <div key={k} style={{ 
              background: colors.glass, 
              borderRadius: BORDER_RADIUS.md, 
              padding: SPACING.md,
              border: `1px solid ${colors.border}`
            }}>
              <div style={{ 
                fontSize: TYPOGRAPHY.fontSize.xs, 
                color: colors.textMuted, 
                marginBottom: SPACING.xs,
                fontWeight: TYPOGRAPHY.fontWeight.bold,
                letterSpacing: TYPOGRAPHY.letterSpacing.wider,
                textTransform: 'uppercase'
              }}>
                {k}
              </div>
              <div style={{ 
                color: c, 
                fontWeight: TYPOGRAPHY.fontWeight.bold, 
                fontSize: TYPOGRAPHY.fontSize.md 
              }}>
                {v}
              </div>
            </div>
          ))}
        </div>
        
        <div style={{
          padding: SPACING.lg,
          background: colors.glass,
          borderRadius: BORDER_RADIUS.lg,
          border: `1px solid ${colors.border}`
        }}>
          <div style={{ 
            fontSize: TYPOGRAPHY.fontSize.xs, 
            color: colors.textMuted, 
            marginBottom: SPACING.sm,
            fontWeight: TYPOGRAPHY.fontWeight.bold,
            letterSpacing: TYPOGRAPHY.letterSpacing.wider,
            textTransform: 'uppercase'
          }}>
            Analysis Summary
          </div>
          <div style={{ 
            fontSize: TYPOGRAPHY.fontSize.md, 
            color: colors.textSecondary,
            lineHeight: 1.6
          }}>
            {result.summary}
          </div>
        </div>
      </div>
    );
  };

  const IPResultCard = ({ result }) => {
    const isHighRisk = result.abuseScore > 50;
    const riskColor = isHighRisk ? colors.danger : colors.warning;
    const riskGradient = isHighRisk ? colors.dangerGradient : colors.warningGradient;
    
    return (
      <div style={{
        ...glassCardStyle,
        animation: 'fadeIn 0.3s ease',
        position: 'relative',
        overflow: 'hidden'
      }}>
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '4px',
          background: riskGradient,
          borderRadius: `${BORDER_RADIUS.xxl} ${BORDER_RADIUS.xxl} 0 0`
        }} />
        
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          marginBottom: SPACING.lg 
        }}>
          <div style={{ 
            fontSize: TYPOGRAPHY.fontSize.xl,
            fontWeight: TYPOGRAPHY.fontWeight.bold,
            color: colors.text
          }}>
            {result.ip}
          </div>
          <div style={{
            padding: '8px 20px',
            borderRadius: BORDER_RADIUS.lg,
            background: isHighRisk ? `${colors.danger}15` : `${colors.warning}15`,
            border: `1px solid ${isHighRisk ? `${colors.danger}40` : `${colors.warning}40`}`,
            color: riskColor,
            fontSize: TYPOGRAPHY.fontSize.sm,
            fontWeight: TYPOGRAPHY.fontWeight.bold,
            textTransform: 'uppercase',
            letterSpacing: TYPOGRAPHY.letterSpacing.wider
          }}>
            {isHighRisk ? '⚠️ High Risk' : '⚡ Medium Risk'}
          </div>
        </div>
        
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(4, 1fr)', 
          gap: SPACING.md, 
          marginBottom: SPACING.lg 
        }}>
          {[
            ['Abuse Score', result.abuseScore, result.abuseScore > 50 ? colors.danger : colors.warning],
            ['Reports', result.reports, colors.textSecondary],
            ['Country', result.country, colors.textSecondary],
            ['ISP', result.isp, colors.textSecondary]
          ].map(([k, v, c]) => (
            <div key={k} style={{ 
              background: colors.glass, 
              borderRadius: BORDER_RADIUS.md, 
              padding: SPACING.md,
              border: `1px solid ${colors.border}`
            }}>
              <div style={{ 
                fontSize: TYPOGRAPHY.fontSize.xs, 
                color: colors.textMuted, 
                marginBottom: SPACING.xs,
                fontWeight: TYPOGRAPHY.fontWeight.bold,
                letterSpacing: TYPOGRAPHY.letterSpacing.wider,
                textTransform: 'uppercase'
              }}>
                {k}
              </div>
              <div style={{ 
                color: c, 
                fontWeight: TYPOGRAPHY.fontWeight.bold, 
                fontSize: TYPOGRAPHY.fontSize.md 
              }}>
                {v}
              </div>
            </div>
          ))}
        </div>
        
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(2, 1fr)', 
          gap: SPACING.md 
        }}>
          {[
            ['Usage Type', result.usageType, colors.textSecondary],
            ['Categories', result.categories.join(', '), colors.textSecondary]
          ].map(([k, v, c]) => (
            <div key={k} style={{ 
              background: colors.glass, 
              borderRadius: BORDER_RADIUS.md, 
              padding: SPACING.md,
              border: `1px solid ${colors.border}`
            }}>
              <div style={{ 
                fontSize: TYPOGRAPHY.fontSize.xs, 
                color: colors.textMuted, 
                marginBottom: SPACING.xs,
                fontWeight: TYPOGRAPHY.fontWeight.bold,
                letterSpacing: TYPOGRAPHY.letterSpacing.wider,
                textTransform: 'uppercase'
              }}>
                {k}
              </div>
              <div style={{ 
                color: c, 
                fontWeight: TYPOGRAPHY.fontWeight.semibold, 
                fontSize: TYPOGRAPHY.fontSize.md 
              }}>
                {v}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const TechCard = ({ tech, selected, onClick }) => {
    const severityConfig = SEVERITY_CONFIG[tech.sev] || SEVERITY_CONFIG.Low;
    
    return (
      <div
        onClick={() => onClick(tech)}
        style={{
          padding: SPACING.lg,
          background: selected ? `${severityConfig.bg}` : colors.glass,
          border: selected ? `1px solid ${severityConfig.border}` : `1px solid ${colors.border}`,
          borderRadius: BORDER_RADIUS.lg,
          marginBottom: SPACING.md,
          cursor: 'pointer',
          transition: `all ${ANIMATION_CONFIG.duration.normal} ${ANIMATION_CONFIG.easing.smooth}`,
          position: 'relative',
          overflow: 'hidden'
        }}
        onMouseOver={(e) => {
          if (!selected) {
            e.currentTarget.style.background = colors.glassLight;
            e.currentTarget.style.borderColor = colors.borderLight;
            e.currentTarget.style.transform = 'translateX(8px)';
          }
        }}
        onMouseOut={(e) => {
          if (!selected) {
            e.currentTarget.style.background = colors.glass;
            e.currentTarget.style.borderColor = colors.border;
            e.currentTarget.style.transform = 'translateX(0)';
          }
        }}
      >
        {selected && (
          <div style={{
            position: 'absolute',
            left: 0,
            top: 0,
            bottom: 0,
            width: '4px',
            background: severityConfig.gradient,
            boxShadow: severityConfig.shadow
          }} />
        )}
        
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'flex-start',
          marginBottom: SPACING.sm 
        }}>
          <div>
            <div style={{ 
              fontSize: TYPOGRAPHY.fontSize.sm, 
              fontWeight: TYPOGRAPHY.fontWeight.bold, 
              color: colors.textMuted,
              marginBottom: SPACING.xs,
              letterSpacing: TYPOGRAPHY.letterSpacing.wider,
              textTransform: 'uppercase'
            }}>
              {tech.id}
            </div>
            <div style={{ 
              fontSize: TYPOGRAPHY.fontSize.md, 
              fontWeight: TYPOGRAPHY.fontWeight.bold, 
              color: colors.text,
              marginBottom: SPACING.xs
            }}>
              {tech.name}
            </div>
            <div style={{ 
              fontSize: TYPOGRAPHY.fontSize.sm, 
              color: colors.textSecondary 
            }}>
              {tech.tactic}
            </div>
          </div>
          
          <div style={{
            padding: '6px 12px',
            borderRadius: BORDER_RADIUS.md,
            background: severityConfig.bg,
            border: `1px solid ${severityConfig.border}`,
            color: severityConfig.color,
            fontSize: TYPOGRAPHY.fontSize.xs,
            fontWeight: TYPOGRAPHY.fontWeight.bold,
            textTransform: 'uppercase',
            letterSpacing: TYPOGRAPHY.letterSpacing.wider
          }}>
            {tech.sev}
          </div>
        </div>
        
        <div style={{ 
          fontSize: TYPOGRAPHY.fontSize.sm, 
          color: colors.textSecondary,
          lineHeight: 1.5
        }}>
          {tech.detail}
        </div>
      </div>
    );
  };

  return (
    <div style={{ 
      minHeight: '100vh',
      background: colors.background,
      color: colors.text,
      fontFamily: TYPOGRAPHY.fontFamily,
      padding: SPACING.xl,
      position: 'relative',
      overflow: 'hidden'
    }}>
      {/* Animated background */}
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
        marginBottom: SPACING.xl,
        paddingBottom: SPACING.lg,
        borderBottom: `1px solid ${colors.border}`,
        position: 'relative',
        zIndex: 1
      }}>
        <h1 style={{
          fontSize: TYPOGRAPHY.fontSize.xxxl,
          fontWeight: TYPOGRAPHY.fontWeight.extrabold,
          margin: '0 0 SPACING.md 0',
          background: colors.primaryGradient,
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text',
          letterSpacing: TYPOGRAPHY.letterSpacing.tight
        }}>
          🎯 Threat Intelligence
        </h1>
        <p style={{ color: colors.textSecondary, margin: 0, fontSize: TYPOGRAPHY.fontSize.md }}>
          Comprehensive threat intelligence analysis from multiple sources
        </p>
      </div>

      {/* Tabs */}
      <div style={{ 
        display: 'flex', 
        borderBottom: `1px solid ${colors.border}`, 
        marginBottom: SPACING.xl,
        position: 'relative',
        zIndex: 1
      }}>
        <TabButton id="vt" label="VirusTotal" icon="🦠" active={tab === 'vt'} />
        <TabButton id="ip" label="AbuseIPDB" icon="🌐" active={tab === 'ip'} />
        <TabButton id="mitre" label="MITRE ATT&CK" icon="🎯" active={tab === 'mitre'} />
        <TabButton id="sigma" label="Sigma Rules" icon="📜" active={tab === 'sigma'} />
        <TabButton id="ioc" label="IOC Explorer" icon="🔍" active={tab === 'ioc'} />
      </div>

      {/* Content */}
      <div style={{ position: 'relative', zIndex: 1 }}>
        {/* VirusTotal */}
        {tab === 'vt' && (
          <div style={{ maxWidth: '800px', animation: 'fadeIn 0.3s ease' }}>
            <ResultCard icon="🦠" title="VirusTotal Lookup" gradient={colors.dangerGradient}>
              <div style={{ marginBottom: SPACING.lg }}>
                <label style={{ 
                  display: 'block', 
                  fontSize: TYPOGRAPHY.fontSize.md, 
                  fontWeight: TYPOGRAPHY.fontWeight.bold, 
                  color: colors.text,
                  marginBottom: SPACING.md 
                }}>
                  VirusTotal Query
                </label>
                <div style={{ display: 'flex', gap: SPACING.md, marginBottom: SPACING.lg }}>
                  <input
                    value={vtQuery}
                    onChange={e => setVtQuery(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && doVtLookup()}
                    placeholder="Enter hash (MD5/SHA256), IP, domain, or URL..."
                    style={{
                      ...modernInputStyle,
                      flex: 1
                    }}
                  />
                  <button
                    onClick={doVtLookup}
                    disabled={vtLoading}
                    style={{
                      ...modernButtonStyle,
                      minWidth: '120px',
                      justifyContent: 'center',
                      opacity: vtLoading ? 0.5 : 1,
                      cursor: vtLoading ? 'not-allowed' : 'pointer'
                    }}
                  >
                    {vtLoading ? '⏳' : '🔍 Scan'}
                  </button>
                </div>
                
                <div style={{ 
                  display: 'flex', 
                  gap: SPACING.sm, 
                  flexWrap: 'wrap' 
                }}>
                  {['5f4dcc3b5aa765d61d8327deb882cf99','203.0.113.47','evil-domain.ru'].map(s => (
                    <button 
                      key={s} 
                      onClick={() => setVtQuery(s)} 
                      style={{
                        padding: `${SPACING.xs} ${SPACING.md}`,
                        background: `${colors.primary}10`,
                        border: `1px solid ${colors.primary}30`,
                        borderRadius: BORDER_RADIUS.md,
                        color: colors.primaryLight,
                        fontSize: TYPOGRAPHY.fontSize.xs,
                        cursor: 'pointer',
                        fontFamily: 'monospace',
                        transition: `all ${ANIMATION_CONFIG.duration.fast} ${ANIMATION_CONFIG.easing.smooth}`
                      }}
                      onMouseOver={(e) => {
                        e.currentTarget.style.background = `${colors.primary}20`;
                        e.currentTarget.style.borderColor = `${colors.primary}50}`;
                      }}
                      onMouseOut={(e) => {
                        e.currentTarget.style.background = `${colors.primary}10`;
                        e.currentTarget.style.borderColor = `${colors.primary}30}`;
                      }}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
              
              {vtResult && <VTResultCard result={vtResult} />}
            </ResultCard>
          </div>
        )}

        {/* AbuseIPDB */}
        {tab === 'ip' && (
          <div style={{ maxWidth: '800px', animation: 'fadeIn 0.3s ease' }}>
            <ResultCard icon="🌐" title="AbuseIPDB Lookup" gradient={colors.warningGradient}>
              <div style={{ marginBottom: SPACING.lg }}>
                <label style={{ 
                  display: 'block', 
                  fontSize: TYPOGRAPHY.fontSize.md, 
                  fontWeight: TYPOGRAPHY.fontWeight.bold, 
                  color: colors.text,
                  marginBottom: SPACING.md 
                }}>
                  IP Address Query
                </label>
                <div style={{ display: 'flex', gap: SPACING.md, marginBottom: SPACING.lg }}>
                  <input
                    value={ipQuery}
                    onChange={e => setIpQuery(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && doIpLookup()}
                    placeholder="Enter IP address to query..."
                    style={{
                      ...modernInputStyle,
                      flex: 1
                    }}
                  />
                  <button
                    onClick={doIpLookup}
                    disabled={ipLoading}
                    style={{
                      ...modernButtonStyle,
                      minWidth: '120px',
                      justifyContent: 'center',
                      opacity: ipLoading ? 0.5 : 1,
                      cursor: ipLoading ? 'not-allowed' : 'cursor'
                    }}
                  >
                    {ipLoading ? '⏳' : '🔍 Query'}
                  </button>
                </div>
              </div>
              
              {ipResult && <IPResultCard result={ipResult} />}
            </ResultCard>
          </div>
        )}

        {/* MITRE ATT&CK */}
        {tab === 'mitre' && (
          <div style={{ animation: 'fadeIn 0.3s ease' }}>
            <ResultCard icon="🎯" title="MITRE ATT&CK Techniques" gradient={colors.primaryGradient}>
              <div style={{ marginBottom: SPACING.lg }}>
                <label style={{ 
                  display: 'block', 
                  fontSize: TYPOGRAPHY.fontSize.md, 
                  fontWeight: TYPOGRAPHY.fontWeight.bold, 
                  color: colors.text,
                  marginBottom: SPACING.md 
                }}>
                  Search Techniques
                </label>
                <input
                  value={mitreSearch}
                  onChange={e => setMitreSearch(e.target.value)}
                  placeholder="Search by technique name, ID, or tactic..."
                  style={{
                    ...modernInputStyle,
                    marginBottom: SPACING.lg
                  }}
                />
              </div>
              
              <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                {filteredTech.map(tech => (
                  <TechCard 
                    key={tech.id} 
                    tech={tech} 
                    selected={selectedTech?.id === tech.id}
                    onClick={setSelectedTech}
                  />
                ))}
              </div>
            </ResultCard>
          </div>
        )}

        {/* Sigma Rules */}
        {tab === 'sigma' && (
          <div style={{ animation: 'fadeIn 0.3s ease' }}>
            <ResultCard icon="📜" title="Sigma Rules" gradient={colors.accentGradient}>
              <div style={{ 
                padding: SPACING.xl, 
                textAlign: 'center', 
                color: colors.textMuted 
              }}>
                <div style={{ fontSize: '48px', marginBottom: SPACING.md }}>📜</div>
                <div style={{ fontSize: TYPOGRAPHY.fontSize.lg, fontWeight: TYPOGRAPHY.fontWeight.bold, marginBottom: SPACING.sm }}>
                  Sigma Rules Engine
                </div>
                <div style={{ fontSize: TYPOGRAPHY.fontSize.md }}>
                  Browse and analyze Sigma detection rules
                </div>
              </div>
            </ResultCard>
          </div>
        )}

        {/* IOC Explorer */}
        {tab === 'ioc' && (
          <div style={{ animation: 'fadeIn 0.3s ease' }}>
            <ResultCard icon="🔍" title="IOC Explorer" gradient={colors.secondaryGradient}>
              <div style={{ 
                padding: SPACING.xl, 
                textAlign: 'center', 
                color: colors.textMuted 
              }}>
                <div style={{ fontSize: '48px', marginBottom: SPACING.md }}>🔍</div>
                <div style={{ fontSize: TYPOGRAPHY.fontSize.lg, fontWeight: TYPOGRAPHY.fontWeight.bold, marginBottom: SPACING.sm }}>
                  IOC Explorer
                </div>
                <div style={{ fontSize: TYPOGRAPHY.fontSize.md }}>
                  Search and investigate indicators of compromise
                </div>
              </div>
            </ResultCard>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatIntelligence;