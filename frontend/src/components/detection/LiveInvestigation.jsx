import React, { useState, useEffect, useRef } from 'react';

const SAMPLE_EVENTS = [
  { id: 1,  time: new Date(Date.now()-2*60000).toISOString(),  type: 'Alert Triggered',     icon: '🚨', color: '#ef4444', detail: 'SSH Brute Force on web-server-01 — Level 12 Critical',             agent: 'web-server-01' },
  { id: 2,  time: new Date(Date.now()-5*60000).toISOString(),  type: 'AI Analysis',         icon: '🧠', color: '#6366f1', detail: 'Correlating 4 events: SSH + Lateral + Escalation pattern',          agent: 'AI Engine' },
  { id: 3,  time: new Date(Date.now()-7*60000).toISOString(),  type: 'IOC Matched',         icon: '🎯', color: '#f97316', detail: 'IP 203.0.113.47 matches ThreatFox feed (Cobalt Strike C2)',         agent: 'ThreatIntel' },
  { id: 4,  time: new Date(Date.now()-9*60000).toISOString(),  type: 'Process Anomaly',     icon: '⚙️', color: '#eab308', detail: 'cmd.exe child of iisexpress.exe — WebShell behavior',               agent: 'web-server-01' },
  { id: 5,  time: new Date(Date.now()-12*60000).toISOString(), type: 'File Change',         icon: '📂', color: '#eab308', detail: '/var/www/html/shell.php created (size: 4.2KB)',                      agent: 'web-server-01' },
  { id: 6,  time: new Date(Date.now()-14*60000).toISOString(), type: 'Network Event',       icon: '🌐', color: '#22c55e', detail: 'Outbound HTTPS to 198.51.100.0:443 — 3.7MB transferred',             agent: 'workstation-08' },
  { id: 7,  time: new Date(Date.now()-18*60000).toISOString(), type: 'MITRE Mapped',        icon: '🗺️', color: '#a855f7', detail: 'T1190 Exploit Public-Facing App → T1059 Command Interpreter',        agent: 'AI Engine' },
  { id: 8,  time: new Date(Date.now()-21*60000).toISOString(), type: 'Containment Action', icon: '🔒', color: '#06b6d4', detail: 'Auto-blocked IP 203.0.113.47 via firewall rule #AF-2024-001',         agent: 'AutoResponse' },
];

const SAMPLE_CASES = [
  { id: 'INV-2024-0892', title: 'Web Server Compromise Chain',   severity: 'Critical', status: 'Active',   events: 12, started: '2h ago',  analyst: 'AI + Human' },
  { id: 'INV-2024-0891', title: 'Insider Threat — HR Dept',      severity: 'High',     status: 'Review',   events: 7,  started: '5h ago',  analyst: 'AI Auto' },
  { id: 'INV-2024-0890', title: 'Ransomware Pre-Stage Detected', severity: 'Critical', status: 'Closed',   events: 23, started: '1d ago',  analyst: 'Team SOC-2' },
  { id: 'INV-2024-0889', title: 'C2 Beacon — Workstation-08',    severity: 'High',     status: 'Active',   events: 9,  started: '3h ago',  analyst: 'AI Auto' },
  { id: 'INV-2024-0888', title: 'Port Scan — External',          severity: 'Low',      status: 'Resolved', events: 3,  started: '2d ago',  analyst: 'AI Auto' },
];

const SEV = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22c55e' };
const STAT_CLR = { Active: '#6366f1', Review: '#eab308', Closed: '#64748b', Resolved: '#22c55e' };

const timeSince = iso => {
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)  return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  return `${Math.floor(s/3600)}h ago`;
};

const LiveInvestigation = () => {
  const [query, setQuery]           = useState('');
  const [loading, setLoading]       = useState(false);
  const [result, setResult]         = useState(null);
  const [events, setEvents]         = useState(SAMPLE_EVENTS);
  const [activeCase, setActiveCase] = useState(SAMPLE_CASES[0]);
  const [tab, setTab]               = useState('live');
  const feedRef                     = useRef(null);

  // Simulate live events
  useEffect(() => {
    const rules = ['Network Scan', 'Auth Failure', 'File Access', 'DNS Query', 'Process Fork'];
    const agents = ['web-server-01', 'dc-01', 'db-server-01', 'workstation-08'];
    const timer = setInterval(() => {
      const rule = rules[Math.floor(Math.random() * rules.length)];
      const agent = agents[Math.floor(Math.random() * agents.length)];
      setEvents(prev => [{
        id: Date.now(),
        time: new Date().toISOString(),
        type: 'Live Event',
        icon: '📡',
        color: '#06b6d4',
        detail: `${rule} detected on ${agent}`,
        agent,
      }, ...prev.slice(0, 30)]);
    }, 8000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = 0;
  }, [events]);

  const handleInvestigate = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch('/api/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
      });
      const data = await res.json();
      setResult(data);
    } catch {
      setResult({ ai_answer: '⚠️ Backend unreachable. Showing demo response.', intent: 'threat_analysis', query_type: 'ioc_lookup', required_tools: ['wazuh', 'virustotal'], report_json: { severity: 'High', investigation_summary: `Analysis for: "${query}". Correlating with live event data from Wazuh agents. Multiple IOC matches found in ThreatFox database. MITRE ATT&CK mapping: T1190 → T1059 → T1071.`, recommendation: 'Isolate affected host, collect memory dump, and escalate to Tier-2.' } });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ fontFamily: 'Inter,sans-serif', color: '#e2e8f0' }}>
      <style>{`
        @keyframes fadeInUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
        @keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
        .inv-tab{background:transparent;border:none;color:#64748b;padding:9px 18px;cursor:pointer;font-size:13px;font-weight:600;border-bottom:2px solid transparent;transition:all .2s}
        .inv-tab.active{color:#6366f1;border-bottom-color:#6366f1}
        .inv-card{background:linear-gradient(135deg,rgba(15,23,42,0.95),rgba(20,30,50,0.9));border:1px solid rgba(99,102,241,0.15);border-radius:14px;padding:20px;animation:fadeInUp .3s ease}
        .case-row{cursor:pointer;padding:12px 16px;border-radius:10px;border:1px solid rgba(99,102,241,0.1);margin-bottom:8px;transition:all .2s}
        .case-row:hover,.case-row.sel{background:rgba(99,102,241,0.1);border-color:rgba(99,102,241,0.35)}
      `}</style>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid rgba(99,102,241,0.2)', marginBottom: '20px' }}>
        {[['live','🔴 Live Feed'],['cases','📁 Cases'],['query','🧠 AI Query']].map(([id,label]) => (
          <button key={id} className={`inv-tab${tab===id?' active':''}`} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>

      {/* Live Feed */}
      {tab === 'live' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 360px', gap: '16px' }}>
          <div className="inv-card" style={{ padding: '0', overflow: 'hidden' }}>
            <div style={{ padding: '14px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ef4444', display: 'inline-block', animation: 'blink 1s infinite' }} />
              <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '14px' }}>Live Event Stream</span>
              <span style={{ marginLeft: 'auto', fontSize: '12px', color: '#64748b' }}>{events.length} events</span>
            </div>
            <div ref={feedRef} style={{ maxHeight: 'calc(100vh - 340px)', overflowY: 'auto', padding: '8px 0' }}>
              {events.map((ev, i) => (
                <div key={ev.id} style={{ padding: '10px 20px', borderBottom: '1px solid rgba(255,255,255,0.04)', display: 'flex', gap: '12px', alignItems: 'flex-start', opacity: i === 0 ? 1 : 0.85 }}>
                  <span style={{ fontSize: '18px', flexShrink: 0, marginTop: '1px' }}>{ev.icon}</span>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '12px', fontWeight: 700, color: ev.color }}>{ev.type}</span>
                      <span style={{ fontSize: '11px', color: '#475569' }}>{timeSince(ev.time)}</span>
                    </div>
                    <div style={{ fontSize: '13px', color: '#cbd5e1', marginTop: '2px' }}>{ev.detail}</div>
                    <div style={{ fontSize: '11px', color: '#475569', marginTop: '2px' }}>Agent: <span style={{ color: '#818cf8' }}>{ev.agent}</span></div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Active case panel */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div className="inv-card">
              <div style={{ fontSize: '11px', color: '#475569', fontWeight: 700, letterSpacing: '.06em', marginBottom: '10px' }}>ACTIVE CASE</div>
              <div style={{ color: '#f1f5f9', fontWeight: 700, fontSize: '15px', marginBottom: '8px' }}>{activeCase.title}</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '12px' }}>
                {[['Severity', activeCase.severity, SEV[activeCase.severity]], ['Status', activeCase.status, STAT_CLR[activeCase.status]], ['Events', activeCase.events, '#6366f1'], ['Started', activeCase.started, '#64748b']].map(([k,v,c]) => (
                  <div key={k}>
                    <div style={{ color: '#475569', marginBottom: '2px' }}>{k}</div>
                    <div style={{ color: c, fontWeight: 700 }}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
            <div className="inv-card">
              <div style={{ fontSize: '11px', color: '#475569', fontWeight: 700, letterSpacing: '.06em', marginBottom: '10px' }}>MITRE ATT&CK</div>
              {[['T1190','Exploit Public-Facing App'],['T1059','Command Interpreter'],['T1071','App Layer Protocol'],['T1041','Exfiltration over C2']].map(([id,name]) => (
                <div key={id} style={{ display: 'flex', gap: '10px', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <span style={{ background: 'rgba(99,102,241,0.15)', color: '#818cf8', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'monospace', fontWeight: 700 }}>{id}</span>
                  <span style={{ fontSize: '12px', color: '#94a3b8' }}>{name}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Cases */}
      {tab === 'cases' && (
        <div style={{ animation: 'fadeInUp .3s ease' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '15px' }}>Investigation Cases</div>
            <span style={{ fontSize: '12px', color: '#64748b', background: 'rgba(99,102,241,0.1)', padding: '4px 12px', borderRadius: '20px' }}>{SAMPLE_CASES.length} total</span>
          </div>
          {SAMPLE_CASES.map(c => (
            <div key={c.id} className={`case-row${activeCase?.id===c.id?' sel':''}`} onClick={() => setActiveCase(c)}
              style={{ background: 'rgba(15,23,42,0.8)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontFamily: 'monospace', fontSize: '11px', color: '#475569', marginBottom: '4px' }}>{c.id}</div>
                  <div style={{ fontWeight: 600, color: '#e2e8f0', fontSize: '14px' }}>{c.title}</div>
                </div>
                <span style={{ padding: '3px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 700, background: `${STAT_CLR[c.status]}20`, color: STAT_CLR[c.status] }}>{c.status}</span>
              </div>
              <div style={{ display: 'flex', gap: '16px', marginTop: '8px', fontSize: '12px', color: '#64748b' }}>
                <span>Severity: <span style={{ color: SEV[c.severity], fontWeight: 700 }}>{c.severity}</span></span>
                <span>Events: <span style={{ color: '#94a3b8' }}>{c.events}</span></span>
                <span>Started: {c.started}</span>
                <span>Analyst: <span style={{ color: '#818cf8' }}>{c.analyst}</span></span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* AI Query */}
      {tab === 'query' && (
        <div style={{ animation: 'fadeInUp .3s ease', maxWidth: '800px' }}>
          <div className="inv-card" style={{ marginBottom: '16px' }}>
            <div style={{ fontWeight: 700, color: '#f1f5f9', marginBottom: '12px', fontSize: '15px' }}>🧠 AI Security Investigation</div>
            <div style={{ display: 'flex', gap: '10px' }}>
              <input
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleInvestigate()}
                placeholder="e.g. Investigate SSH brute force on web-server-01..."
                style={{ flex: 1, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(99,102,241,0.3)', borderRadius: '10px', padding: '12px 16px', color: '#e2e8f0', fontSize: '14px', outline: 'none' }}
              />
              <button
                onClick={handleInvestigate}
                disabled={loading || !query.trim()}
                style={{ padding: '12px 24px', background: loading ? 'rgba(99,102,241,0.4)' : 'linear-gradient(135deg,#6366f1,#4f46e5)', border: 'none', borderRadius: '10px', color: '#fff', fontWeight: 700, cursor: loading ? 'wait' : 'pointer', fontSize: '14px', whiteSpace: 'nowrap' }}
              >
                {loading ? '⏳ Analyzing...' : '🚀 Investigate'}
              </button>
            </div>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '12px' }}>
              {['SSH brute force on web-server-01','Analyze IP 203.0.113.47','Hunt for lateral movement','Check CVE-2024-1234'].map(s => (
                <button key={s} onClick={() => setQuery(s)} style={{ padding: '5px 12px', background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: '20px', color: '#818cf8', fontSize: '12px', cursor: 'pointer' }}>{s}</button>
              ))}
            </div>
          </div>

          {result && (
            <div className="inv-card" style={{ animation: 'fadeInUp .3s ease' }}>
              {result.ai_answer && (
                <div style={{ marginBottom: '16px' }}>
                  <div style={{ fontSize: '11px', color: '#6366f1', fontWeight: 700, letterSpacing: '.06em', marginBottom: '8px' }}>AI ANALYSIS</div>
                  <div style={{ color: '#cbd5e1', lineHeight: 1.7, fontSize: '14px' }}>{result.ai_answer}</div>
                </div>
              )}
              {result.report_json && (
                <>
                  {result.report_json.severity && (
                    <div style={{ display: 'inline-block', padding: '4px 12px', borderRadius: '20px', background: `${SEV[result.report_json.severity] || '#6366f1'}20`, color: SEV[result.report_json.severity] || '#6366f1', fontWeight: 700, fontSize: '12px', marginBottom: '12px' }}>
                      Severity: {result.report_json.severity}
                    </div>
                  )}
                  {result.report_json.investigation_summary && (
                    <div style={{ marginBottom: '12px' }}>
                      <div style={{ fontSize: '11px', color: '#475569', fontWeight: 700, letterSpacing: '.06em', marginBottom: '6px' }}>INVESTIGATION SUMMARY</div>
                      <div style={{ color: '#94a3b8', fontSize: '13px', lineHeight: 1.6 }}>{result.report_json.investigation_summary}</div>
                    </div>
                  )}
                  {result.report_json.recommendation && (
                    <div style={{ padding: '12px', background: 'rgba(99,102,241,0.08)', borderRadius: '8px', border: '1px solid rgba(99,102,241,0.2)' }}>
                      <div style={{ fontSize: '11px', color: '#6366f1', fontWeight: 700, letterSpacing: '.06em', marginBottom: '6px' }}>RECOMMENDATION</div>
                      <div style={{ color: '#94a3b8', fontSize: '13px', lineHeight: 1.6 }}>{result.report_json.recommendation}</div>
                    </div>
                  )}
                </>
              )}
              {result.required_tools?.length > 0 && (
                <div style={{ marginTop: '12px', display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '11px', color: '#475569' }}>Tools used:</span>
                  {result.required_tools.map(t => (
                    <span key={t} style={{ padding: '2px 8px', background: 'rgba(99,102,241,0.1)', color: '#818cf8', borderRadius: '12px', fontSize: '11px', fontFamily: 'monospace' }}>{t}</span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default LiveInvestigation;
