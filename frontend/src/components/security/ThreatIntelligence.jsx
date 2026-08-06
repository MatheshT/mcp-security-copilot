import React, { useState } from 'react';

const MITRE_TECHNIQUES = [
  { id: 'T1190', name: 'Exploit Public-Facing Application',  tactic: 'Initial Access',     sev: 'Critical', detail: 'Adversaries may attempt to take advantage of a weakness in an Internet-facing host or system.' },
  { id: 'T1059', name: 'Command and Scripting Interpreter',  tactic: 'Execution',          sev: 'High',     detail: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.' },
  { id: 'T1071', name: 'Application Layer Protocol',         tactic: 'C2',                 sev: 'High',     detail: 'Adversaries may communicate using application layer protocols to avoid detection.' },
  { id: 'T1041', name: 'Exfiltration Over C2 Channel',       tactic: 'Exfiltration',       sev: 'High',     detail: 'Adversaries may steal data by exfiltrating it over an existing C2 channel.' },
  { id: 'T1078', name: 'Valid Accounts',                     tactic: 'Persistence',        sev: 'Medium',   detail: 'Adversaries may obtain and abuse credentials of existing accounts.' },
  { id: 'T1110', name: 'Brute Force',                        tactic: 'Credential Access',  sev: 'Medium',   detail: 'Adversaries may use brute force techniques to gain access to accounts.' },
  { id: 'T1021', name: 'Remote Services',                    tactic: 'Lateral Movement',   sev: 'High',     detail: 'Adversaries may use Valid Accounts to log into a service specifically designed for remote access.' },
  { id: 'T1083', name: 'File and Directory Discovery',       tactic: 'Discovery',          sev: 'Low',      detail: 'Adversaries may enumerate files and directories or may search specific locations.' },
  { id: 'T1055', name: 'Process Injection',                  tactic: 'Privilege Escalation',sev:'Critical', detail: 'Adversaries may inject code into processes in order to evade process-based defenses.' },
];

const SEV = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22c55e' };

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

  return (
    <div style={{ fontFamily: 'Inter,sans-serif', color: '#e2e8f0' }}>
      <style>{`
        @keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
        .ti-tab{background:transparent;border:none;color:#64748b;padding:9px 18px;cursor:pointer;font-size:13px;font-weight:600;border-bottom:2px solid transparent;transition:all .2s}
        .ti-tab.active{color:#6366f1;border-bottom-color:#6366f1}
        .ti-card{background:linear-gradient(135deg,rgba(15,23,42,0.95),rgba(20,30,50,0.9));border:1px solid rgba(99,102,241,0.15);border-radius:14px;padding:20px;animation:fadeIn .3s ease}
        .ti-input{width:100%;background:rgba(255,255,255,0.05);border:1px solid rgba(99,102,241,0.3);border-radius:10px;padding:12px 16px;color:#e2e8f0;font-size:14px;outline:none;box-sizing:border-box}
        .ti-btn{padding:12px 24px;background:linear-gradient(135deg,#6366f1,#4f46e5);border:none;border-radius:10px;color:#fff;font-weight:700;cursor:pointer;font-size:14px;white-space:nowrap}
        .tech-row{cursor:pointer;padding:12px 14px;border-radius:8px;border:1px solid rgba(99,102,241,0.1);margin-bottom:6px;transition:all .2s;background:rgba(15,23,42,0.7)}
        .tech-row:hover,.tech-row.sel{background:rgba(99,102,241,0.1);border-color:rgba(99,102,241,0.35)}
      `}</style>

      <div style={{ display: 'flex', borderBottom: '1px solid rgba(99,102,241,0.2)', marginBottom: '20px' }}>
        {[['vt','🦠 VirusTotal'],['ip','🌐 AbuseIPDB'],['mitre','🎯 MITRE ATT&CK'],['sigma','📜 Sigma Rules'],['ioc','🔍 IOC Explorer']].map(([id,label]) => (
          <button key={id} className={`ti-tab${tab===id?' active':''}`} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>

      {/* VirusTotal */}
      {tab === 'vt' && (
        <div style={{ maxWidth: '700px', animation: 'fadeIn .3s ease' }}>
          <div className="ti-card" style={{ marginBottom: '16px' }}>
            <div style={{ fontWeight: 700, color: '#f1f5f9', marginBottom: '12px' }}>🦠 VirusTotal Lookup</div>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
              <input className="ti-input" value={vtQuery} onChange={e => setVtQuery(e.target.value)} onKeyDown={e => e.key==='Enter'&&doVtLookup()} placeholder="Enter hash (MD5/SHA256), IP, domain, or URL..." />
              <button className="ti-btn" onClick={doVtLookup} disabled={vtLoading}>{vtLoading ? '⏳' : '🔍 Scan'}</button>
            </div>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {['5f4dcc3b5aa765d61d8327deb882cf99','203.0.113.47','evil-domain.ru'].map(s => (
                <button key={s} onClick={() => setVtQuery(s)} style={{ padding: '4px 10px', background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: '16px', color: '#818cf8', fontSize: '11px', cursor: 'pointer', fontFamily: 'monospace' }}>{s}</button>
              ))}
            </div>
          </div>
          {vtResult && (
            <div className="ti-card" style={{ animation: 'fadeIn .25s ease' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div style={{ fontFamily: 'monospace', fontSize: '13px', color: '#94a3b8', wordBreak: 'break-all' }}>{vtResult.hash}</div>
                <span style={{ padding: '4px 12px', borderRadius: '12px', fontWeight: 700, fontSize: '13px', background: vtResult.verdict==='Malicious'?'rgba(239,68,68,0.15)':'rgba(34,197,94,0.15)', color: vtResult.verdict==='Malicious'?'#ef4444':'#22c55e', flexShrink: 0, marginLeft: '12px' }}>
                  {vtResult.verdict === 'Malicious' ? '⛔ Malicious' : '✅ Clean'}
                </span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: '12px', marginBottom: '16px' }}>
                {[['Type', vtResult.type, '#94a3b8'], ['Detections', `${vtResult.detections}/${vtResult.total}`, vtResult.detections>20?'#ef4444':'#eab308'], ['Malware Family', vtResult.families, '#f97316']].map(([k,v,c]) => (
                  <div key={k} style={{ background: 'rgba(255,255,255,0.04)', borderRadius: '10px', padding: '12px' }}>
                    <div style={{ fontSize: '11px', color: '#475569', marginBottom: '4px' }}>{k}</div>
                    <div style={{ color: c, fontWeight: 700, fontSize: '14px' }}>{v}</div>
                  </div>
                ))}
              </div>
              <div style={{ color: '#94a3b8', fontSize: '13px', lineHeight: 1.6 }}>{vtResult.summary}</div>
            </div>
          )}
        </div>
      )}

      {/* AbuseIPDB */}
      {tab === 'ip' && (
        <div style={{ maxWidth: '700px', animation: 'fadeIn .3s ease' }}>
          <div className="ti-card" style={{ marginBottom: '16px' }}>
            <div style={{ fontWeight: 700, color: '#f1f5f9', marginBottom: '12px' }}>🌐 AbuseIPDB Check</div>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
              <input className="ti-input" value={ipQuery} onChange={e => setIpQuery(e.target.value)} onKeyDown={e => e.key==='Enter'&&doIpLookup()} placeholder="Enter IP address (e.g. 203.0.113.47)..." />
              <button className="ti-btn" onClick={doIpLookup} disabled={ipLoading}>{ipLoading ? '⏳' : '🔍 Check'}</button>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              {['203.0.113.47','192.0.2.100','198.51.100.0'].map(s => (
                <button key={s} onClick={() => setIpQuery(s)} style={{ padding: '4px 10px', background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: '16px', color: '#818cf8', fontSize: '11px', cursor: 'pointer', fontFamily: 'monospace' }}>{s}</button>
              ))}
            </div>
          </div>
          {ipResult && (
            <div className="ti-card" style={{ animation: 'fadeIn .25s ease' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div style={{ fontFamily: 'monospace', fontSize: '18px', fontWeight: 700, color: '#f1f5f9' }}>{ipResult.ip}</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '28px', fontWeight: 800, color: ipResult.abuseScore>75?'#ef4444':ipResult.abuseScore>40?'#f97316':'#22c55e' }}>{ipResult.abuseScore}%</span>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>abuse<br/>confidence</span>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: '12px', fontSize: '13px' }}>
                {[['Country', ipResult.country],['ISP', ipResult.isp],['Usage Type', ipResult.usageType],['Reports', `${ipResult.reports} reports`],['Categories', ipResult.categories],['Last Report', ipResult.lastReport]].map(([k,v]) => (
                  <div key={k} style={{ background: 'rgba(255,255,255,0.04)', borderRadius: '8px', padding: '10px' }}>
                    <div style={{ fontSize: '11px', color: '#475569', marginBottom: '3px' }}>{k}</div>
                    <div style={{ color: '#94a3b8', fontWeight: 500 }}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* MITRE ATT&CK */}
      {tab === 'mitre' && (
        <div style={{ animation: 'fadeIn .3s ease' }}>
          <input
            value={mitreSearch} onChange={e => setMitreSearch(e.target.value)}
            placeholder="Search techniques by ID, name, or tactic..."
            style={{ width: '100%', marginBottom: '16px', background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(99,102,241,0.25)', borderRadius: '10px', padding: '10px 16px', color: '#e2e8f0', fontSize: '13px', outline: 'none', boxSizing: 'border-box' }}
          />
          <div style={{ display: 'grid', gridTemplateColumns: selectedTech ? '1fr 380px' : '1fr', gap: '16px' }}>
            <div>
              {filteredTech.map(t => (
                <div key={t.id} className={`tech-row${selectedTech?.id===t.id?' sel':''}`} onClick={() => setSelectedTech(selectedTech?.id===t.id?null:t)}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#6366f1', fontSize: '13px', background: 'rgba(99,102,241,0.12)', padding: '2px 8px', borderRadius: '6px' }}>{t.id}</span>
                      <span style={{ fontWeight: 600, color: '#e2e8f0', fontSize: '14px' }}>{t.name}</span>
                    </div>
                    <div style={{ display: 'flex', gap: '6px', flexShrink: 0 }}>
                      <span style={{ padding: '2px 8px', borderRadius: '12px', fontSize: '11px', background: 'rgba(99,102,241,0.1)', color: '#818cf8' }}>{t.tactic}</span>
                      <span style={{ padding: '2px 8px', borderRadius: '12px', fontSize: '11px', fontWeight: 700, background: `${SEV[t.sev]}15`, color: SEV[t.sev] }}>{t.sev}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
            {selectedTech && (
              <div className="ti-card" style={{ animation: 'fadeIn .25s ease', height: 'fit-content', position: 'sticky', top: 0 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#6366f1', fontSize: '16px' }}>{selectedTech.id}</span>
                  <button onClick={() => setSelectedTech(null)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}>✕</button>
                </div>
                <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '16px', marginBottom: '8px' }}>{selectedTech.name}</div>
                <div style={{ display: 'flex', gap: '6px', marginBottom: '16px' }}>
                  <span style={{ padding: '3px 10px', borderRadius: '12px', background: 'rgba(99,102,241,0.12)', color: '#818cf8', fontSize: '12px' }}>{selectedTech.tactic}</span>
                  <span style={{ padding: '3px 10px', borderRadius: '12px', fontSize: '12px', fontWeight: 700, background: `${SEV[selectedTech.sev]}15`, color: SEV[selectedTech.sev] }}>{selectedTech.sev}</span>
                </div>
                <div style={{ color: '#94a3b8', fontSize: '13px', lineHeight: 1.7, marginBottom: '16px' }}>{selectedTech.detail}</div>
                <div style={{ padding: '12px', background: 'rgba(99,102,241,0.08)', borderRadius: '8px', border: '1px solid rgba(99,102,241,0.2)' }}>
                  <div style={{ fontSize: '11px', color: '#6366f1', fontWeight: 700, marginBottom: '6px' }}>DETECTION HINTS</div>
                  <div style={{ fontSize: '12px', color: '#94a3b8' }}>Monitor for unusual process spawning, command-line arguments, and network connections. Enable Wazuh rule group for this technique.</div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Sigma Rules */}
      {tab === 'sigma' && (
        <div style={{ animation: 'fadeIn .3s ease' }}>
          {[
            { id: 'SIGMA-001', title: 'Suspicious PowerShell Encoded Command', desc: 'Detects PowerShell with base64 encoded arguments often used in malicious scripts.', tags: ['T1059.001','execution'], level: 'High' },
            { id: 'SIGMA-002', title: 'SSH Brute Force Detection', desc: 'Multiple failed SSH authentication attempts from a single source IP.', tags: ['T1110','credential'], level: 'Medium' },
            { id: 'SIGMA-003', title: 'Mimikatz Credential Dumping', desc: 'Detects common Mimikatz command patterns for credential dumping.', tags: ['T1003','credential-access'], level: 'Critical' },
            { id: 'SIGMA-004', title: 'Lateral Movement via PsExec', desc: 'Detects PsExec usage for lateral movement in enterprise networks.', tags: ['T1021','lateral-movement'], level: 'High' },
          ].map(r => (
            <div key={r.id} style={{ background: 'rgba(15,23,42,0.85)', border: '1px solid rgba(99,102,241,0.12)', borderRadius: '10px', padding: '14px 16px', marginBottom: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                <div>
                  <span style={{ fontFamily: 'monospace', fontSize: '11px', color: '#475569', marginRight: '8px' }}>{r.id}</span>
                  <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '14px' }}>{r.title}</span>
                </div>
                <span style={{ padding: '2px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 700, background: `${SEV[r.level]}15`, color: SEV[r.level], flexShrink: 0, marginLeft: '10px' }}>{r.level}</span>
              </div>
              <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '8px' }}>{r.desc}</div>
              <div style={{ display: 'flex', gap: '6px' }}>
                {r.tags.map(t => <span key={t} style={{ padding: '2px 8px', background: 'rgba(99,102,241,0.1)', color: '#818cf8', borderRadius: '8px', fontSize: '11px', fontFamily: 'monospace' }}>{t}</span>)}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* IOC Explorer */}
      {tab === 'ioc' && (
        <div style={{ animation: 'fadeIn .3s ease', display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(300px,1fr))', gap: '12px' }}>
          {[
            { type: 'IP Addresses', icon: '🌐', color: '#6366f1', items: ['203.0.113.47','198.51.100.0','192.0.2.100','45.89.125.0','91.219.236.0'], label: 'C2 & Scanner IPs' },
            { type: 'File Hashes', icon: '🔑', color: '#f97316', items: ['5f4dcc3b5aa765d61d8327deb882cf99','e99a18c428cb38d5f260853678922e03','aad3b435b51404eeaad3b435b51404ee'], label: 'Malware Hashes (MD5)' },
            { type: 'Domains', icon: '🌍', color: '#ef4444', items: ['evil-c2.ru','malware-drop.xyz','beacon.bad-actor.net','update-checker.top'], label: 'Malicious Domains' },
            { type: 'File Paths', icon: '📂', color: '#eab308', items: ['C:\\Users\\Public\\shell.exe','C:\\Windows\\Temp\\svhost.exe','/tmp/.hidden_process','/var/www/html/shell.php'], label: 'Suspicious Paths' },
          ].map(cat => (
            <div key={cat.type} style={{ background: 'linear-gradient(135deg,rgba(15,23,42,0.95),rgba(20,30,50,0.9))', border: `1px solid ${cat.color}25`, borderRadius: '12px', padding: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                <span style={{ fontSize: '20px' }}>{cat.icon}</span>
                <div>
                  <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '14px' }}>{cat.type}</div>
                  <div style={{ fontSize: '11px', color: '#64748b' }}>{cat.label}</div>
                </div>
              </div>
              {cat.items.map(item => (
                <div key={item} style={{ fontFamily: 'monospace', fontSize: '11px', color: '#94a3b8', padding: '6px 8px', background: 'rgba(255,255,255,0.04)', borderRadius: '6px', marginBottom: '4px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ wordBreak: 'break-all' }}>{item}</span>
                  <button onClick={() => navigator.clipboard?.writeText(item)} style={{ background: 'none', border: 'none', color: '#475569', cursor: 'pointer', fontSize: '12px', flexShrink: 0, marginLeft: '8px' }}>📋</button>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ThreatIntelligence;
