import React, { useState, useEffect } from 'react';

/* ─── Mock data ─── */
const HISTORY = [
  { id: 'INV-2024-0892', title: 'Web Server Compromise Chain',       severity: 'Critical', status: 'Active',   started: '2024-01-15 08:12', analyst: 'AI + SOC-1', tools: ['wazuh','virustotal','mitre'], summary: 'Multi-stage attack via CVE-2024-1234. Webshell installed, C2 contact established. Blocked at firewall.' },
  { id: 'INV-2024-0891', title: 'Insider Threat — HR Department',     severity: 'High',     status: 'Review',   started: '2024-01-15 05:31', analyst: 'AI Auto',    tools: ['wazuh','windows-logs'],     summary: 'HR employee accessed 1,400 records outside working hours. Data exfil to personal cloud detected.' },
  { id: 'INV-2024-0890', title: 'Ransomware Pre-Stage Detected',      severity: 'Critical', status: 'Resolved', started: '2024-01-14 14:20', analyst: 'SOC Team 2', tools: ['wazuh','mitre'],             summary: 'Ryuk precursor activity. Shadow copies deleted. Containment successful before encryption started.' },
  { id: 'INV-2024-0889', title: 'C2 Beacon from Workstation-08',      severity: 'High',     status: 'Active',   started: '2024-01-15 07:42', analyst: 'AI Auto',    tools: ['virustotal','shodan'],       summary: 'Periodic HTTPS beacon to 198.51.100.0 every 60s. Cobalt Strike profile identified.' },
  { id: 'INV-2024-0888', title: 'External Port Scan Campaign',        severity: 'Low',      status: 'Resolved', started: '2024-01-13 22:10', analyst: 'AI Auto',    tools: ['abuseipdb'],                 summary: 'Systematic SYN scan from 192.0.2.0/24. No successful intrusions. Blocked at perimeter.' },
  { id: 'INV-2024-0887', title: 'Suspicious PowerShell Execution',    severity: 'High',     status: 'Closed',   started: '2024-01-12 11:55', analyst: 'AI + SOC-2', tools: ['wazuh','windows-logs'],     summary: 'Encoded PS command from Word macro. Fileless payload. Endpoint isolated, re-imaged.' },
];

const SEV = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22c55e' };
const STAT = { Active: '#6366f1', Review: '#eab308', Resolved: '#22c55e', Closed: '#64748b' };

const InvestigationHistory = () => {
  const [search, setSearch]   = useState('');
  const [sevF, setSevF]       = useState('all');
  const [statF, setStatF]     = useState('all');
  const [selected, setSelected] = useState(null);

  const filtered = HISTORY.filter(h =>
    (sevF  === 'all' || h.severity === sevF) &&
    (statF === 'all' || h.status === statF) &&
    (h.title.toLowerCase().includes(search.toLowerCase()) || h.id.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div style={{ fontFamily: 'Inter,sans-serif', color: '#e2e8f0' }}>
      <style>{`
        @keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
        .hist-row{cursor:pointer;padding:14px 16px;border-radius:10px;border:1px solid rgba(99,102,241,0.1);margin-bottom:8px;background:rgba(15,23,42,0.8);transition:all .2s;animation:fadeIn .3s ease}
        .hist-row:hover,.hist-row.sel{background:rgba(99,102,241,0.1);border-color:rgba(99,102,241,0.35)}
        .filt{background:rgba(15,23,42,0.8);border:1px solid rgba(99,102,241,0.25);border-radius:8px;padding:8px 12px;color:#e2e8f0;font-size:13px;cursor:pointer;outline:none}
      `}</style>

      <div style={{ display: 'flex', gap: '10px', marginBottom: '20px', flexWrap: 'wrap' }}>
        <input
          value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search investigations..."
          style={{ flex: 1, minWidth: '200px', background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(99,102,241,0.25)', borderRadius: '10px', padding: '10px 16px', color: '#e2e8f0', fontSize: '13px', outline: 'none' }}
        />
        <select value={sevF} onChange={e => setSevF(e.target.value)} className="filt">
          <option value="all">All Severities</option>
          {['Critical','High','Medium','Low'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={statF} onChange={e => setStatF(e.target.value)} className="filt">
          <option value="all">All Statuses</option>
          {['Active','Review','Resolved','Closed'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <span style={{ padding: '10px 14px', background: 'rgba(99,102,241,0.1)', borderRadius: '10px', fontSize: '13px', color: '#818cf8', display: 'flex', alignItems: 'center' }}>
          {filtered.length} results
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 380px' : '1fr', gap: '16px' }}>
        <div>
          {filtered.length === 0 && <div style={{ textAlign: 'center', color: '#475569', padding: '40px' }}>No investigations match your filters.</div>}
          {filtered.map(h => (
            <div key={h.id} className={`hist-row${selected?.id===h.id?' sel':''}`} onClick={() => setSelected(selected?.id===h.id ? null : h)}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontFamily: 'monospace', fontSize: '11px', color: '#475569', marginBottom: '4px' }}>{h.id}</div>
                  <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '14px', marginBottom: '6px' }}>{h.title}</div>
                  <div style={{ fontSize: '12px', color: '#64748b', lineHeight: 1.5 }}>{h.summary.slice(0, 100)}…</div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', alignItems: 'flex-end', marginLeft: '16px' }}>
                  <span style={{ padding: '3px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 700, background: `${SEV[h.severity]}20`, color: SEV[h.severity] }}>{h.severity}</span>
                  <span style={{ padding: '3px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 700, background: `${STAT[h.status]}20`, color: STAT[h.status] }}>{h.status}</span>
                </div>
              </div>
              <div style={{ display: 'flex', gap: '16px', marginTop: '10px', fontSize: '11px', color: '#475569' }}>
                <span>Started: <span style={{ color: '#94a3b8' }}>{h.started}</span></span>
                <span>Analyst: <span style={{ color: '#818cf8' }}>{h.analyst}</span></span>
                <span>Tools: {h.tools.map(t => <span key={t} style={{ marginLeft: '4px', padding: '1px 6px', background: 'rgba(99,102,241,0.1)', color: '#818cf8', borderRadius: '8px', fontFamily: 'monospace' }}>{t}</span>)}</span>
              </div>
            </div>
          ))}
        </div>

        {selected && (
          <div style={{ background: 'linear-gradient(135deg,rgba(15,23,42,0.95),rgba(20,30,50,0.9))', border: '1px solid rgba(99,102,241,0.2)', borderRadius: '14px', padding: '20px', animation: 'fadeIn .25s ease', height: 'fit-content', position: 'sticky', top: '0' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
              <div>
                <div style={{ fontFamily: 'monospace', fontSize: '11px', color: '#475569', marginBottom: '4px' }}>{selected.id}</div>
                <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '15px' }}>{selected.title}</div>
              </div>
              <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: '16px' }}>✕</button>
            </div>
            <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
              <span style={{ padding: '4px 12px', borderRadius: '12px', fontSize: '12px', fontWeight: 700, background: `${SEV[selected.severity]}20`, color: SEV[selected.severity] }}>{selected.severity}</span>
              <span style={{ padding: '4px 12px', borderRadius: '12px', fontSize: '12px', fontWeight: 700, background: `${STAT[selected.status]}20`, color: STAT[selected.status] }}>{selected.status}</span>
            </div>
            <div style={{ fontSize: '11px', color: '#475569', fontWeight: 700, letterSpacing: '.06em', marginBottom: '8px' }}>FULL SUMMARY</div>
            <div style={{ color: '#94a3b8', fontSize: '13px', lineHeight: 1.7, marginBottom: '16px' }}>{selected.summary}</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '12px', marginBottom: '16px' }}>
              <div><div style={{ color: '#475569', marginBottom: '3px' }}>STARTED</div><div style={{ color: '#94a3b8' }}>{selected.started}</div></div>
              <div><div style={{ color: '#475569', marginBottom: '3px' }}>ANALYST</div><div style={{ color: '#818cf8' }}>{selected.analyst}</div></div>
            </div>
            <div style={{ fontSize: '11px', color: '#475569', fontWeight: 700, letterSpacing: '.06em', marginBottom: '8px' }}>TOOLS USED</div>
            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
              {selected.tools.map(t => <span key={t} style={{ padding: '4px 10px', background: 'rgba(99,102,241,0.12)', color: '#818cf8', borderRadius: '8px', fontSize: '12px', fontFamily: 'monospace' }}>{t}</span>)}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default InvestigationHistory;
