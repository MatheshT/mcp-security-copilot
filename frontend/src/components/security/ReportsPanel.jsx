import React, { useState } from 'react';

const REPORTS = [
  { id: 'RPT-2024-0015', title: 'Daily Security Summary — Jan 15', type: 'Daily', date: '2024-01-15', status: 'Ready', severity: 'High',   size: '2.4 MB', pages: 12 },
  { id: 'RPT-2024-0014', title: 'Incident Report: Web Server Compromise', type: 'Incident', date: '2024-01-15', status: 'Ready', severity: 'Critical', size: '5.1 MB', pages: 28 },
  { id: 'RPT-2024-0013', title: 'Weekly Executive Summary — W2 Jan', type: 'Executive', date: '2024-01-14', status: 'Ready', severity: 'Medium', size: '1.8 MB', pages: 8 },
  { id: 'RPT-2024-0012', title: 'Threat Intelligence Digest — Jan 14', type: 'ThreatIntel', date: '2024-01-14', status: 'Ready', severity: 'High', size: '3.2 MB', pages: 18 },
  { id: 'RPT-2024-0011', title: 'Compliance Audit Q4 2023', type: 'Compliance', date: '2024-01-10', status: 'Ready', severity: 'Low', size: '4.7 MB', pages: 45 },
];

const REPORT_TYPES = [
  { id: 'incident', label: 'Incident Report', icon: '🚨', desc: 'Detailed investigation report for a specific incident' },
  { id: 'executive', label: 'Executive Summary', icon: '👔', desc: 'High-level overview for management and stakeholders' },
  { id: 'daily', label: 'Daily Digest', icon: '📅', desc: 'Summary of all security events in the last 24 hours' },
  { id: 'threat', label: 'Threat Intel', icon: '🌐', desc: 'Compiled threat intelligence from all sources' },
  { id: 'compliance', label: 'Compliance', icon: '📋', desc: 'Compliance posture and audit trail report' },
  { id: 'pdf', label: 'PDF Export', icon: '📑', desc: 'Export any investigation as formatted PDF' },
];

const SEV = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22c55e' };

const ReportsPanel = ({ view }) => {
  const [tab, setTab]           = useState(view === 'pdf-export' ? 'generate' : view === 'report-history' ? 'history' : view === 'executive-reports' ? 'generate' : 'history');
  const [generating, setGenerating] = useState(false);
  const [genProgress, setGenProgress] = useState(0);
  const [genDone, setGenDone]   = useState(false);
  const [selType, setSelType]   = useState('incident');
  const [selReport, setSelReport] = useState(null);
  const [incidentId, setIncidentId] = useState('');

  const handleGenerate = async () => {
    setGenerating(true);
    setGenProgress(0);
    setGenDone(false);
    for (let i = 0; i <= 100; i += 10) {
      await new Promise(r => setTimeout(r, 180));
      setGenProgress(i);
    }
    setGenerating(false);
    setGenDone(true);
  };

  return (
    <div style={{ fontFamily: 'Inter,sans-serif', color: '#e2e8f0' }}>
      <style>{`
        @keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
        .rpt-tab{background:transparent;border:none;color:#64748b;padding:9px 18px;cursor:pointer;font-size:13px;font-weight:600;border-bottom:2px solid transparent;transition:all .2s}
        .rpt-tab.active{color:#6366f1;border-bottom-color:#6366f1}
        .rpt-card{background:linear-gradient(135deg,rgba(15,23,42,0.95),rgba(20,30,50,0.9));border:1px solid rgba(99,102,241,0.15);border-radius:14px;padding:20px}
        .rpt-type{cursor:pointer;padding:14px;border-radius:10px;border:2px solid rgba(99,102,241,0.1);transition:all .2s;background:rgba(15,23,42,0.7)}
        .rpt-type:hover,.rpt-type.sel{border-color:#6366f1;background:rgba(99,102,241,0.08)}
        .rpt-row{cursor:pointer;padding:12px 16px;border-radius:8px;border:1px solid rgba(99,102,241,0.1);margin-bottom:6px;background:rgba(15,23,42,0.8);transition:all .2s}
        .rpt-row:hover,.rpt-row.sel{background:rgba(99,102,241,0.1);border-color:rgba(99,102,241,0.35)}
      `}</style>

      <div style={{ display: 'flex', borderBottom: '1px solid rgba(99,102,241,0.2)', marginBottom: '20px' }}>
        {[['generate','📝 Generate Report'],['history','📚 Report History']].map(([id,label]) => (
          <button key={id} className={`rpt-tab${tab===id?' active':''}`} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>

      {/* Generate */}
      {tab === 'generate' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', animation: 'fadeIn .3s ease' }}>
          <div>
            <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '15px', marginBottom: '14px' }}>Select Report Type</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '20px' }}>
              {REPORT_TYPES.map(r => (
                <div key={r.id} className={`rpt-type${selType===r.id?' sel':''}`} onClick={() => setSelType(r.id)}>
                  <div style={{ fontSize: '20px', marginBottom: '6px' }}>{r.icon}</div>
                  <div style={{ fontWeight: 600, color: '#e2e8f0', fontSize: '13px', marginBottom: '4px' }}>{r.label}</div>
                  <div style={{ fontSize: '11px', color: '#64748b' }}>{r.desc}</div>
                </div>
              ))}
            </div>
            <div style={{ marginBottom: '14px' }}>
              <label style={{ fontSize: '12px', color: '#64748b', display: 'block', marginBottom: '6px' }}>Incident / Case ID (optional)</label>
              <input
                value={incidentId} onChange={e => setIncidentId(e.target.value)}
                placeholder="e.g. INV-2024-0892"
                style={{ width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(99,102,241,0.3)', borderRadius: '8px', padding: '10px 14px', color: '#e2e8f0', fontSize: '13px', outline: 'none', boxSizing: 'border-box' }}
              />
            </div>
            <button
              onClick={handleGenerate}
              disabled={generating}
              style={{ width: '100%', padding: '14px', background: generating ? 'rgba(99,102,241,0.4)' : 'linear-gradient(135deg,#6366f1,#4f46e5)', border: 'none', borderRadius: '10px', color: '#fff', fontWeight: 700, fontSize: '14px', cursor: generating ? 'wait' : 'pointer' }}
            >
              {generating ? '⏳ Generating…' : '📄 Generate Report'}
            </button>
          </div>

          <div>
            {!generating && !genDone && (
              <div className="rpt-card" style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '12px', opacity: 0.5 }}>
                <span style={{ fontSize: '48px' }}>📄</span>
                <span style={{ color: '#64748b', fontSize: '14px' }}>Select a report type and click Generate</span>
              </div>
            )}
            {generating && (
              <div className="rpt-card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '16px', animation: 'fadeIn .3s ease' }}>
                <div style={{ fontSize: '40px' }}>⚙️</div>
                <div style={{ fontWeight: 700, color: '#f1f5f9' }}>Generating Report…</div>
                <div style={{ width: '100%', background: 'rgba(255,255,255,0.06)', borderRadius: '8px', height: '10px', overflow: 'hidden' }}>
                  <div style={{ width: `${genProgress}%`, height: '100%', background: 'linear-gradient(90deg,#6366f1,#a855f7)', borderRadius: '8px', transition: 'width .3s ease', boxShadow: '0 0 8px rgba(99,102,241,0.6)' }} />
                </div>
                <div style={{ fontSize: '13px', color: '#64748b' }}>{genProgress}% — {genProgress < 30 ? 'Collecting data…' : genProgress < 60 ? 'Running AI analysis…' : genProgress < 90 ? 'Formatting report…' : 'Finalizing…'}</div>
              </div>
            )}
            {genDone && (
              <div className="rpt-card" style={{ display: 'flex', flexDirection: 'column', gap: '14px', animation: 'fadeIn .3s ease' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '28px' }}>✅</span>
                  <div style={{ fontWeight: 700, color: '#22c55e', fontSize: '16px' }}>Report Ready!</div>
                </div>
                <div style={{ fontSize: '13px', color: '#94a3b8' }}>Report generated successfully. You can download it below.</div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                  {[['📥 Download PDF','#6366f1'],['📊 Download JSON','#0ea5e9'],['📧 Send Email','#22c55e'],['👁 Preview','#a855f7']].map(([label,color]) => (
                    <button key={label} style={{ padding: '10px', background: `${color}15`, border: `1px solid ${color}40`, borderRadius: '8px', color, fontWeight: 600, fontSize: '13px', cursor: 'pointer' }}>{label}</button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* History */}
      {tab === 'history' && (
        <div style={{ display: 'grid', gridTemplateColumns: selReport ? '1fr 380px' : '1fr', gap: '16px', animation: 'fadeIn .3s ease' }}>
          <div>
            {REPORTS.map(r => (
              <div key={r.id} className={`rpt-row${selReport?.id===r.id?' sel':''}`} onClick={() => setSelReport(selReport?.id===r.id?null:r)}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ fontFamily: 'monospace', fontSize: '11px', color: '#475569', marginBottom: '4px' }}>{r.id}</div>
                    <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '14px', marginBottom: '4px' }}>{r.title}</div>
                    <div style={{ fontSize: '12px', color: '#64748b' }}>{r.date} · {r.pages} pages · {r.size}</div>
                  </div>
                  <div style={{ display: 'flex', gap: '6px', flexDirection: 'column', alignItems: 'flex-end' }}>
                    <span style={{ padding: '2px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 700, background: `${SEV[r.severity]}15`, color: SEV[r.severity] }}>{r.severity}</span>
                    <span style={{ padding: '2px 10px', borderRadius: '12px', fontSize: '11px', background: 'rgba(34,197,94,0.1)', color: '#22c55e' }}>{r.type}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
          {selReport && (
            <div className="rpt-card" style={{ animation: 'fadeIn .25s ease', height: 'fit-content' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '14px' }}>
                <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '15px' }}>Report Details</span>
                <button onClick={() => setSelReport(null)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}>✕</button>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px', marginBottom: '16px' }}>
                {[['ID',selReport.id],['Title',selReport.title],['Type',selReport.type],['Date',selReport.date],['Pages',selReport.pages],['Size',selReport.size]].map(([k,v]) => (
                  <div key={k}><div style={{ color: '#475569', fontSize: '11px', fontWeight: 700, marginBottom: '3px' }}>{k}</div><div style={{ color: '#94a3b8' }}>{v}</div></div>
                ))}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                {[['📥 Download','#6366f1'],['📧 Email','#22c55e'],['🗑 Delete','#ef4444'],['📋 Clone','#0ea5e9']].map(([label,color]) => (
                  <button key={label} style={{ padding: '10px', background: `${color}15`, border: `1px solid ${color}40`, borderRadius: '8px', color, fontWeight: 600, fontSize: '13px', cursor: 'pointer' }}>{label}</button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ReportsPanel;
