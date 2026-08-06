import React, { useState } from 'react';

const PROCESSES = [
  { pid: 1234, name: 'cmd.exe',       parent: 'w3wp.exe (PID:4532)', user: 'IIS_IUSR',   cpu: '12%', mem: '18MB', risk: 'Critical', args: 'cmd.exe /c whoami && net user' },
  { pid: 4532, name: 'w3wp.exe',      parent: 'iisexpress.exe',       user: 'NETWORK SERVICE', cpu: '3%',  mem: '210MB',risk: 'High',     args: 'w3wp.exe -ap "DefaultAppPool"' },
  { pid: 5678, name: 'powershell.exe',parent: 'svchost.exe (PID:878)',user: 'SYSTEM',    cpu: '8%',  mem: '45MB', risk: 'High',     args: 'powershell.exe -enc SQBFAFgA...' },
  { pid: 3344, name: 'mmc.exe',       parent: 'explorer.exe',         user: 'admin',     cpu: '0%',  mem: '22MB', risk: 'Low',      args: 'mmc.exe' },
  { pid: 9900, name: 'nc.exe',        parent: 'cmd.exe (PID:1234)',   user: 'IIS_IUSR',   cpu: '2%',  mem: '4MB',  risk: 'Critical', args: 'nc.exe -lvp 4444' },
];

const HOSTS = [
  { name: 'web-server-01', ip: '192.168.1.10', os: 'Ubuntu 22.04', risk: 'Critical', alerts: 7,  last: '2m ago',  anomalies: ['Webshell detected','Outbound C2 beacon','Privilege escalation'] },
  { name: 'workstation-08',ip: '192.168.2.8',  os: 'Windows 11',   risk: 'High',     alerts: 4,  last: '15m ago', anomalies: ['Suspicious powershell','Encoded command exec'] },
  { name: 'dc-01',         ip: '192.168.1.5',  os: 'Win Server 22', risk: 'High',    alerts: 3,  last: '30m ago', anomalies: ['Unusual admin login','LDAP enumeration'] },
  { name: 'laptop-hr-03',  ip: '192.168.3.12', os: 'macOS 14',      risk: 'Medium',  alerts: 2,  last: '1h ago',  anomalies: ['Large upload detected'] },
  { name: 'db-server-01',  ip: '192.168.1.20', os: 'CentOS 9',      risk: 'Low',     alerts: 1,  last: '3h ago',  anomalies: ['Port scan from external'] },
];

const USERS = [
  { name: 'jsmith',   dept: 'Engineering', events: 142, risk: 'Low',     anomalies: 0, lastLogin: '2024-01-15 09:12', status: 'Normal' },
  { name: 'admin',    dept: 'IT',          events: 891, risk: 'High',    anomalies: 5, lastLogin: '2024-01-15 03:42', status: '⚠ Off-hours login' },
  { name: 'mwilliams',dept: 'HR',          events: 1403,risk: 'Critical',anomalies: 8, lastLogin: '2024-01-14 22:15', status: '🚨 Bulk data access' },
  { name: 'svc_iis',  dept: 'Service',     events: 234, risk: 'High',    anomalies: 3, lastLogin: '2024-01-15 10:28', status: '⚠ Spawned shell' },
  { name: 'dbread',   dept: 'Database',    events: 67,  risk: 'Low',     anomalies: 0, lastLogin: '2024-01-15 08:00', status: 'Normal' },
];

const SEV = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22c55e' };

const ThreatHunting = ({ view }) => {
  const [tab, setTab]         = useState(view === 'process-analysis' ? 'process' : view === 'host-analysis' ? 'host' : view === 'user-activity' ? 'user' : 'ioc');
  const [iocQ, setIocQ]       = useState('');
  const [iocResult, setIocResult] = useState(null);
  const [selProc, setSelProc] = useState(null);
  const [selHost, setSelHost] = useState(null);
  const [selUser, setSelUser] = useState(null);

  const searchIoc = () => {
    if (!iocQ.trim()) return;
    const matches = [];
    if (iocQ.includes('.') || iocQ.includes(':')) matches.push({ type:'Network', host:'web-server-01', detail:`Connection to ${iocQ} detected`, time:'10m ago', risk:'High' });
    if (iocQ.length >= 20) matches.push({ type:'File Hash', host:'workstation-08', detail:`Hash ${iocQ} found in temp directory`, time:'2h ago', risk:'Critical' });
    matches.push({ type:'Registry', host:'dc-01', detail:`IOC pattern matched in EventLog`, time:'30m ago', risk:'Medium' });
    setIocResult(matches);
  };

  return (
    <div style={{ fontFamily: 'Inter,sans-serif', color: '#e2e8f0' }}>
      <style>{`
        @keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
        .th-tab{background:transparent;border:none;color:#64748b;padding:9px 18px;cursor:pointer;font-size:13px;font-weight:600;border-bottom:2px solid transparent;transition:all .2s}
        .th-tab.active{color:#6366f1;border-bottom-color:#6366f1}
        .th-card{background:linear-gradient(135deg,rgba(15,23,42,0.95),rgba(20,30,50,0.9));border:1px solid rgba(99,102,241,0.15);border-radius:14px;padding:20px}
        .th-row{cursor:pointer;padding:12px 14px;border-radius:8px;border:1px solid rgba(99,102,241,0.1);margin-bottom:6px;transition:all .2s;background:rgba(15,23,42,0.7)}
        .th-row:hover,.th-row.sel{background:rgba(99,102,241,0.1);border-color:rgba(99,102,241,0.35)}
      `}</style>

      <div style={{ display: 'flex', borderBottom: '1px solid rgba(99,102,241,0.2)', marginBottom: '20px' }}>
        {[['ioc','🔎 IOC Search'],['process','⚙️ Process Analysis'],['host','🖥️ Host Analysis'],['user','👤 User Activity']].map(([id,label]) => (
          <button key={id} className={`th-tab${tab===id?' active':''}`} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>

      {/* IOC Search */}
      {tab === 'ioc' && (
        <div style={{ maxWidth: '750px', animation: 'fadeIn .3s ease' }}>
          <div className="th-card" style={{ marginBottom: '16px' }}>
            <div style={{ fontWeight: 700, color: '#f1f5f9', marginBottom: '12px' }}>🔎 Hunt IOCs Across Endpoints</div>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
              <input
                value={iocQ} onChange={e => setIocQ(e.target.value)} onKeyDown={e => e.key==='Enter'&&searchIoc()}
                placeholder="Search for IP, hash, domain, file path, registry key..."
                style={{ flex: 1, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(99,102,241,0.3)', borderRadius: '10px', padding: '12px 16px', color: '#e2e8f0', fontSize: '14px', outline: 'none' }}
              />
              <button onClick={searchIoc} style={{ padding: '12px 24px', background: 'linear-gradient(135deg,#6366f1,#4f46e5)', border: 'none', borderRadius: '10px', color: '#fff', fontWeight: 700, cursor: 'pointer', fontSize: '14px' }}>🔍 Hunt</button>
            </div>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {['203.0.113.47','5f4dcc3b5aa765d61d8327deb882cf99','C:\\Windows\\Temp\\evil.exe','evil-c2.ru'].map(s => (
                <button key={s} onClick={() => setIocQ(s)} style={{ padding: '4px 10px', background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: '16px', color: '#818cf8', fontSize: '11px', cursor: 'pointer', fontFamily: 'monospace' }}>{s}</button>
              ))}
            </div>
          </div>
          {iocResult && (
            <div style={{ animation: 'fadeIn .3s ease' }}>
              <div style={{ fontSize: '13px', color: '#64748b', marginBottom: '10px' }}>{iocResult.length} matches found for <span style={{ color: '#818cf8', fontFamily: 'monospace' }}>{iocQ}</span></div>
              {iocResult.map((r, i) => (
                <div key={i} className="th-row">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <span style={{ padding: '2px 8px', borderRadius: '6px', background: 'rgba(99,102,241,0.12)', color: '#818cf8', fontSize: '11px', fontFamily: 'monospace', marginRight: '10px' }}>{r.type}</span>
                      <span style={{ color: '#e2e8f0', fontSize: '13px', fontWeight: 500 }}>{r.detail}</span>
                    </div>
                    <span style={{ padding: '2px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 700, background: `${SEV[r.risk]}15`, color: SEV[r.risk], flexShrink: 0, marginLeft: '10px' }}>{r.risk}</span>
                  </div>
                  <div style={{ fontSize: '11px', color: '#475569', marginTop: '6px' }}>Host: <span style={{ color: '#a5b4fc' }}>{r.host}</span> · {r.time}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Process Analysis */}
      {tab === 'process' && (
        <div style={{ display: 'grid', gridTemplateColumns: selProc ? '1fr 360px' : '1fr', gap: '16px', animation: 'fadeIn .3s ease' }}>
          <div className="th-card" style={{ padding: '0', overflow: 'hidden' }}>
            <div style={{ padding: '14px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', fontWeight: 700, color: '#f1f5f9', fontSize: '14px' }}>⚙️ Suspicious Process Tree</div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', background: 'rgba(15,23,42,0.5)' }}>
                    {['PID','Process','Parent','User','CPU','MEM','Risk'].map(h => (
                      <th key={h} style={{ padding: '10px 14px', textAlign: 'left', color: '#475569', fontWeight: 700, fontSize: '11px', letterSpacing: '.05em' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {PROCESSES.map(p => {
                    const cfg = SEV[p.risk];
                    return (
                      <tr key={p.pid} onClick={() => setSelProc(selProc?.pid===p.pid?null:p)}
                        style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', cursor: 'pointer', background: selProc?.pid===p.pid?'rgba(99,102,241,0.1)':'' }}
                        onMouseEnter={e => e.currentTarget.style.background='rgba(99,102,241,0.07)'}
                        onMouseLeave={e => e.currentTarget.style.background=selProc?.pid===p.pid?'rgba(99,102,241,0.1)':''}
                      >
                        <td style={{ padding: '10px 14px', color: '#64748b', fontFamily: 'monospace' }}>{p.pid}</td>
                        <td style={{ padding: '10px 14px', fontWeight: 600, color: '#e2e8f0' }}>{p.name}</td>
                        <td style={{ padding: '10px 14px', color: '#94a3b8', fontSize: '12px' }}>{p.parent}</td>
                        <td style={{ padding: '10px 14px', color: '#a5b4fc' }}>{p.user}</td>
                        <td style={{ padding: '10px 14px', color: '#64748b' }}>{p.cpu}</td>
                        <td style={{ padding: '10px 14px', color: '#64748b' }}>{p.mem}</td>
                        <td style={{ padding: '10px 14px' }}><span style={{ padding: '2px 8px', borderRadius: '12px', fontSize: '11px', fontWeight: 700, background: `${cfg}15`, color: cfg }}>{p.risk}</span></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
          {selProc && (
            <div className="th-card" style={{ animation: 'fadeIn .25s ease', height: 'fit-content' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '15px' }}>{selProc.name}</span>
                <button onClick={() => setSelProc(null)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}>✕</button>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                {[['PID',selProc.pid],['Parent',selProc.parent],['User',selProc.user],['CPU',selProc.cpu],['Memory',selProc.mem]].map(([k,v]) => (
                  <div key={k}><div style={{ color: '#475569', fontSize: '11px', fontWeight: 700, letterSpacing: '.06em', marginBottom: '3px' }}>{k}</div><div style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{v}</div></div>
                ))}
                <div><div style={{ color: '#475569', fontSize: '11px', fontWeight: 700, letterSpacing: '.06em', marginBottom: '3px' }}>COMMAND LINE</div><div style={{ color: '#ef4444', fontFamily: 'monospace', fontSize: '12px', wordBreak: 'break-all', background: 'rgba(239,68,68,0.05)', padding: '8px', borderRadius: '6px' }}>{selProc.args}</div></div>
                <div style={{ padding: '10px', background: 'rgba(99,102,241,0.08)', borderRadius: '8px', border: '1px solid rgba(99,102,241,0.2)' }}>
                  <div style={{ fontSize: '11px', color: '#6366f1', fontWeight: 700, marginBottom: '6px' }}>RISK ASSESSMENT</div>
                  <div style={{ fontSize: '12px', color: '#94a3b8' }}>{selProc.risk === 'Critical' ? '🚨 Immediate threat. Likely webshell or RAT. Kill process and isolate host.' : selProc.risk === 'High' ? '⚠️ Suspicious. Encoded arguments suggest evasion. Investigate further.' : '✅ Low risk. Normal system activity.'}</div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Host Analysis */}
      {tab === 'host' && (
        <div style={{ display: 'grid', gridTemplateColumns: selHost ? '1fr 360px' : '1fr', gap: '16px', animation: 'fadeIn .3s ease' }}>
          <div>
            {HOSTS.map(h => (
              <div key={h.name} className={`th-row${selHost?.name===h.name?' sel':''}`} onClick={() => setSelHost(selHost?.name===h.name?null:h)}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: SEV[h.risk], boxShadow: `0 0 6px ${SEV[h.risk]}`, display: 'inline-block', flexShrink: 0 }} />
                    <div>
                      <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '14px' }}>{h.name}</div>
                      <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'monospace' }}>{h.ip} · {h.os}</div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <span style={{ fontSize: '12px', color: '#64748b' }}>{h.alerts} alerts</span>
                    <span style={{ padding: '2px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 700, background: `${SEV[h.risk]}15`, color: SEV[h.risk] }}>{h.risk}</span>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '8px' }}>
                  {h.anomalies.map(a => <span key={a} style={{ padding: '2px 8px', background: 'rgba(239,68,68,0.08)', color: '#fca5a5', borderRadius: '6px', fontSize: '11px' }}>⚠ {a}</span>)}
                </div>
              </div>
            ))}
          </div>
          {selHost && (
            <div className="th-card" style={{ animation: 'fadeIn .25s ease', height: 'fit-content' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '14px' }}>
                <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '15px' }}>{selHost.name}</span>
                <button onClick={() => setSelHost(null)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}>✕</button>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px' }}>
                {[['IP',selHost.ip],['OS',selHost.os],['Alert Count',selHost.alerts],['Last Activity',selHost.last]].map(([k,v]) => (
                  <div key={k}><div style={{ color: '#475569', fontSize: '11px', fontWeight: 700, marginBottom: '3px' }}>{k}</div><div style={{ color: '#94a3b8' }}>{v}</div></div>
                ))}
                <div><div style={{ color: '#475569', fontSize: '11px', fontWeight: 700, marginBottom: '6px' }}>ANOMALIES DETECTED</div>
                  {selHost.anomalies.map(a => <div key={a} style={{ padding: '6px 10px', background: 'rgba(239,68,68,0.08)', borderRadius: '6px', marginBottom: '4px', fontSize: '12px', color: '#fca5a5' }}>⚠ {a}</div>)}
                </div>
                <button style={{ padding: '10px', background: 'linear-gradient(135deg,#ef4444,#dc2626)', border: 'none', borderRadius: '8px', color: '#fff', fontWeight: 700, cursor: 'pointer', fontSize: '13px' }}>🔒 Isolate Host</button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* User Activity */}
      {tab === 'user' && (
        <div style={{ display: 'grid', gridTemplateColumns: selUser ? '1fr 360px' : '1fr', gap: '16px', animation: 'fadeIn .3s ease' }}>
          <div>
            {USERS.map(u => (
              <div key={u.name} className={`th-row${selUser?.name===u.name?' sel':''}`} onClick={() => setSelUser(selUser?.name===u.name?null:u)}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div style={{ width: '36px', height: '36px', borderRadius: '50%', background: `linear-gradient(135deg,${SEV[u.risk]}40,${SEV[u.risk]}20)`, border: `2px solid ${SEV[u.risk]}60`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '14px', fontWeight: 700, color: SEV[u.risk] }}>
                      {u.name[0].toUpperCase()}
                    </div>
                    <div>
                      <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '14px' }}>{u.name} <span style={{ fontSize: '11px', color: '#64748b', fontWeight: 400 }}>({u.dept})</span></div>
                      <div style={{ fontSize: '11px', color: u.status.includes('🚨')||u.status.includes('⚠') ? '#f97316' : '#64748b' }}>{u.status}</div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    {u.anomalies > 0 && <span style={{ fontSize: '12px', color: '#ef4444', fontWeight: 700 }}>{u.anomalies} anomalies</span>}
                    <span style={{ padding: '2px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 700, background: `${SEV[u.risk]}15`, color: SEV[u.risk] }}>{u.risk}</span>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '16px', marginTop: '8px', fontSize: '11px', color: '#475569' }}>
                  <span>Events: <span style={{ color: '#94a3b8' }}>{u.events}</span></span>
                  <span>Last login: <span style={{ color: '#94a3b8' }}>{u.lastLogin}</span></span>
                </div>
              </div>
            ))}
          </div>
          {selUser && (
            <div className="th-card" style={{ animation: 'fadeIn .25s ease', height: 'fit-content' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '14px' }}>
                <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '15px' }}>👤 {selUser.name}</span>
                <button onClick={() => setSelUser(null)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}>✕</button>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px' }}>
                {[['Department',selUser.dept],['Risk Level',selUser.risk],['Total Events',selUser.events],['Last Login',selUser.lastLogin],['Status',selUser.status]].map(([k,v]) => (
                  <div key={k}><div style={{ color: '#475569', fontSize: '11px', fontWeight: 700, marginBottom: '3px' }}>{k}</div><div style={{ color: k==='Risk Level'?SEV[v]:'#94a3b8', fontWeight: k==='Risk Level'?700:400 }}>{v}</div></div>
                ))}
                {selUser.anomalies > 0 && (
                  <div style={{ padding: '10px', background: 'rgba(239,68,68,0.08)', borderRadius: '8px', border: '1px solid rgba(239,68,68,0.2)' }}>
                    <div style={{ fontSize: '11px', color: '#ef4444', fontWeight: 700, marginBottom: '6px' }}>⚠ {selUser.anomalies} ANOMALIES DETECTED</div>
                    <div style={{ fontSize: '12px', color: '#94a3b8' }}>User behavior deviates from baseline. Review access logs and apply MFA challenge.</div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ThreatHunting;
