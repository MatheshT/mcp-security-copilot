import React, { useState } from 'react';

const SettingsPanel = ({ view }) => {
  const [tab, setTab] = useState(view === 'api-keys' ? 'keys' : view === 'windows-collectors' ? 'windows' : view === 'wazuh-settings' ? 'wazuh' : view === 'system-health' ? 'health' : 'wazuh');
  const [wazuhUrl, setWazuhUrl]     = useState('https://192.168.1.7');
  const [wazuhUser, setWazuhUser]   = useState('wazuh-wui');
  const [wazuhPass, setWazuhPass]   = useState('wazuh-wui');
  const [vtKey, setVtKey]           = useState('b98f230d...f90cb');
  const [testing, setTesting]       = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [saved, setSaved]           = useState(false);
  const [showPass, setShowPass]     = useState(false);
  const [showVt, setShowVt]         = useState(false);

  const testConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const resp = await fetch('/api/detection/wazuh/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: wazuhUrl, username: wazuhUser, password: wazuhPass })
      });
      const data = await resp.json();
      setTesting(false);
      if (data.ok) {
        setTestResult({ ok: true, msg: data.detail || 'Connected to Wazuh.' });
      } else {
        setTestResult({ ok: false, msg: data.detail || data || 'Connection failed' });
      }
    } catch (e) {
      setTesting(false);
      setTestResult({ ok: false, msg: e.message || String(e) });
    }
  };

  const saveSettings = async () => {
    setSaved(false);
    try {
      const resp = await fetch('/api/detection/wazuh/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: wazuhUrl, username: wazuhUser, password: wazuhPass })
      });
      const data = await resp.json();
      if (resp.ok && data.ok) {
        setSaved(true);
        setTimeout(() => setSaved(false), 3000);
      } else {
        setSaved(false);
      }
    } catch (e) {
      console.error('Save settings error', e);
      setSaved(false);
    }
  };

  const COLLECTORS = [
    { name: 'Security Events', source: 'Windows Security Log', status: 'active', events: '1,247', interval: '30s' },
    { name: 'System Events',   source: 'Windows System Log',   status: 'active', events: '342',   interval: '60s' },
    { name: 'App Events',      source: 'Application Log',      status: 'active', events: '89',    interval: '60s' },
    { name: 'PowerShell Log',  source: 'PS ScriptBlock Log',   status: 'warning',events: '23',    interval: '30s' },
    { name: 'Sysmon',          source: 'Sysmon Operational',   status: 'inactive',events: '0',    interval: 'N/A' },
  ];

  const API_KEYS = [
    { name: 'VirusTotal',    key: 'b98f230d490e78ec0b56...f90cb', status: 'valid',   requests: '850/1000', expires: '—' },
    { name: 'AbuseIPDB',     key: 'Not configured',              status: 'missing',  requests: '—',        expires: '—' },
    { name: 'Shodan',        key: 'Not configured',              status: 'missing',  requests: '—',        expires: '—' },
    { name: 'MISP',          key: 'Configured (hidden)',         status: 'valid',    requests: '—',        expires: '2025-01-01' },
    { name: 'OpenAI / LLM',  key: 'sk-***...***',               status: 'valid',    requests: '12,400/mo',expires: '—' },
  ];

  const statColor = s => ({ active: '#22c55e', warning: '#eab308', inactive: '#64748b', valid: '#22c55e', missing: '#ef4444' }[s] || '#64748b');

  return (
    <div style={{ fontFamily: 'Inter,sans-serif', color: '#e2e8f0' }}>
      <style>{`
        @keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
        .set-tab{background:transparent;border:none;color:#64748b;padding:9px 18px;cursor:pointer;font-size:13px;font-weight:600;border-bottom:2px solid transparent;transition:all .2s}
        .set-tab.active{color:#6366f1;border-bottom-color:#6366f1}
        .set-card{background:linear-gradient(135deg,rgba(15,23,42,0.95),rgba(20,30,50,0.9));border:1px solid rgba(99,102,241,0.15);border-radius:14px;padding:20px;margin-bottom:16px;animation:fadeIn .3s ease}
        .set-inp{width:100%;background:rgba(255,255,255,0.05);border:1px solid rgba(99,102,241,0.25);border-radius:8px;padding:10px 14px;color:#e2e8f0;font-size:13px;outline:none;box-sizing:border-box}
        .set-inp:focus{border-color:rgba(99,102,241,0.6);background:rgba(99,102,241,0.05)}
        .set-label{font-size:11px;color:#475569;font-weight:700;letter-spacing:.05em;display:block;margin-bottom:5px}
      `}</style>

      <div style={{ display: 'flex', borderBottom: '1px solid rgba(99,102,241,0.2)', marginBottom: '20px' }}>
        {[['wazuh','⚙️ Wazuh'],['windows','🪟 Windows Collectors'],['keys','🔑 API Keys'],['health','💚 System Health']].map(([id,label]) => (
          <button key={id} className={`set-tab${tab===id?' active':''}`} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>

      {/* Wazuh Settings */}
      {tab === 'wazuh' && (
        <div style={{ maxWidth: '640px', animation: 'fadeIn .3s ease' }}>
          <div className="set-card">
            <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '15px', marginBottom: '18px' }}>⚙️ Wazuh API Configuration</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label className="set-label">WAZUH API URL</label>
                <input className="set-inp" value={wazuhUrl} onChange={e => setWazuhUrl(e.target.value)} placeholder="http://192.168.1.5:55000" />
              </div>
              <div>
                <label className="set-label">USERNAME</label>
                <input className="set-inp" value={wazuhUser} onChange={e => setWazuhUser(e.target.value)} />
              </div>
              <div>
                <label className="set-label">PASSWORD</label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input className="set-inp" type={showPass ? 'text' : 'password'} value={wazuhPass} onChange={e => setWazuhPass(e.target.value)} />
                  <button onClick={() => setShowPass(!showPass)} style={{ padding: '10px 14px', background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: '8px', color: '#818cf8', cursor: 'pointer', fontSize: '13px', flexShrink: 0 }}>{showPass ? '🙈' : '👁'}</button>
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '10px', marginTop: '18px' }}>
              <button onClick={testConnection} disabled={testing} style={{ padding: '10px 20px', background: 'rgba(99,102,241,0.15)', border: '1px solid rgba(99,102,241,0.35)', borderRadius: '8px', color: '#818cf8', fontWeight: 600, fontSize: '13px', cursor: 'pointer' }}>
                {testing ? '⏳ Testing…' : '🔗 Test Connection'}
              </button>
              <button onClick={saveSettings} style={{ padding: '10px 20px', background: 'linear-gradient(135deg,#6366f1,#4f46e5)', border: 'none', borderRadius: '8px', color: '#fff', fontWeight: 700, fontSize: '13px', cursor: 'pointer' }}>
                {saved ? '✅ Saved!' : '💾 Save Settings'}
              </button>
            </div>
            {testResult && (
              <div style={{ marginTop: '14px', padding: '12px', background: testResult.ok ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)', border: `1px solid ${testResult.ok ? 'rgba(34,197,94,0.25)' : 'rgba(239,68,68,0.25)'}`, borderRadius: '8px' }}>
                <div style={{ fontSize: '13px', color: testResult.ok ? '#22c55e' : '#ef4444' }}>{testResult.ok ? '✅ Connected' : '❌ Failed'}</div>
                <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '4px' }}>{testResult.msg}</div>
                {!testResult.ok && <div style={{ fontSize: '12px', color: '#64748b', marginTop: '6px' }}>💡 The dashboard will display demo data until Wazuh is reachable.</div>}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Windows Collectors */}
      {tab === 'windows' && (
        <div style={{ animation: 'fadeIn .3s ease' }}>
          <div className="set-card" style={{ padding: '0', overflow: 'hidden' }}>
            <div style={{ padding: '14px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', fontWeight: 700, color: '#f1f5f9', fontSize: '14px' }}>🪟 Windows Event Log Collectors</div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', background: 'rgba(15,23,42,0.5)' }}>
                    {['COLLECTOR','SOURCE','STATUS','EVENTS/DAY','INTERVAL','ACTIONS'].map(h => (
                      <th key={h} style={{ padding: '10px 16px', textAlign: 'left', color: '#475569', fontWeight: 700, fontSize: '11px', letterSpacing: '.05em' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {COLLECTORS.map(c => (
                    <tr key={c.name} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <td style={{ padding: '12px 16px', fontWeight: 600, color: '#e2e8f0' }}>{c.name}</td>
                      <td style={{ padding: '12px 16px', color: '#94a3b8', fontSize: '12px' }}>{c.source}</td>
                      <td style={{ padding: '12px 16px' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: statColor(c.status), display: 'inline-block' }} />
                          <span style={{ color: statColor(c.status), fontWeight: 600, fontSize: '12px' }}>{c.status}</span>
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px', color: '#64748b', fontFamily: 'monospace' }}>{c.events}</td>
                      <td style={{ padding: '12px 16px', color: '#64748b' }}>{c.interval}</td>
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          {c.status !== 'active' && <button style={{ padding: '4px 10px', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.25)', borderRadius: '6px', color: '#22c55e', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}>Enable</button>}
                          {c.status === 'active' && <button style={{ padding: '4px 10px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)', borderRadius: '6px', color: '#ef4444', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}>Disable</button>}
                          <button style={{ padding: '4px 10px', background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.25)', borderRadius: '6px', color: '#818cf8', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}>Config</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* API Keys */}
      {tab === 'keys' && (
        <div style={{ animation: 'fadeIn .3s ease' }}>
          <div className="set-card" style={{ padding: '0', overflow: 'hidden' }}>
            <div style={{ padding: '14px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', fontWeight: 700, color: '#f1f5f9', fontSize: '14px' }}>🔑 API Key Management</div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', background: 'rgba(15,23,42,0.5)' }}>
                    {['SERVICE','KEY','STATUS','USAGE','EXPIRES','ACTIONS'].map(h => (
                      <th key={h} style={{ padding: '10px 16px', textAlign: 'left', color: '#475569', fontWeight: 700, fontSize: '11px', letterSpacing: '.05em' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {API_KEYS.map(k => (
                    <tr key={k.name} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <td style={{ padding: '12px 16px', fontWeight: 700, color: '#e2e8f0' }}>{k.name}</td>
                      <td style={{ padding: '12px 16px', color: '#64748b', fontFamily: 'monospace', fontSize: '12px' }}>{k.key}</td>
                      <td style={{ padding: '12px 16px' }}>
                        <span style={{ padding: '2px 8px', borderRadius: '12px', fontSize: '11px', fontWeight: 700, background: `${statColor(k.status)}15`, color: statColor(k.status) }}>{k.status}</span>
                      </td>
                      <td style={{ padding: '12px 16px', color: '#64748b', fontSize: '12px' }}>{k.requests}</td>
                      <td style={{ padding: '12px 16px', color: '#64748b', fontSize: '12px' }}>{k.expires}</td>
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          <button style={{ padding: '4px 10px', background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.25)', borderRadius: '6px', color: '#818cf8', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}>Edit</button>
                          {k.status === 'missing' && <button style={{ padding: '4px 10px', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.25)', borderRadius: '6px', color: '#22c55e', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}>Add Key</button>}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* System Health */}
      {tab === 'health' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(280px,1fr))', gap: '14px', animation: 'fadeIn .3s ease' }}>
          {[
            { label: 'Backend API',         status: 'Online',     detail: 'FastAPI v2.0.0 running',               icon: '⚡', color: '#22c55e' },
            { label: 'Database',            status: 'Connected',  detail: 'SQLite — 4.1 MB used',                 icon: '🗄️', color: '#22c55e' },
            { label: 'Wazuh Integration',   status: (testResult && testResult.ok) ? 'Online' : 'Offline',    detail: (testResult && testResult.ok) ? `Reachable at ${wazuhUrl}` : `Not reachable at ${wazuhUrl}`,   icon: '⚠️', color: (testResult && testResult.ok) ? '#22c55e' : '#f97316' },
            { label: 'VirusTotal API',      status: 'Active',     detail: '850/1000 daily requests used',          icon: '🦠', color: '#22c55e' },
            { label: 'AI / LLM Engine',     status: 'Ready',      detail: 'Multi-model support enabled',           icon: '🧠', color: '#6366f1' },
            { label: 'Windows Collectors',  status: 'Running',    detail: '4/5 collectors active',                 icon: '🪟', color: '#22c55e' },
            { label: 'Cache Layer',         status: 'Active',     detail: 'In-memory cache enabled',               icon: '⚡', color: '#22c55e' },
            { label: 'Prometheus Metrics',  status: 'Enabled',    detail: 'Metrics at /metrics endpoint',          icon: '📊', color: '#22c55e' },
          ].map(s => (
            <div key={s.label} style={{ background: 'linear-gradient(135deg,rgba(15,23,42,0.95),rgba(20,30,50,0.9))', border: `1px solid ${s.color}25`, borderRadius: '12px', padding: '16px', display: 'flex', alignItems: 'center', gap: '14px' }}>
              <span style={{ fontSize: '28px' }}>{s.icon}</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '14px', marginBottom: '3px' }}>{s.label}</div>
                <div style={{ fontSize: '12px', color: '#64748b' }}>{s.detail}</div>
              </div>
              <span style={{ padding: '3px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 700, background: `${s.color}15`, color: s.color, flexShrink: 0 }}>{s.status}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default SettingsPanel;
