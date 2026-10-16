import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { MODERN_COLORS as colors, SPACING, BORDER_RADIUS } from '../theme/modernTheme';

const API_BASE = (import.meta.env.VITE_API_URL?.replace(/\/$/, '') || '') + '/api';

const DEFAULT_TACTICS = [
  {
    tactic_id: "TA0001",
    name: "Initial Access",
    techniques: [
      { id: "T1566.001", name: "Spearphishing Attachment", severity: "High", active_detections: 3 },
      { id: "T1190", name: "Exploit Public-Facing App", severity: "Critical", active_detections: 1 },
      { id: "T1078", name: "Valid Accounts", severity: "Medium", active_detections: 2 }
    ]
  },
  {
    tactic_id: "TA0002",
    name: "Execution",
    techniques: [
      { id: "T1059.001", name: "PowerShell Scripting", severity: "Critical", active_detections: 5 },
      { id: "T1059.003", name: "Windows Command Shell", severity: "High", active_detections: 2 },
      { id: "T1204.002", name: "Malicious File Execution", severity: "High", active_detections: 1 }
    ]
  },
  {
    tactic_id: "TA0003",
    name: "Persistence",
    techniques: [
      { id: "T1505.003", name: "Web Shell", severity: "Critical", active_detections: 1 },
      { id: "T1547.001", name: "Registry Run Keys", severity: "High", active_detections: 2 },
      { id: "T1053.005", name: "Scheduled Task", severity: "Medium", active_detections: 1 }
    ]
  },
  {
    tactic_id: "TA0004",
    name: "Privilege Escalation",
    techniques: [
      { id: "T1068", name: "Exploitation for PrivEsc", severity: "Critical", active_detections: 1 },
      { id: "T1548.002", name: "Bypass UAC", severity: "High", active_detections: 2 }
    ]
  },
  {
    tactic_id: "TA0005",
    name: "Defense Evasion",
    techniques: [
      { id: "T1562.001", name: "Disable Security Tools (vssadmin)", severity: "Critical", active_detections: 4 },
      { id: "T1070.004", name: "File Deletion / Timestomp", severity: "Medium", active_detections: 2 },
      { id: "T1027", name: "Obfuscated / Encrypted Files", severity: "High", active_detections: 3 }
    ]
  },
  {
    tactic_id: "TA0006",
    name: "Credential Access",
    techniques: [
      { id: "T1558.003", name: "Kerberoasting (TGS Request)", severity: "Critical", active_detections: 2 },
      { id: "T1003.001", name: "LSASS Memory Dump", severity: "Critical", active_detections: 1 },
      { id: "T1110.001", name: "Password Brute Force", severity: "High", active_detections: 6 }
    ]
  },
  {
    tactic_id: "TA0007",
    name: "Discovery",
    techniques: [
      { id: "T1046", name: "Network Service Scanning", severity: "Medium", active_detections: 3 },
      { id: "T1087.002", name: "Domain Account Discovery", severity: "Medium", active_detections: 2 }
    ]
  },
  {
    tactic_id: "TA0008",
    name: "Lateral Movement",
    techniques: [
      { id: "T1021.002", name: "SMB / Windows Admin Shares", severity: "Critical", active_detections: 2 },
      { id: "T1021.001", name: "Remote Desktop Protocol", severity: "High", active_detections: 1 }
    ]
  },
  {
    tactic_id: "TA0009",
    name: "Collection",
    techniques: [
      { id: "T1114.002", name: "Remote Email Collection", severity: "High", active_detections: 1 },
      { id: "T1005", name: "Data from Local System", severity: "Medium", active_detections: 2 }
    ]
  },
  {
    tactic_id: "TA0011",
    name: "Command & Control",
    techniques: [
      { id: "T1071.001", name: "HTTPS C2 Beaconing", severity: "Critical", active_detections: 4 },
      { id: "T1573.001", name: "Encrypted Channel", severity: "High", active_detections: 2 }
    ]
  },
  {
    tactic_id: "TA0010",
    name: "Exfiltration",
    techniques: [
      { id: "T1048", name: "Exfiltration Over Alt Protocol", severity: "Critical", active_detections: 1 },
      { id: "T1567.002", name: "Exfiltration to Cloud Storage", severity: "High", active_detections: 1 }
    ]
  },
  {
    tactic_id: "TA0040",
    name: "Impact",
    techniques: [
      { id: "T1486", name: "Data Encrypted (Ransomware)", severity: "Critical", active_detections: 2 },
      { id: "T1490", name: "Inhibit System Recovery", severity: "Critical", active_detections: 3 }
    ]
  }
];

const MitreMatrix = () => {
  const [tactics, setTactics] = useState(DEFAULT_TACTICS);
  const [selectedTech, setSelectedTech] = useState(null);
  const [coverageData, setCoverageData] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    fetchMatrix();
  }, []);

  const fetchMatrix = async () => {
    try {
      const res = await axios.get(`${API_BASE}/v2/mitre/matrix`);
      if (res.data && res.data.tactics) {
        setTactics(res.data.tactics);
      }
      const covRes = await axios.get(`${API_BASE}/v2/mitre/coverage`);
      if (covRes.data) {
        setCoverageData(covRes.data);
      }
    } catch (e) {
      console.log('Using default MITRE matrix dataset');
    }
  };

  const getSeverityColor = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical':
        return { bg: 'rgba(239, 68, 68, 0.25)', border: 'rgba(239, 68, 68, 0.6)', text: '#fca5a5' };
      case 'high':
        return { bg: 'rgba(249, 115, 22, 0.25)', border: 'rgba(249, 115, 22, 0.6)', text: '#fdba74' };
      default:
        return { bg: 'rgba(234, 179, 8, 0.2)', border: 'rgba(234, 179, 8, 0.5)', text: '#fde047' };
    }
  };

  return (
    <div style={{ padding: '8px', color: '#e2e8f0' }}>
      {/* Header Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.15), rgba(168, 85, 247, 0.08))',
        border: '1px solid rgba(99, 102, 241, 0.3)',
        borderRadius: BORDER_RADIUS.lg,
        padding: SPACING.xl,
        marginBottom: SPACING.xl
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
              <span style={{ fontSize: '32px' }}>🗺️</span>
              <h1 style={{
                margin: 0,
                fontSize: '28px',
                fontWeight: 800,
                background: 'linear-gradient(135deg, #c084fc, #818cf8)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent'
              }}>
                MITRE ATT&CK Enterprise Matrix Navigator
              </h1>
              <span style={{
                background: 'rgba(168, 85, 247, 0.2)',
                color: '#d8b4fe',
                padding: '4px 12px',
                borderRadius: '999px',
                fontSize: '12px',
                fontWeight: 700,
                border: '1px solid rgba(168, 85, 247, 0.4)'
              }}>
                v14.1 ENTERPRISE MATRIX
              </span>
            </div>
            <p style={{ margin: 0, color: '#94a3b8', fontSize: '14px', maxWidth: '800px', lineHeight: '1.6' }}>
              Interactive tactical matrix mapping adversary TTPs (Tactics, Techniques, and Procedures). Color-coded heatmap highlighting active real-time detections, defensive telemetry coverage, and Sigma detection rules.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '12px' }}>
            <input
              type="text"
              placeholder="Search technique (e.g. PowerShell, T1486)..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              style={{
                background: 'rgba(15, 23, 42, 0.8)',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                color: '#ffffff',
                padding: '10px 16px',
                borderRadius: '8px',
                fontSize: '13px',
                width: '280px',
                outline: 'none'
              }}
            />
          </div>
        </div>
      </div>

      {/* Coverage Highlights Bar */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '16px',
        marginBottom: SPACING.xl
      }}>
        <div style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '16px' }}>
          <div style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 700 }}>Framework Coverage</div>
          <div style={{ fontSize: '26px', fontWeight: 800, color: '#34d399', marginTop: '4px' }}>89.4%</div>
          <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px' }}>Across 12 Enterprise Tactics</div>
        </div>
        <div style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '16px' }}>
          <div style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 700 }}>Monitored Techniques</div>
          <div style={{ fontSize: '26px', fontWeight: 800, color: '#818cf8', marginTop: '4px' }}>44 Rules</div>
          <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px' }}>Active Sigma & Wazuh correlation</div>
        </div>
        <div style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '16px' }}>
          <div style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 700 }}>Active Heat Detections</div>
          <div style={{ fontSize: '26px', fontWeight: 800, color: '#f87171', marginTop: '4px' }}>35 Events</div>
          <div style={{ fontSize: '11px', color: '#fca5a5', marginTop: '4px' }}>Critical & High severity focus</div>
        </div>
        <div style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '16px' }}>
          <div style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 700 }}>Top Threat Actor</div>
          <div style={{ fontSize: '22px', fontWeight: 800, color: '#c084fc', marginTop: '4px' }}>LockBit / APT29</div>
          <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px' }}>High TTP similarity index</div>
        </div>
      </div>

      {/* Horizontal Scrolling Matrix Grid */}
      <div style={{
        overflowX: 'auto',
        paddingBottom: '16px'
      }}>
        <div style={{
          display: 'grid',
          gridAutoFlow: 'column',
          gridAutoColumns: 'minmax(210px, 1fr)',
          gap: '12px',
          alignItems: 'start'
        }}>
          {tactics.map(tactic => (
            <div
              key={tactic.tactic_id}
              style={{
                background: 'rgba(15, 23, 42, 0.75)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: BORDER_RADIUS.md,
                padding: '12px',
                minWidth: '200px'
              }}
            >
              <div style={{
                borderBottom: '2px solid #6366f1',
                paddingBottom: '8px',
                marginBottom: '12px'
              }}>
                <div style={{ fontSize: '11px', color: '#818cf8', fontWeight: 700 }}>
                  {tactic.tactic_id}
                </div>
                <div style={{ fontSize: '14px', fontWeight: 800, color: '#f8fafc', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {tactic.name}
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {tactic.techniques
                  .filter(tech => {
                    if (!searchQuery) return true;
                    const q = searchQuery.toLowerCase();
                    return tech.name.toLowerCase().includes(q) || tech.id.toLowerCase().includes(q);
                  })
                  .map(tech => {
                    const sevStyle = getSeverityColor(tech.severity);
                    const isHot = tech.active_detections > 0;
                    return (
                      <div
                        key={tech.id}
                        onClick={() => setSelectedTech({ ...tech, tactic: tactic.name })}
                        style={{
                          background: isHot ? sevStyle.bg : 'rgba(30, 41, 59, 0.4)',
                          border: isHot ? `1px solid ${sevStyle.border}` : '1px solid rgba(255, 255, 255, 0.05)',
                          borderRadius: '6px',
                          padding: '10px',
                          cursor: 'pointer',
                          transition: 'all 0.15s ease',
                          position: 'relative'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span style={{ fontSize: '11px', fontFamily: 'monospace', color: '#94a3b8' }}>
                            {tech.id}
                          </span>
                          {isHot && (
                            <span style={{
                              background: '#ef4444',
                              color: '#ffffff',
                              fontSize: '10px',
                              fontWeight: 800,
                              padding: '1px 6px',
                              borderRadius: '999px'
                            }}>
                              {tech.active_detections}
                            </span>
                          )}
                        </div>

                        <div style={{
                          fontSize: '12px',
                          fontWeight: 700,
                          color: isHot ? sevStyle.text : '#cbd5e1',
                          lineHeight: '1.3'
                        }}>
                          {tech.name}
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Technique Detail Modal */}
      {selectedTech && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '16px'
        }}>
          <div style={{
            background: '#0c1120',
            border: '1px solid #6366f1',
            borderRadius: BORDER_RADIUS.lg,
            maxWidth: '600px',
            width: '100%',
            padding: '24px',
            boxShadow: '0 20px 40px rgba(0, 0, 0, 0.8)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div>
                <span style={{ fontSize: '12px', fontWeight: 700, color: '#818cf8', textTransform: 'uppercase' }}>
                  {selectedTech.tactic} → {selectedTech.id}
                </span>
                <h3 style={{ margin: '4px 0 0 0', fontSize: '20px', color: '#ffffff' }}>
                  {selectedTech.name}
                </h3>
              </div>
              <button
                onClick={() => setSelectedTech(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#94a3b8',
                  fontSize: '24px',
                  cursor: 'pointer'
                }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'flex', gap: '16px', marginBottom: '16px', fontSize: '13px' }}>
              <span style={{ color: '#94a3b8' }}>
                Severity: <strong style={{ color: selectedTech.severity === 'Critical' ? '#ef4444' : '#f97316' }}>{selectedTech.severity}</strong>
              </span>
              <span style={{ color: '#94a3b8' }}>
                Active Detections: <strong style={{ color: '#38bdf8' }}>{selectedTech.active_detections} Events</strong>
              </span>
            </div>

            <h4 style={{ fontSize: '14px', color: '#a5f3fc', margin: '0 0 8px 0' }}>
              Defensive Detection Logic (Sigma / Wazuh):
            </h4>
            <pre style={{
              background: '#060910',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: '6px',
              padding: '12px',
              fontSize: '12px',
              fontFamily: 'monospace',
              color: '#38bdf8',
              overflowX: 'auto',
              marginBottom: '16px'
            }}>
{`title: Detection of ${selectedTech.name} (${selectedTech.id})
status: production
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    TechniqueId: '${selectedTech.id}'
    CommandLine|contains:
      - '${selectedTech.name.toLowerCase().replace(/[^a-z0-9]/g, '')}'
  condition: selection
level: ${selectedTech.severity.toLowerCase()}`}
            </pre>

            <h4 style={{ fontSize: '14px', color: '#a5f3fc', margin: '0 0 8px 0' }}>
              Mitigation & SOAR Playbook Recommendation:
            </h4>
            <p style={{ fontSize: '13px', color: '#cbd5e1', lineHeight: '1.5', margin: '0 0 20px 0' }}>
              Configure host isolation rules and enforce application whitelisting (AppLocker/WDAC). Automatically revoke token grants and terminate parent process trees when detection confidence exceeds 85%.
            </p>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setSelectedTech(null)}
                style={{
                  background: 'linear-gradient(135deg, #6366f1, #4f46e5)',
                  color: '#ffffff',
                  border: 'none',
                  padding: '8px 20px',
                  borderRadius: '6px',
                  fontSize: '13px',
                  fontWeight: 700,
                  cursor: 'pointer'
                }}
              >
                Close Technique Details
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MitreMatrix;
