import React, { useState, useEffect } from 'react';
import api from '../../services/api';

const Alerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [filteredAlerts, setFilteredAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [filters, setFilters] = useState({
    severity: 'all',
    status: 'all',
    source: 'all',
    search: ''
  });

  useEffect(() => {
    loadAlerts();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [alerts, filters]);

  const loadAlerts = async () => {
    try {
      setLoading(true);
      setError(null);

      const alertsData = await api.getAlerts();
      if (alertsData) {
        setAlerts(alertsData.alerts || []);
      }
    } catch (err) {
      console.error('Error loading alerts:', err);
      setError('Failed to load alerts. Using mock data for demonstration.');
      loadMockAlerts();
    } finally {
      setLoading(false);
    }
  };

  const loadMockAlerts = () => {
    const mockAlerts = [
      {
        id: 1,
        title: 'SSH Brute Force Attack Detected',
        severity: 'Critical',
        status: 'Open',
        source: 'Wazuh',
        agent: 'web-server-01',
        timestamp: '2024-01-15T10:30:00Z',
        description: 'Multiple failed SSH login attempts detected from IP 192.168.1.100',
        rule: 'SSH Brute Force',
        level: 12,
        iocs: ['192.168.1.100', 'root', 'ssh'],
        mitigation: 'Block source IP and implement rate limiting'
      },
      {
        id: 2,
        title: 'Malware Signature Detected',
        severity: 'High',
        status: 'Open',
        source: 'Windows Defender',
        agent: 'workstation-15',
        timestamp: '2024-01-15T10:15:00Z',
        description: 'Known malware signature detected in file: C:\\Users\\temp\\suspicious.exe',
        rule: 'Malware Detection',
        level: 10,
        iocs: ['C:\\Users\\temp\\suspicious.exe', 'Trojan.Win32.Generic'],
        mitigation: 'Isolate endpoint and perform full system scan'
      },
      {
        id: 3,
        title: 'Suspicious Process Execution',
        severity: 'Medium',
        status: 'Investigating',
        source: 'Sysmon',
        agent: 'db-server-02',
        timestamp: '2024-01-15T10:00:00Z',
        description: 'Unusual process execution pattern detected: powershell.exe with encoded command',
        rule: 'Suspicious Process',
        level: 8,
        iocs: ['powershell.exe', 'encoded-command'],
        mitigation: 'Investigate process chain and user activity'
      },
      {
        id: 4,
        title: 'System File Modification',
        severity: 'Low',
        status: 'Closed',
        source: 'Windows Event Log',
        agent: 'file-server-01',
        timestamp: '2024-01-15T09:45:00Z',
        description: 'System file modification detected in C:\\Windows\\System32\\drivers',
        rule: 'File Modification',
        level: 6,
        iocs: ['C:\\Windows\\System32\\drivers'],
        mitigation: 'Verify file integrity and check for unauthorized changes'
      },
      {
        id: 5,
        title: 'Network Anomaly Detected',
        severity: 'Medium',
        status: 'Open',
        source: 'Wazuh',
        agent: 'web-server-02',
        timestamp: '2024-01-15T09:30:00Z',
        description: 'Unusual network traffic pattern detected: large data transfer to external IP',
        rule: 'Network Anomaly',
        level: 7,
        iocs: ['203.0.113.45', 'large-transfer'],
        mitigation: 'Investigate data transfer and verify destination'
      },
      {
        id: 6,
        title: 'Privilege Escalation Attempt',
        severity: 'High',
        status: 'Investigating',
        source: 'Windows Event Log',
        agent: 'workstation-08',
        timestamp: '2024-01-15T09:15:00Z',
        description: 'Privilege escalation attempt detected via exploit of vulnerable service',
        rule: 'Privilege Escalation',
        level: 11,
        iocs: ['CVE-2023-1234', 'administrator'],
        mitigation: 'Isolate system and patch vulnerability'
      },
      {
        id: 7,
        title: 'Multiple Failed Logins',
        severity: 'Medium',
        status: 'Open',
        source: 'Windows Event Log',
        agent: 'dc-01',
        timestamp: '2024-01-15T09:00:00Z',
        description: 'Multiple failed login attempts detected for user account',
        rule: 'Failed Logins',
        level: 8,
        iocs: ['user1@domain.com', '46 failed attempts'],
        mitigation: 'Lock account and investigate source'
      },
      {
        id: 8,
        title: 'DNS Tunneling Detected',
        severity: 'High',
        status: 'Open',
        source: 'Wazuh',
        agent: 'workstation-12',
        timestamp: '2024-01-15T08:45:00Z',
        description: 'DNS tunneling activity detected to suspicious domain',
        rule: 'DNS Tunneling',
        level: 10,
        iocs: ['suspicious-domain.com', 'DNS tunneling'],
        mitigation: 'Block domain and investigate compromised host'
      }
    ];

    setAlerts(mockAlerts);
  };

  const applyFilters = () => {
    let filtered = [...alerts];

    if (filters.severity !== 'all') {
      filtered = filtered.filter(alert => 
        alert.severity.toLowerCase() === filters.severity.toLowerCase()
      );
    }

    if (filters.status !== 'all') {
      filtered = filtered.filter(alert => 
        alert.status.toLowerCase() === filters.status.toLowerCase()
      );
    }

    if (filters.source !== 'all') {
      filtered = filtered.filter(alert => 
        alert.source.toLowerCase() === filters.source.toLowerCase()
      );
    }

    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      filtered = filtered.filter(alert => 
        alert.title.toLowerCase().includes(searchLower) ||
        alert.description.toLowerCase().includes(searchLower) ||
        alert.agent.toLowerCase().includes(searchLower)
      );
    }

    setFilteredAlerts(filtered);
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return '#dc2626';
      case 'high': return '#ea580c';
      case 'medium': return '#ca8a04';
      case 'low': return '#16a34a';
      default: return '#6b7280';
    }
  };

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'open': return '#dc2626';
      case 'investigating': return '#ca8a04';
      case 'closed': return '#16a34a';
      default: return '#6b7280';
    }
  };

  const handleAlertClick = (alert) => {
    setSelectedAlert(alert);
  };

  const closeAlertDetails = () => {
    setSelectedAlert(null);
  };

  const updateAlertStatus = async (alertId, newStatus) => {
    try {
      await api.updateAlertStatus(alertId, newStatus);
      setAlerts(alerts.map(alert => 
        alert.id === alertId ? { ...alert, status: newStatus } : alert
      ));
    } catch (err) {
      console.error('Error updating alert status:', err);
      // Mock update for demo
      setAlerts(alerts.map(alert => 
        alert.id === alertId ? { ...alert, status: newStatus } : alert
      ));
    }
  };

  if (loading) {
    return (
      <div style={{ padding: '20px', textAlign: 'center' }}>
        <div style={{ fontSize: '18px', color: '#666' }}>Loading alerts...</div>
      </div>
    );
  }

  return (
    <div style={{ padding: '20px', fontFamily: 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif' }}>
      <div style={{ marginBottom: '20px' }}>
        <h2 style={{ margin: 0, color: '#1e3a5f' }}>🚨 Security Alerts</h2>
        <p style={{ color: '#6b7280', margin: '8px 0 0 0' }}>
          Total: {filteredAlerts.length} alerts
        </p>
      </div>

      {error && (
        <div style={{ 
          padding: '12px', 
          backgroundColor: '#fef3c7', 
          border: '1px solid #f59e0b', 
          borderRadius: '4px', 
          marginBottom: '20px',
          color: '#92400e'
        }}>
          ⚠️ {error}
        </div>
      )}

      {/* Filters */}
      <div style={{ 
        backgroundColor: 'white', 
        padding: '16px', 
        borderRadius: '8px', 
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)', 
        marginBottom: '20px',
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '12px'
      }}>
        <div>
          <label style={{ display: 'block', fontSize: '14px', color: '#6b7280', marginBottom: '4px' }}>
            Severity
          </label>
          <select 
            value={filters.severity}
            onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #d1d5db' }}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '14px', color: '#6b7280', marginBottom: '4px' }}>
            Status
          </label>
          <select 
            value={filters.status}
            onChange={(e) => setFilters({ ...filters, status: e.target.value })}
            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #d1d5db' }}
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="closed">Closed</option>
          </select>
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '14px', color: '#6b7280', marginBottom: '4px' }}>
            Source
          </label>
          <select 
            value={filters.source}
            onChange={(e) => setFilters({ ...filters, source: e.target.value })}
            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #d1d5db' }}
          >
            <option value="all">All Sources</option>
            <option value="wazuh">Wazuh</option>
            <option value="windows defender">Windows Defender</option>
            <option value="sysmon">Sysmon</option>
            <option value="windows event log">Windows Event Log</option>
          </select>
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '14px', color: '#6b7280', marginBottom: '4px' }}>
            Search
          </label>
          <input 
            type="text"
            value={filters.search}
            onChange={(e) => setFilters({ ...filters, search: e.target.value })}
            placeholder="Search alerts..."
            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #d1d5db' }}
          />
        </div>
      </div>

      {/* Alerts List */}
      <div style={{ backgroundColor: 'white', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
        {filteredAlerts.length === 0 ? (
          <div style={{ padding: '40px', textAlign: 'center', color: '#6b7280' }}>
            No alerts found matching the current filters
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #e5e7eb', backgroundColor: '#f9fafb' }}>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Title</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Severity</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Status</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Source</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Agent</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((alert) => (
                  <tr 
                    key={alert.id} 
                    style={{ borderBottom: '1px solid #e5e7eb', cursor: 'pointer' }}
                    onClick={() => handleAlertClick(alert)}
                    onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#f9fafb'}
                    onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                  >
                    <td style={{ padding: '12px' }}>
                      <div style={{ fontWeight: '500', color: '#1e3a5f' }}>{alert.title}</div>
                      <div style={{ fontSize: '12px', color: '#6b7280', marginTop: '2px' }}>
                        {alert.rule}
                      </div>
                    </td>
                    <td style={{ padding: '12px' }}>
                      <span style={{ 
                        padding: '4px 8px', 
                        borderRadius: '4px', 
                        backgroundColor: getSeverityColor(alert.severity),
                        color: 'white',
                        fontSize: '12px',
                        fontWeight: '500'
                      }}>
                        {alert.severity}
                      </span>
                    </td>
                    <td style={{ padding: '12px' }}>
                      <span style={{ 
                        padding: '4px 8px', 
                        borderRadius: '4px', 
                        backgroundColor: getStatusColor(alert.status),
                        color: 'white',
                        fontSize: '12px',
                        fontWeight: '500'
                      }}>
                        {alert.status}
                      </span>
                    </td>
                    <td style={{ padding: '12px' }}>{alert.source}</td>
                    <td style={{ padding: '12px', fontFamily: 'monospace' }}>{alert.agent}</td>
                    <td style={{ padding: '12px', fontSize: '14px' }}>
                      {new Date(alert.timestamp).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Alert Details Modal */}
      {selectedAlert && (
        <div style={{ 
          position: 'fixed', 
          top: 0, 
          left: 0, 
          right: 0, 
          bottom: 0, 
          backgroundColor: 'rgba(0,0,0,0.5)', 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{ 
            backgroundColor: 'white', 
            borderRadius: '8px', 
            maxWidth: '800px', 
            width: '90%', 
            maxHeight: '90vh', 
            overflow: 'auto',
            padding: '24px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '20px' }}>
              <h3 style={{ margin: 0, color: '#1e3a5f' }}>{selectedAlert.title}</h3>
              <button 
                onClick={closeAlertDetails}
                style={{ 
                  padding: '8px 12px', 
                  backgroundColor: '#f3f4f6', 
                  border: 'none', 
                  borderRadius: '4px', 
                  cursor: 'pointer' 
                }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '16px', marginBottom: '20px' }}>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Severity</label>
                <div style={{ marginTop: '4px' }}>
                  <span style={{ 
                    padding: '4px 8px', 
                    borderRadius: '4px', 
                    backgroundColor: getSeverityColor(selectedAlert.severity),
                    color: 'white',
                    fontSize: '12px',
                    fontWeight: '500'
                  }}>
                    {selectedAlert.severity}
                  </span>
                </div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Status</label>
                <div style={{ marginTop: '4px' }}>
                  <span style={{ 
                    padding: '4px 8px', 
                    borderRadius: '4px', 
                    backgroundColor: getStatusColor(selectedAlert.status),
                    color: 'white',
                    fontSize: '12px',
                    fontWeight: '500'
                  }}>
                    {selectedAlert.status}
                  </span>
                </div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Source</label>
                <div style={{ marginTop: '4px', fontWeight: '500' }}>{selectedAlert.source}</div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Agent</label>
                <div style={{ marginTop: '4px', fontFamily: 'monospace' }}>{selectedAlert.agent}</div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Rule</label>
                <div style={{ marginTop: '4px', fontWeight: '500' }}>{selectedAlert.rule}</div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Level</label>
                <div style={{ marginTop: '4px', fontWeight: '500' }}>{selectedAlert.level}</div>
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '12px', color: '#6b7280' }}>Description</label>
              <div style={{ marginTop: '4px', padding: '12px', backgroundColor: '#f9fafb', borderRadius: '4px' }}>
                {selectedAlert.description}
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '12px', color: '#6b7280' }}>IOCs</label>
              <div style={{ marginTop: '4px', display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {selectedAlert.iocs?.map((ioc, index) => (
                  <span key={index} style={{ 
                    padding: '4px 8px', 
                    backgroundColor: '#fef3c7', 
                    borderRadius: '4px', 
                    fontSize: '12px',
                    fontFamily: 'monospace'
                  }}>
                    {ioc}
                  </span>
                ))}
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '12px', color: '#6b7280' }}>Mitigation</label>
              <div style={{ marginTop: '4px', padding: '12px', backgroundColor: '#ecfdf5', borderRadius: '4px', color: '#065f46' }}>
                {selectedAlert.mitigation}
              </div>
            </div>

            <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
              <select 
                value={selectedAlert.status}
                onChange={(e) => updateAlertStatus(selectedAlert.id, e.target.value)}
                style={{ padding: '8px', borderRadius: '4px', border: '1px solid #d1d5db' }}
              >
                <option value="Open">Open</option>
                <option value="Investigating">Investigating</option>
                <option value="Closed">Closed</option>
              </select>
              <button 
                onClick={closeAlertDetails}
                style={{ 
                  padding: '8px 16px', 
                  backgroundColor: '#3b82f6', 
                  color: 'white', 
                  border: 'none', 
                  borderRadius: '4px', 
                  cursor: 'pointer' 
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Alerts;