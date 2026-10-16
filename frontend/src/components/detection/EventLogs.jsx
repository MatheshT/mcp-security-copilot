import React, { useState, useEffect } from 'react';
import { getEventLogs } from '../../services/api';

const EventLogs = () => {
  const [logs, setLogs] = useState([]);
  const [filteredLogs, setFilteredLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedLog, setSelectedLog] = useState(null);
  const [filters, setFilters] = useState({
    source: 'all',
    level: 'all',
    timeRange: '24h',
    search: ''
  });
  const [autoRefresh, setAutoRefresh] = useState(false);

  useEffect(() => {
    loadLogs();
  }, [filters.timeRange]);

  useEffect(() => {
    let interval;
    if (autoRefresh) {
      interval = setInterval(() => loadLogs(), 30000); // Refresh every 30 seconds
    }
    return () => clearInterval(interval);
  }, [autoRefresh, filters.timeRange]);

  useEffect(() => {
    applyFilters();
  }, [logs, filters]);

  const loadLogs = async () => {
    try {
      setLoading(true);
      setError(null);

      const logsData = await getEventLogs(filters.timeRange);
      if (logsData) {
        setLogs(logsData.logs || []);
      }
    } catch (err) {
      console.error('Error loading event logs:', err);
      setError('Failed to load event logs. Using mock data for demonstration.');
      loadMockLogs();
    } finally {
      setLoading(false);
    }
  };

  const loadMockLogs = () => {
    const mockLogs = [
      {
        id: 1,
        timestamp: '2024-01-15T10:30:45Z',
        source: 'Windows Event Log',
        level: 'Error',
        event_id: 4625,
        computer: 'DC-01',
        message: 'An account failed to log on. Subject: Security ID: S-1-5-18, Account Name: DC-01$, Account Domain: CORP. Account That Failed to Log On: Security ID: S-1-5-21-123456789-1234567890-1234567890-1234, Account Name: user1, Account Domain: CORP',
        category: 'Security',
        keywords: ['Audit Failure'],
        data: {
          logon_type: '3',
          logon_process: 'NtLmSsp',
          source_network_address: '192.168.1.100',
          source_port: '54321'
        }
      },
      {
        id: 2,
        timestamp: '2024-01-15T10:28:32Z',
        source: 'Sysmon',
        level: 'Warning',
        event_id: 1,
        computer: 'WORKSTATION-15',
        message: 'Process created: Command line: C:\\Windows\\System32\\powershell.exe -EncodedCommand SQBuAH...',
        category: 'Process Creation',
        keywords: ['Process Create'],
        data: {
          process_id: 4567,
          parent_process_id: 1234,
          image: 'C:\\Windows\\System32\\powershell.exe',
          command_line: 'powershell.exe -EncodedCommand SQBuAH...',
          user: 'CORP\\user2',
          integrity_level: 'Medium'
        }
      },
      {
        id: 3,
        timestamp: '2024-01-15T10:25:18Z',
        source: 'Wazuh',
        level: 'Critical',
        event_id: 1001,
        computer: 'WEB-SERVER-01',
        message: 'SSH brute force attack detected. Multiple failed login attempts from 203.0.113.45',
        category: 'Authentication',
        keywords: ['Brute Force', 'SSH'],
        data: {
          rule: 'SSH Brute Force',
          level: 12,
          src_ip: '203.0.113.45',
          dst_ip: '192.168.1.10',
          dst_port: 22,
          attempts: 45
        }
      },
      {
        id: 4,
        timestamp: '2024-01-15T10:22:05Z',
        source: 'Windows Defender',
        level: 'Error',
        event_id: 1116,
        computer: 'WORKSTATION-08',
        message: 'Malware detected: Trojan:Win32/Generic!BT. File: C:\\Users\\temp\\downloads\\suspicious.exe',
        category: 'Malware Protection',
        keywords: ['Malware', 'Trojan'],
        data: {
          threat_name: 'Trojan:Win32/Generic!BT',
          threat_id: '2147716458',
          resource_path: 'C:\\Users\\temp\\downloads\\suspicious.exe',
          process_name: 'unknown',
          user: 'CORP\\user3',
          action_taken: 'Quarantined'
        }
      },
      {
        id: 5,
        timestamp: '2024-01-15T10:18:42Z',
        source: 'Windows Event Log',
        level: 'Information',
        event_id: 4624,
        computer: 'DC-01',
        message: 'An account was successfully logged on. Subject: Security ID: S-1-5-18, Account Name: DC-01$, Account Domain: CORP. Account That Was Logged On: Security ID: S-1-5-21-123456789-1234567890-1234567890-5678, Account Name: admin, Account Domain: CORP',
        category: 'Security',
        keywords: ['Audit Success'],
        data: {
          logon_type: '2',
          logon_process: 'Advapi',
          source_network_address: '-',
          source_port: '-'
        }
      },
      {
        id: 6,
        timestamp: '2024-01-15T10:15:30Z',
        source: 'Sysmon',
        level: 'Warning',
        event_id: 3,
        computer: 'DB-SERVER-02',
        message: 'Network connection initialized: Protocol: TCP, Destination IP: 203.0.113.50, Destination Port: 443',
        category: 'Network Connection',
        keywords: ['Network Connect'],
        data: {
          process_id: 7890,
          image: 'C:\\Program Files\\MySQL\\MySQL Server 8.0\\bin\\mysqld.exe',
          destination_ip: '203.0.113.50',
          destination_port: 443,
          source_ip: '192.168.1.20',
          source_port: 54321,
          protocol: 'tcp',
          user: 'CORP\\SYSTEM'
        }
      },
      {
        id: 7,
        timestamp: '2024-01-15T10:12:15Z',
        source: 'Wazuh',
        level: 'High',
        event_id: 1002,
        computer: 'FILE-SERVER-01',
        message: 'File integrity monitoring detected changes in critical system directory',
        category: 'File Integrity',
        keywords: ['FIM', 'File Modification'],
        data: {
          rule: 'File Modification',
          level: 10,
          path: 'C:\\Windows\\System32\\drivers',
          changed_files: ['sysdrv.sys', 'netflt.sys'],
          md5_changed: true
        }
      },
      {
        id: 8,
        timestamp: '2024-01-15T10:08:55Z',
        source: 'Windows Event Log',
        level: 'Warning',
        event_id: 4740,
        computer: 'DC-01',
        message: 'A user account was locked out. Account Name: user4, Account Domain: CORP',
        category: 'Security',
        keywords: ['Account Lockout'],
        data: {
          caller_process_name: 'C:\\Windows\\System32\\lsass.exe',
          caller_process_id: 876,
          target_user_name: 'user4',
          target_domain_name: 'CORP',
          lockout_time: '2024-01-15T10:08:55Z'
        }
      },
      {
        id: 9,
        timestamp: '2024-01-15T10:05:22Z',
        source: 'Sysmon',
        level: 'Information',
        event_id: 7,
        computer: 'WEB-SERVER-02',
        message: 'Image loaded: Process ID: 3456, Image: C:\\Windows\\System32\\kernel32.dll',
        category: 'Image Loaded',
        keywords: ['Image Load'],
        data: {
          process_id: 3456,
          image: 'C:\\Windows\\System32\\kernel32.dll',
          file_version: '10.0.19041.1',
          signature_status: 'Valid',
          signed: true
        }
      },
      {
        id: 10,
        timestamp: '2024-01-15T10:02:10Z',
        source: 'Wazuh',
        level: 'Medium',
        event_id: 1003,
        computer: 'MAIL-SERVER-01',
        message: 'Unusual DNS query detected to suspicious domain',
        category: 'DNS',
        keywords: ['DNS', 'Suspicious'],
        data: {
          rule: 'DNS Anomaly',
          level: 7,
          query_type: 'A',
          query: 'suspicious-domain.com',
          answer: '203.0.113.100',
          client_ip: '192.168.1.40'
        }
      }
    ];

    setLogs(mockLogs);
  };

  const applyFilters = () => {
    let filtered = [...logs];

    if (filters.source !== 'all') {
      filtered = filtered.filter(log => 
        log.source.toLowerCase() === filters.source.toLowerCase()
      );
    }

    if (filters.level !== 'all') {
      filtered = filtered.filter(log => 
        log.level.toLowerCase() === filters.level.toLowerCase()
      );
    }

    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      filtered = filtered.filter(log => 
        log.message.toLowerCase().includes(searchLower) ||
        log.computer.toLowerCase().includes(searchLower) ||
        log.category.toLowerCase().includes(searchLower)
      );
    }

    setFilteredLogs(filtered);
  };

  const getLevelColor = (level) => {
    switch (level?.toLowerCase()) {
      case 'critical': return '#dc2626';
      case 'error': return '#dc2626';
      case 'warning': return '#ca8a04';
      case 'information': return '#3b82f6';
      default: return '#6b7280';
    }
  };

  const getSourceIcon = (source) => {
    switch (source?.toLowerCase()) {
      case 'windows event log': return '🪟';
      case 'sysmon': return '🔍';
      case 'wazuh': return '🛡️';
      case 'windows defender': return '🦠';
      default: return '📋';
    }
  };

  const handleLogClick = (log) => {
    setSelectedLog(log);
  };

  const closeLogDetails = () => {
    setSelectedLog(null);
  };

  const exportLogs = () => {
    const csv = [
      ['Timestamp', 'Source', 'Level', 'Computer', 'Event ID', 'Category', 'Message'].join(','),
      ...filteredLogs.map(log => [
        log.timestamp,
        log.source,
        log.level,
        log.computer,
        log.event_id,
        log.category,
        `"${log.message.replace(/"/g, '""')}"`
      ].join(','))
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `event-logs-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div style={{ padding: '20px', textAlign: 'center' }}>
        <div style={{ fontSize: '18px', color: '#666' }}>Loading event logs...</div>
      </div>
    );
  }

  return (
    <div className="detection-dark-view" style={{ padding: '20px', fontFamily: 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif' }}>
      <div style={{ marginBottom: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ margin: 0, color: '#1e3a5f' }}>📋 Event Logs</h2>
          <p style={{ color: '#6b7280', margin: '8px 0 0 0' }}>
            Total: {filteredLogs.length} events
          </p>
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '14px' }}>
            <input 
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            Auto-refresh (30s)
          </label>
          <button 
            onClick={exportLogs}
            style={{ 
              padding: '8px 16px', 
              backgroundColor: '#3b82f6', 
              color: 'white', 
              border: 'none', 
              borderRadius: '4px', 
              cursor: 'pointer' 
            }}
          >
            📥 Export CSV
          </button>
          <button 
            onClick={loadLogs}
            style={{ 
              padding: '8px 16px', 
              backgroundColor: '#6b7280', 
              color: 'white', 
              border: 'none', 
              borderRadius: '4px', 
              cursor: 'pointer' 
            }}
          >
            🔄 Refresh
          </button>
        </div>
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
        backgroundColor: 'var(--bg-surface)',
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
            Source
          </label>
          <select 
            value={filters.source}
            onChange={(e) => setFilters({ ...filters, source: e.target.value })}
            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #d1d5db' }}
          >
            <option value="all">All Sources</option>
            <option value="windows event log">Windows Event Log</option>
            <option value="sysmon">Sysmon</option>
            <option value="wazuh">Wazuh</option>
            <option value="windows defender">Windows Defender</option>
          </select>
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '14px', color: '#6b7280', marginBottom: '4px' }}>
            Level
          </label>
          <select 
            value={filters.level}
            onChange={(e) => setFilters({ ...filters, level: e.target.value })}
            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #d1d5db' }}
          >
            <option value="all">All Levels</option>
            <option value="critical">Critical</option>
            <option value="error">Error</option>
            <option value="warning">Warning</option>
            <option value="information">Information</option>
          </select>
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '14px', color: '#6b7280', marginBottom: '4px' }}>
            Time Range
          </label>
          <select 
            value={filters.timeRange}
            onChange={(e) => setFilters({ ...filters, timeRange: e.target.value })}
            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #d1d5db' }}
          >
            <option value="1h">Last 1 hour</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
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
            placeholder="Search logs..."
            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #d1d5db' }}
          />
        </div>
      </div>

      {/* Logs List */}
      <div style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.35)' }}>
        {filteredLogs.length === 0 ? (
          <div style={{ padding: '40px', textAlign: 'center', color: '#6b7280' }}>
            No logs found matching the current filters
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #e5e7eb', backgroundColor: '#f9fafb' }}>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Timestamp</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Source</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Level</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Computer</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Category</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Message</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.map((log) => (
                  <tr 
                    key={log.id} 
                    style={{ borderBottom: '1px solid #e5e7eb', cursor: 'pointer' }}
                    onClick={() => handleLogClick(log)}
                    onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#f9fafb'}
                    onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                  >
                    <td style={{ padding: '12px', fontSize: '14px', whiteSpace: 'nowrap' }}>
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td style={{ padding: '12px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <span>{getSourceIcon(log.source)}</span>
                        <span>{log.source}</span>
                      </div>
                    </td>
                    <td style={{ padding: '12px' }}>
                      <span style={{ 
                        padding: '4px 8px', 
                        borderRadius: '4px', 
                        backgroundColor: getLevelColor(log.level),
                        color: 'white',
                        fontSize: '12px',
                        fontWeight: '500'
                      }}>
                        {log.level}
                      </span>
                    </td>
                    <td style={{ padding: '12px', fontFamily: 'monospace' }}>{log.computer}</td>
                    <td style={{ padding: '12px' }}>{log.category}</td>
                    <td style={{ padding: '12px', maxWidth: '400px' }}>
                      <div style={{ 
                        overflow: 'hidden', 
                        textOverflow: 'ellipsis', 
                        whiteSpace: 'nowrap',
                        color: '#374151'
                      }}>
                        {log.message}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Log Details Modal */}
      {selectedLog && (
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
            backgroundColor: 'var(--bg-surface)', 
            borderRadius: '8px', 
            maxWidth: '900px', 
            width: '90%', 
            maxHeight: '90vh', 
            overflow: 'auto',
            padding: '24px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '20px' }}>
              <h3 style={{ margin: 0, color: '#1e3a5f' }}>
                {getSourceIcon(selectedLog.source)} Event Details
              </h3>
              <button 
                onClick={closeLogDetails}
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
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Timestamp</label>
                <div style={{ marginTop: '4px', fontSize: '14px' }}>
                  {new Date(selectedLog.timestamp).toLocaleString()}
                </div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Source</label>
                <div style={{ marginTop: '4px', fontWeight: '500' }}>{selectedLog.source}</div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Level</label>
                <div style={{ marginTop: '4px' }}>
                  <span style={{ 
                    padding: '4px 8px', 
                    borderRadius: '4px', 
                    backgroundColor: getLevelColor(selectedLog.level),
                    color: 'white',
                    fontSize: '12px',
                    fontWeight: '500'
                  }}>
                    {selectedLog.level}
                  </span>
                </div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Event ID</label>
                <div style={{ marginTop: '4px', fontFamily: 'monospace' }}>{selectedLog.event_id}</div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Computer</label>
                <div style={{ marginTop: '4px', fontFamily: 'monospace' }}>{selectedLog.computer}</div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Category</label>
                <div style={{ marginTop: '4px', fontWeight: '500' }}>{selectedLog.category}</div>
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '12px', color: '#6b7280' }}>Message</label>
              <div style={{ 
                marginTop: '4px', 
                padding: '12px', 
                backgroundColor: '#f9fafb', 
                borderRadius: '4px',
                fontFamily: 'monospace',
                fontSize: '13px',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word'
              }}>
                {selectedLog.message}
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '12px', color: '#6b7280' }}>Keywords</label>
              <div style={{ marginTop: '4px', display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {selectedLog.keywords?.map((keyword, index) => (
                  <span key={index} style={{ 
                    padding: '4px 8px', 
                    backgroundColor: '#dbeafe', 
                    borderRadius: '4px', 
                    fontSize: '12px',
                    color: '#1e40af'
                  }}>
                    {keyword}
                  </span>
                ))}
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '12px', color: '#6b7280' }}>Event Data</label>
              <div style={{ 
                marginTop: '4px', 
                padding: '12px', 
                backgroundColor: '#1e3a5f', 
                borderRadius: '4px',
                fontFamily: 'monospace',
                fontSize: '13px',
                color: '#ecfdf5',
                overflow: 'auto'
              }}>
                <pre style={{ margin: 0 }}>{JSON.stringify(selectedLog.data, null, 2)}</pre>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
              <button 
                onClick={closeLogDetails}
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

export default EventLogs;