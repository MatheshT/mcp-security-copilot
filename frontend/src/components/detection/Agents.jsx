import React, { useState, useEffect } from 'react';
import api from '../../services/api';

const Agents = () => {
  const [agents, setAgents] = useState([]);
  const [filteredAgents, setFilteredAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [filters, setFilters] = useState({
    status: 'all',
    os: 'all',
    search: ''
  });

  useEffect(() => {
    loadAgents();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [agents, filters]);

  const loadAgents = async () => {
    try {
      setLoading(true);
      setError(null);

      const agentsData = await api.getWazuhAgents();
      if (agentsData) {
        setAgents(agentsData.agents || []);
      }
    } catch (err) {
      console.error('Error loading agents:', err);
      setError('Failed to load agents. Using mock data for demonstration.');
      loadMockAgents();
    } finally {
      setLoading(false);
    }
  };

  const loadMockAgents = () => {
    const mockAgents = [
      {
        id: '001',
        name: 'web-server-01',
        ip: '192.168.1.10',
        status: 'active',
        os: 'Ubuntu 22.04 LTS',
        version: '4.4.0',
        last_keepalive: '2024-01-15T10:30:00Z',
        first_keepalive: '2024-01-01T00:00:00Z',
        config_sum: 'abc123',
        merged_sum: 'def456',
        manager_host: 'wazuh-manager',
        node_name: 'node-01',
        group: ['web-servers', 'production'],
        active_events: 234,
        alerts_count: 12,
        vulnerability_count: 3
      },
      {
        id: '002',
        name: 'web-server-02',
        ip: '192.168.1.11',
        status: 'active',
        os: 'Ubuntu 22.04 LTS',
        version: '4.4.0',
        last_keepalive: '2024-01-15T10:29:00Z',
        first_keepalive: '2024-01-01T00:00:00Z',
        config_sum: 'ghi789',
        merged_sum: 'jkl012',
        manager_host: 'wazuh-manager',
        node_name: 'node-01',
        group: ['web-servers', 'production'],
        active_events: 189,
        alerts_count: 8,
        vulnerability_count: 1
      },
      {
        id: '003',
        name: 'db-server-01',
        ip: '192.168.1.20',
        status: 'active',
        os: 'CentOS 8',
        version: '4.3.0',
        last_keepalive: '2024-01-15T10:28:00Z',
        first_keepalive: '2024-01-02T00:00:00Z',
        config_sum: 'mno345',
        merged_sum: 'pqr678',
        manager_host: 'wazuh-manager',
        node_name: 'node-02',
        group: ['database-servers', 'production'],
        active_events: 567,
        alerts_count: 23,
        vulnerability_count: 5
      },
      {
        id: '004',
        name: 'workstation-15',
        ip: '192.168.2.45',
        status: 'disconnected',
        os: 'Windows 11',
        version: '4.4.0',
        last_keepalive: '2024-01-15T08:00:00Z',
        first_keepalive: '2024-01-05T00:00:00Z',
        config_sum: 'stu901',
        merged_sum: 'vwx234',
        manager_host: 'wazuh-manager',
        node_name: 'node-01',
        group: ['workstations', 'office'],
        active_events: 0,
        alerts_count: 0,
        vulnerability_count: 0
      },
      {
        id: '005',
        name: 'file-server-01',
        ip: '192.168.1.30',
        status: 'active',
        os: 'Windows Server 2022',
        version: '4.4.0',
        last_keepalive: '2024-01-15T10:30:00Z',
        first_keepalive: '2024-01-03T00:00:00Z',
        config_sum: 'yzab56',
        merged_sum: 'cdef78',
        manager_host: 'wazuh-manager',
        node_name: 'node-02',
        group: ['file-servers', 'production'],
        active_events: 123,
        alerts_count: 5,
        vulnerability_count: 2
      },
      {
        id: '006',
        name: 'mail-server-01',
        ip: '192.168.1.40',
        status: 'active',
        os: 'Ubuntu 20.04 LTS',
        version: '4.3.0',
        last_keepalive: '2024-01-15T10:27:00Z',
        first_keepalive: '2024-01-04T00:00:00Z',
        config_sum: 'ghij01',
        merged_sum: 'klmn23',
        manager_host: 'wazuh-manager',
        node_name: 'node-01',
        group: ['mail-servers', 'production'],
        active_events: 345,
        alerts_count: 15,
        vulnerability_count: 4
      },
      {
        id: '007',
        name: 'workstation-08',
        ip: '192.168.2.38',
        status: 'never_connected',
        os: 'Windows 10',
        version: '4.4.0',
        last_keepalive: null,
        first_keepalive: '2024-01-10T00:00:00Z',
        config_sum: 'opqr45',
        merged_sum: 'stuv67',
        manager_host: 'wazuh-manager',
        node_name: 'node-01',
        group: ['workstations', 'office'],
        active_events: 0,
        alerts_count: 0,
        vulnerability_count: 0
      },
      {
        id: '008',
        name: 'backup-server-01',
        ip: '192.168.1.50',
        status: 'active',
        os: 'Ubuntu 22.04 LTS',
        version: '4.4.0',
        last_keepalive: '2024-01-15T10:30:00Z',
        first_keepalive: '2024-01-06T00:00:00Z',
        config_sum: 'wxyz89',
        merged_sum: 'abcd01',
        manager_host: 'wazuh-manager',
        node_name: 'node-02',
        group: ['backup-servers', 'production'],
        active_events: 45,
        alerts_count: 2,
        vulnerability_count: 0
      }
    ];

    setAgents(mockAgents);
  };

  const applyFilters = () => {
    let filtered = [...agents];

    if (filters.status !== 'all') {
      filtered = filtered.filter(agent => 
        agent.status.toLowerCase() === filters.status.toLowerCase()
      );
    }

    if (filters.os !== 'all') {
      filtered = filtered.filter(agent => 
        agent.os.toLowerCase().includes(filters.os.toLowerCase())
      );
    }

    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      filtered = filtered.filter(agent => 
        agent.name.toLowerCase().includes(searchLower) ||
        agent.ip.includes(searchLower) ||
        agent.id.includes(searchLower)
      );
    }

    setFilteredAgents(filtered);
  };

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'active': return '#16a34a';
      case 'disconnected': return '#dc2626';
      case 'never_connected': return '#6b7280';
      default: return '#6b7280';
    }
  };

  const handleAgentClick = (agent) => {
    setSelectedAgent(agent);
  };

  const closeAgentDetails = () => {
    setSelectedAgent(null);
  };

  const restartAgent = async (agentId) => {
    try {
      await api.restartWazuhAgent(agentId);
      alert(`Agent ${agentId} restart command sent successfully`);
    } catch (err) {
      console.error('Error restarting agent:', err);
      alert(`Failed to restart agent ${agentId} (mock for demo)`);
    }
  };

  const getOSIcon = (os) => {
    if (os.toLowerCase().includes('windows')) return '🪟';
    if (os.toLowerCase().includes('ubuntu')) return '🐧';
    if (os.toLowerCase().includes('centos')) return '🐧';
    return '💻';
  };

  if (loading) {
    return (
      <div style={{ padding: '20px', textAlign: 'center' }}>
        <div style={{ fontSize: '18px', color: '#666' }}>Loading agents...</div>
      </div>
    );
  }

  const activeCount = agents.filter(a => a.status === 'active').length;
  const disconnectedCount = agents.filter(a => a.status === 'disconnected').length;
  const neverConnectedCount = agents.filter(a => a.status === 'never_connected').length;

  return (
    <div style={{ padding: '20px', fontFamily: 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif' }}>
      <div style={{ marginBottom: '20px' }}>
        <h2 style={{ margin: 0, color: '#1e3a5f' }}>🖥️ Wazuh Agents</h2>
        <p style={{ color: '#6b7280', margin: '8px 0 0 0' }}>
          Total: {agents.length} agents | Active: {activeCount} | Disconnected: {disconnectedCount} | Never Connected: {neverConnectedCount}
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

      {/* Statistics Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginBottom: '24px' }}>
        <StatCard title="Total Agents" value={agents.length} color="#3b82f6" icon="🖥️" />
        <StatCard title="Active Agents" value={activeCount} color="#16a34a" icon="✅" />
        <StatCard title="Disconnected" value={disconnectedCount} color="#dc2626" icon="❌" />
        <StatCard title="Never Connected" value={neverConnectedCount} color="#6b7280" icon="⚠️" />
      </div>

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
            Status
          </label>
          <select 
            value={filters.status}
            onChange={(e) => setFilters({ ...filters, status: e.target.value })}
            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #d1d5db' }}
          >
            <option value="all">All Statuses</option>
            <option value="active">Active</option>
            <option value="disconnected">Disconnected</option>
            <option value="never_connected">Never Connected</option>
          </select>
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '14px', color: '#6b7280', marginBottom: '4px' }}>
            Operating System
          </label>
          <select 
            value={filters.os}
            onChange={(e) => setFilters({ ...filters, os: e.target.value })}
            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #d1d5db' }}
          >
            <option value="all">All OS</option>
            <option value="windows">Windows</option>
            <option value="ubuntu">Ubuntu</option>
            <option value="centos">CentOS</option>
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
            placeholder="Search by name, IP, or ID..."
            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #d1d5db' }}
          />
        </div>
      </div>

      {/* Agents List */}
      <div style={{ backgroundColor: 'white', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
        {filteredAgents.length === 0 ? (
          <div style={{ padding: '40px', textAlign: 'center', color: '#6b7280' }}>
            No agents found matching the current filters
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #e5e7eb', backgroundColor: '#f9fafb' }}>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>ID</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Name</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>IP Address</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>OS</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Status</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Last Keepalive</th>
                  <th style={{ padding: '12px', textAlign: 'left', color: '#6b7280', fontWeight: '600' }}>Alerts</th>
                </tr>
              </thead>
              <tbody>
                {filteredAgents.map((agent) => (
                  <tr 
                    key={agent.id} 
                    style={{ borderBottom: '1px solid #e5e7eb', cursor: 'pointer' }}
                    onClick={() => handleAgentClick(agent)}
                    onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#f9fafb'}
                    onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                  >
                    <td style={{ padding: '12px', fontFamily: 'monospace' }}>{agent.id}</td>
                    <td style={{ padding: '12px' }}>
                      <div style={{ fontWeight: '500', color: '#1e3a5f' }}>{agent.name}</div>
                      <div style={{ fontSize: '12px', color: '#6b7280', marginTop: '2px' }}>
                        {agent.group?.join(', ')}
                      </div>
                    </td>
                    <td style={{ padding: '12px', fontFamily: 'monospace' }}>{agent.ip}</td>
                    <td style={{ padding: '12px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <span>{getOSIcon(agent.os)}</span>
                        <span>{agent.os}</span>
                      </div>
                    </td>
                    <td style={{ padding: '12px' }}>
                      <span style={{ 
                        padding: '4px 8px', 
                        borderRadius: '4px', 
                        backgroundColor: getStatusColor(agent.status),
                        color: 'white',
                        fontSize: '12px',
                        fontWeight: '500'
                      }}>
                        {agent.status}
                      </span>
                    </td>
                    <td style={{ padding: '12px', fontSize: '14px' }}>
                      {agent.last_keepalive ? new Date(agent.last_keepalive).toLocaleString() : 'Never'}
                    </td>
                    <td style={{ padding: '12px' }}>
                      <span style={{ 
                        padding: '4px 8px', 
                        borderRadius: '4px', 
                        backgroundColor: agent.alerts_count > 0 ? '#fef3c7' : '#ecfdf5',
                        color: agent.alerts_count > 0 ? '#92400e' : '#065f46',
                        fontSize: '12px',
                        fontWeight: '500'
                      }}>
                        {agent.alerts_count}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Agent Details Modal */}
      {selectedAgent && (
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
              <h3 style={{ margin: 0, color: '#1e3a5f' }}>
                {getOSIcon(selectedAgent.os)} {selectedAgent.name}
              </h3>
              <button 
                onClick={closeAgentDetails}
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
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Agent ID</label>
                <div style={{ marginTop: '4px', fontFamily: 'monospace' }}>{selectedAgent.id}</div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>IP Address</label>
                <div style={{ marginTop: '4px', fontFamily: 'monospace' }}>{selectedAgent.ip}</div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Status</label>
                <div style={{ marginTop: '4px' }}>
                  <span style={{ 
                    padding: '4px 8px', 
                    borderRadius: '4px', 
                    backgroundColor: getStatusColor(selectedAgent.status),
                    color: 'white',
                    fontSize: '12px',
                    fontWeight: '500'
                  }}>
                    {selectedAgent.status}
                  </span>
                </div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Version</label>
                <div style={{ marginTop: '4px', fontWeight: '500' }}>{selectedAgent.version}</div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Manager</label>
                <div style={{ marginTop: '4px', fontWeight: '500' }}>{selectedAgent.manager_host}</div>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7280' }}>Node</label>
                <div style={{ marginTop: '4px', fontWeight: '500' }}>{selectedAgent.node_name}</div>
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '12px', color: '#6b7280' }}>Groups</label>
              <div style={{ marginTop: '4px', display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {selectedAgent.group?.map((group, index) => (
                  <span key={index} style={{ 
                    padding: '4px 8px', 
                    backgroundColor: '#dbeafe', 
                    borderRadius: '4px', 
                    fontSize: '12px',
                    color: '#1e40af'
                  }}>
                    {group}
                  </span>
                ))}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '20px' }}>
              <div style={{ padding: '16px', backgroundColor: '#f9fafb', borderRadius: '8px', textAlign: 'center' }}>
                <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#1e3a5f' }}>{selectedAgent.active_events}</div>
                <div style={{ fontSize: '12px', color: '#6b7280' }}>Active Events</div>
              </div>
              <div style={{ padding: '16px', backgroundColor: '#f9fafb', borderRadius: '8px', textAlign: 'center' }}>
                <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#dc2626' }}>{selectedAgent.alerts_count}</div>
                <div style={{ fontSize: '12px', color: '#6b7280' }}>Alerts</div>
              </div>
              <div style={{ padding: '16px', backgroundColor: '#f9fafb', borderRadius: '8px', textAlign: 'center' }}>
                <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#ca8a04' }}>{selectedAgent.vulnerability_count}</div>
                <div style={{ fontSize: '12px', color: '#6b7280' }}>Vulnerabilities</div>
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '12px', color: '#6b7280' }}>First Keepalive</label>
              <div style={{ marginTop: '4px', fontSize: '14px' }}>
                {new Date(selectedAgent.first_keepalive).toLocaleString()}
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '12px', color: '#6b7280' }}>Last Keepalive</label>
              <div style={{ marginTop: '4px', fontSize: '14px' }}>
                {selectedAgent.last_keepalive ? new Date(selectedAgent.last_keepalive).toLocaleString() : 'Never'}
              </div>
            </div>

            <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
              <button 
                onClick={() => restartAgent(selectedAgent.id)}
                style={{ 
                  padding: '8px 16px', 
                  backgroundColor: '#f59e0b', 
                  color: 'white', 
                  border: 'none', 
                  borderRadius: '4px', 
                  cursor: 'pointer' 
                }}
              >
                🔄 Restart Agent
              </button>
              <button 
                onClick={closeAgentDetails}
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

const StatCard = ({ title, value, color, icon }) => (
  <div style={{ 
    backgroundColor: 'white', 
    padding: '20px', 
    borderRadius: '8px', 
    boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
    borderLeft: `4px solid ${color}`
  }}>
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
      <div>
        <div style={{ fontSize: '14px', color: '#6b7280', marginBottom: '4px' }}>{title}</div>
        <div style={{ fontSize: '28px', fontWeight: 'bold', color: '#1e3a5f' }}>{value}</div>
      </div>
      <div style={{ fontSize: '32px' }}>{icon}</div>
    </div>
  </div>
);

export default Agents;