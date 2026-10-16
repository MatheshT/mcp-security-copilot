import React, { useState, useEffect } from 'react';
import { getWazuhAgents, restartWazuhAgent } from '../../services/api';

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

      const agentsData = await getWazuhAgents();
      console.log('Wazuh agents response:', agentsData);
      console.log('Raw agents data:', agentsData.agents);
      
      if (agentsData && agentsData.agents) {
        // Transform Wazuh API data to match component format
        const transformedAgents = agentsData.agents.map(agent => {
          // Handle group which can be array, object, or string
          let groupList = [];
          if (Array.isArray(agent.group)) {
            groupList = agent.group;
          } else if (typeof agent.group === 'object' && agent.group !== null) {
            groupList = Object.keys(agent.group);
          } else if (typeof agent.group === 'string') {
            groupList = [agent.group];
          }

          return {
            id: agent.id,
            name: agent.name,
            ip: agent.ip || agent.registerIP || 'N/A',
            status: agent.status || 'unknown',
            os: agent.os?.name || agent.os?.platform || 'Unknown OS',
            version: agent.version || 'N/A',
            last_keepalive: agent.lastKeepAlive || null,
            first_keepalive: agent.dateAdd || null,
            config_sum: agent.configSum || 'N/A',
            merged_sum: agent.mergedSum || 'N/A',
            manager_host: agent.manager || 'N/A',
            node_name: agent.node_name || 'N/A',
            group: groupList,
            active_events: 0, // Wazuh doesn't provide this directly
            alerts_count: 0, // Will be updated from alerts endpoint
            vulnerability_count: 0
          };
        });
        
        setAgents(transformedAgents);
        console.log('Successfully loaded', transformedAgents.length, 'real Wazuh agents');
      } else {
        setError('No agents data received from Wazuh');
      }
    } catch (err) {
      console.error('Error loading agents:', err);
      setError(`Failed to load agents: ${err.message}. Please check Wazuh connectivity.`);
    } finally {
      setLoading(false);
    }
  };



  const applyFilters = () => {
    let filtered = [...agents];

    if (filters.status !== 'all') {
      filtered = filtered.filter(agent => 
        agent.status?.toLowerCase() === filters.status.toLowerCase()
      );
    }

    if (filters.os !== 'all') {
      filtered = filtered.filter(agent => 
        agent.os?.toLowerCase().includes(filters.os.toLowerCase())
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
      await restartWazuhAgent(agentId);
      alert(`Agent ${agentId} restart command sent successfully`);
      // Reload agents to get updated status
      loadAgents();
    } catch (err) {
      console.error('Error restarting agent:', err);
      alert(`Failed to restart agent ${agentId}: ${err.message}`);
    }
  };

  const getOSIcon = (os) => {
    if (!os) return '💻';
    const osLower = os.toLowerCase();
    if (osLower.includes('windows')) return '🪟';
    if (osLower.includes('ubuntu') || osLower.includes('linux') || osLower.includes('amazon')) return '🐧';
    if (osLower.includes('centos') || osLower.includes('red hat') || osLower.includes('rhel')) return '🐧';
    if (osLower.includes('macos') || osLower.includes('darwin')) return '🍎';
    return '💻';
  };

  if (loading) {
    return (
      <div style={{ padding: '20px', textAlign: 'center' }}>
        <div style={{ fontSize: '18px', color: 'var(--text-secondary)' }}>Loading agents...</div>
      </div>
    );
  }

  const activeCount = agents.filter(a => a.status?.toLowerCase() === 'active').length;
  const disconnectedCount = agents.filter(a => a.status?.toLowerCase() === 'disconnected').length;
  const neverConnectedCount = agents.filter(a => a.status?.toLowerCase() === 'never_connected').length;

  return (
    <div className="detection-dark-view" style={{ padding: '20px', fontFamily: 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif' }}>
      <div style={{ marginBottom: '20px' }}>
        <h2 style={{ margin: 0, color: 'var(--text-primary)' }}>🖥️ Wazuh Agents</h2>
        <p style={{ color: 'var(--text-secondary)', margin: '8px 0 0 0' }}>
          Total: {agents.length} agents | Active: {activeCount} | Disconnected: {disconnectedCount} | Never Connected: {neverConnectedCount}
        </p>
      </div>

      {error && (
        <div style={{ 
          padding: '12px', 
          backgroundColor: 'var(--warning-bg)',
          border: '1px solid var(--warning-border)',
          borderRadius: '4px', 
          marginBottom: '20px',
          color: 'var(--warning)'
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
      <div style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.35)' }}>
        {filteredAgents.length === 0 ? (
          <div style={{ padding: '40px', textAlign: 'center', color: '#6b7280' }}>
            No agents found matching the current filters
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--bg-hover)', backgroundColor: 'var(--bg-elevated)' }}>
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
                    style={{ borderBottom: '1px solid var(--bg-hover)', cursor: 'pointer' }}
                    onClick={() => handleAgentClick(agent)}
                    onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'var(--bg-hover)'}
                    onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                  >
                    <td style={{ padding: '12px', fontFamily: 'monospace' }}>{agent.id}</td>
                    <td style={{ padding: '12px' }}>
                      <div style={{ fontWeight: '500', color: 'var(--text-primary)' }}>{agent.name}</div>
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
                        backgroundColor: agent.alerts_count > 0 ? 'var(--warning-bg)' : 'var(--success-bg)',
                        color: agent.alerts_count > 0 ? 'var(--warning)' : 'var(--success)',
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
            backgroundColor: 'var(--bg-surface)', 
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
                  backgroundColor: 'var(--bg-hover)', 
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
              <div style={{ padding: '16px', backgroundColor: 'var(--bg-elevated)', borderRadius: '8px', textAlign: 'center' }}>
                <div style={{ fontSize: '24px', fontWeight: 'bold', color: 'var(--text-primary)' }}>{selectedAgent.active_events}</div>
                <div style={{ fontSize: '12px', color: '#6b7280' }}>Active Events</div>
              </div>
              <div style={{ padding: '16px', backgroundColor: 'var(--bg-elevated)', borderRadius: '8px', textAlign: 'center' }}>
                <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#dc2626' }}>{selectedAgent.alerts_count}</div>
                <div style={{ fontSize: '12px', color: '#6b7280' }}>Alerts</div>
              </div>
              <div style={{ padding: '16px', backgroundColor: 'var(--bg-elevated)', borderRadius: '8px', textAlign: 'center' }}>
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
    backgroundColor: 'var(--bg-surface)', 
    padding: '20px', 
    borderRadius: '8px', 
    boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
    borderLeft: `4px solid ${color}`
  }}>
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
      <div>
        <div style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '4px' }}>{title}</div>
        <div style={{ fontSize: '28px', fontWeight: 'bold', color: 'var(--text-primary)' }}>{value}</div>
      </div>
      <div style={{ fontSize: '32px' }}>{icon}</div>
    </div>
  </div>
);

export default Agents;