import React, { useState, useEffect } from 'react';

const AuditLogs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ action: '', resource: '' });

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    try {
      const token = localStorage.getItem('token');
      let url = '/api/audit/';
      const params = new URLSearchParams();
      if (filter.action) params.append('action', filter.action);
      if (filter.resource) params.append('resource', filter.resource);
      if (params.toString()) url += '?' + params.toString();

      const response = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      const data = await response.json();
      setLogs(data);
    } catch (error) {
      console.error('Error fetching audit logs:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (e) => {
    setFilter({ ...filter, [e.target.name]: e.target.value });
  };

  if (loading) return <div className="loading">Loading audit logs...</div>;

  return (
    <div className="audit-logs">
      <div className="audit-header">
        <h2>📋 Audit Logs</h2>
        <div className="filter-controls">
          <input
            name="action"
            placeholder="Filter by action..."
            value={filter.action}
            onChange={handleFilterChange}
          />
          <input
            name="resource"
            placeholder="Filter by resource..."
            value={filter.resource}
            onChange={handleFilterChange}
          />
          <button className="btn-primary" onClick={fetchLogs}>Apply Filters</button>
        </div>
      </div>

      <div className="logs-table">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>User ID</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Resource ID</th>
              <th>IP Address</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {logs.map(log => (
              <tr key={log.id}>
                <td>{new Date(log.timestamp).toLocaleString()}</td>
                <td>{log.user_id || '-'}</td>
                <td><span className="action-badge">{log.action}</span></td>
                <td>{log.resource}</td>
                <td>{log.resource_id || '-'}</td>
                <td>{log.ip_address || '-'}</td>
                <td className="details-cell">{log.details || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AuditLogs;