import React, { useState } from 'react';

const AutomatedResponse = () => {
  const [responses, setResponses] = useState([]);
  const [currentResponse, setCurrentResponse] = useState(null);
  const [loading, setLoading] = useState(false);
  const [incidentData, setIncidentData] = useState({
    severity: 'medium',
    affected_assets: [],
    data_sensitivity: 'medium',
    operational_impact: 'medium',
    financial_impact: 'low',
    reputational_impact: 'low',
    compliance_impact: 'medium'
  });
  const [selectedPlaybook, setSelectedPlaybook] = useState('malware');

  const initiateResponse = async (autoApprove = false) => {
    setLoading(true);
    try {
      const response = await fetch('/api/automated-response', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_data: incidentData,
          playbook_id: selectedPlaybook,
          auto_approve: autoApprove
        })
      });
      const data = await response.json();
      setResponses([...responses, data]);
      setCurrentResponse(data);
    } catch (error) {
      console.error('Error initiating automated response:', error);
    } finally {
      setLoading(false);
    }
  };

  const playbooks = [
    { id: 'malware', name: 'Malware Containment', severity: 'critical' },
    { id: 'data_breach', name: 'Data Breach Response', severity: 'critical' },
    { id: 'ddos', name: 'DDoS Mitigation', severity: 'high' }
  ];

  return (
    <div className="automated-response">
      <div className="header">
        <h2>🚨 Automated Incident Response</h2>
      </div>

      <div className="incident-input">
        <h3>Incident Information</h3>
        <div className="input-grid">
          <div className="input-group">
            <label>Severity:</label>
            <select
              value={incidentData.severity}
              onChange={(e) => setIncidentData({ ...incidentData, severity: e.target.value })}
              className="form-select"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          <div className="input-group">
            <label>Data Sensitivity:</label>
            <select
              value={incidentData.data_sensitivity}
              onChange={(e) => setIncidentData({ ...incidentData, data_sensitivity: e.target.value })}
              className="form-select"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          <div className="input-group">
            <label>Operational Impact:</label>
            <select
              value={incidentData.operational_impact}
              onChange={(e) => setIncidentData({ ...incidentData, operational_impact: e.target.value })}
              className="form-select"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
            </select>
          </div>

          <div className="input-group">
            <label>Financial Impact:</label>
            <select
              value={incidentData.financial_impact}
              onChange={(e) => setIncidentData({ ...incidentData, financial_impact: e.target.value })}
              className="form-select"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
            </select>
          </div>
        </div>

        <div className="input-group">
          <label>Affected Assets (comma-separated):</label>
          <input
            type="text"
            value={incidentData.affected_assets.join(', ')}
            onChange={(e) => setIncidentData({ 
              ...incidentData, 
              affected_assets: e.target.value.split(',').map(a => a.trim()) 
            })}
            placeholder="e.g., server-01, database-02, workstation-03"
          />
        </div>
      </div>

      <div className="playbook-selection">
        <h3>Select Response Playbook</h3>
        <div className="playbook-cards">
          {playbooks.map(playbook => (
            <div 
              key={playbook.id}
              className={`playbook-card ${selectedPlaybook === playbook.id ? 'selected' : ''}`}
              onClick={() => setSelectedPlaybook(playbook.id)}
            >
              <div className="playbook-header">
                <h4>{playbook.name}</h4>
                <span className={`severity ${playbook.severity}`}>{playbook.severity}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="response-actions">
        <button 
          className="btn-primary"
          onClick={() => initiateResponse(false)}
          disabled={loading}
        >
          {loading ? 'Initiating...' : 'Initiate Response (Manual Approval)'}
        </button>
        <button 
          className="btn-danger"
          onClick={() => initiateResponse(true)}
          disabled={loading}
        >
          {loading ? 'Initiating...' : 'Auto-Approve & Execute'}
        </button>
      </div>

      {currentResponse && (
        <div className="response-monitoring">
          <h3>Response Monitoring</h3>
          <div className="response-summary">
            <div className="summary-item">
              <span className="label">Response ID:</span>
              <span className="value">{currentResponse.response_id}</span>
            </div>
            <div className="summary-item">
              <span className="label">Playbook:</span>
              <span className="value">{currentResponse.playbook_activated}</span>
            </div>
            <div className="summary-item">
              <span className="label">Status:</span>
              <span className="value">In Progress</span>
            </div>
            <div className="summary-item">
              <span className="label">Automated Actions:</span>
              <span className="value">{currentResponse.actions_automated}</span>
            </div>
            <div className="summary-item">
              <span className="label">Actions Requiring Approval:</span>
              <span className="value">{currentResponse.actions_requiring_approval}</span>
            </div>
          </div>

          <div className="incident-assessment">
            <h4>Incident Assessment</h4>
            <div className="assessment-details">
              <div className="detail-item">
                <span className="label">Severity:</span>
                <span className={`value ${currentResponse.incident_assessment?.severity?.toLowerCase()}`}>
                  {currentResponse.incident_assessment?.severity}
                </span>
              </div>
              <div className="detail-item">
                <span className="label">Scope:</span>
                <span className="value">{currentResponse.incident_assessment?.scope}</span>
              </div>
              <div className="detail-item">
                <span className="label">Impact Score:</span>
                <span className="value">{currentResponse.incident_assessment?.impact_score}</span>
              </div>
              <div className="detail-item">
                <span className="label">Urgency:</span>
                <span className="value">{currentResponse.incident_assessment?.urgency_level}</span>
              </div>
            </div>
          </div>

          <div className="selected-strategies">
            <h4>Selected Containment Strategies</h4>
            <div className="strategies-list">
              {currentResponse.strategies_selected?.map((strategy, index) => (
                <span key={index} className="strategy-tag">{strategy}</span>
              ))}
            </div>
          </div>

          <div className="monitoring-link">
            <a href={currentResponse.monitoring_url} target="_blank" rel="noopener noreferrer">
              Monitor Response Progress →
            </a>
          </div>
        </div>
      )}

      <div className="response-history">
        <h3>Response History</h3>
        {responses.length === 0 ? (
          <p className="no-responses">No automated responses initiated yet</p>
        ) : (
          <div className="history-list">
            {responses.map((response, index) => (
              <div key={index} className="history-item">
                <div className="history-header">
                  <span className="response-id">{response.response_id?.slice(0, 8)}</span>
                  <span className="playbook-name">{response.playbook_activated}</span>
                </div>
                <div className="history-details">
                  <span className="timestamp">{new Date().toLocaleString()}</span>
                  <span className="actions-count">
                    {response.actions_automated} automated, {response.actions_requiring_approval} manual
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default AutomatedResponse;