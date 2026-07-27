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
  const [responseStatus, setResponseStatus] = useState(null);
  const [responseReport, setResponseReport] = useState(null);

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
      setResponses([...responses, data.response]);
      setCurrentResponse(data.response);
    } catch (error) {
      console.error('Error initiating automated response:', error);
    } finally {
      setLoading(false);
    }
  };

  const getResponseStatus = async (responseId) => {
    try {
      const response = await fetch(`/api/response/${responseId}/status`);
      const data = await response.json();
      setResponseStatus(data.response_status);
    } catch (error) {
      console.error('Error getting response status:', error);
    }
  };

  const generateResponseReport = async (responseId) => {
    try {
      const response = await fetch(`/api/response/${responseId}/report`);
      const data = await response.json();
      setResponseReport(data.response_report);
    } catch (error) {
      console.error('Error generating response report:', error);
    }
  };

  const approveAction = async (responseId, actionId) => {
    try {
      const response = await fetch(`/api/response/${responseId}/approve/${actionId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approver_id: 'admin' })
      });
      const data = await response.json();
      if (currentResponse) {
        getResponseStatus(currentResponse.response_id);
      }
    } catch (error) {
      console.error('Error approving action:', error);
    }
  };

  const playbooks = [
    { id: 'malware', name: 'Malware Containment', severity: 'critical', description: 'Isolate systems, kill processes, block C2' },
    { id: 'data_breach', name: 'Data Breach Response', severity: 'critical', description: 'Block exfiltration, preserve evidence, notify stakeholders' },
    { id: 'ddos', name: 'DDoS Mitigation', severity: 'high', description: 'Activate mitigation, rate limit, enable scrubbing' }
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
          className="btn-secondary"
          onClick={() => currentResponse && getResponseStatus(currentResponse.response_id)}
          disabled={!currentResponse}
        >
          Check Status
        </button>
        <button 
          className="btn-info"
          onClick={() => currentResponse && generateResponseReport(currentResponse.response_id)}
          disabled={!currentResponse}
        >
          Generate Report
        </button>
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
              <span className="value">{currentResponse.response_id?.slice(0, 8)}...</span>
            </div>
            <div className="summary-item">
              <span className="label">Playbook:</span>
              <span className="value">{currentResponse.playbook_activated}</span>
            </div>
            <div className="summary-item">
              <span className="label">Status:</span>
              <span className={`value ${responseStatus?.status?.toLowerCase() || 'in-progress'}`}>{responseStatus?.status || 'In Progress'}</span>
            </div>
            <div className="summary-item">
              <span className="label">Effectiveness Score:</span>
              <span className="value">{responseStatus?.effectiveness_score || 0}%</span>
            </div>
            <div className="summary-item">
              <span className="label">Current Phase:</span>
              <span className="value">{responseStatus?.current_phase || 'initializing'}</span>
            </div>
            <div className="summary-item">
              <span className="label">Automated Actions:</span>
              <span className="value">{currentResponse.actions_automated}</span>
            </div>
            <div className="summary-item">
              <span className="label">Actions Requiring Approval:</span>
              <span className="value">{currentResponse.actions_requiring_approval}</span>
            </div>
            <div className="summary-item">
              <span className="label">Estimated Completion:</span>
              <span className="value">{currentResponse.estimated_completion_time}</span>
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

          <div className="pending-actions">
            <h4>Pending Actions (Require Approval)</h4>
            {currentResponse.execution_results?.pending_approval?.length > 0 ? (
              <div className="pending-list">
                {currentResponse.execution_results.pending_approval.map((action, index) => (
                  <div key={index} className="pending-item">
                    <div className="action-info">
                      <span className="action-name">{action.action}</span>
                      <span className="action-reason">{action.reason}</span>
                    </div>
                    <button 
                      className="btn-approve"
                      onClick={() => approveAction(currentResponse.response_id, action.action_id)}
                    >
                      Approve
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="no-pending">No pending actions</p>
            )}
          </div>

          <div className="successful-actions">
            <h4>Successfully Executed Actions</h4>
            {currentResponse.execution_results?.successful?.length > 0 ? (
              <div className="success-list">
                {currentResponse.execution_results.successful.map((action, index) => (
                  <div key={index} className="success-item">
                    <span className="action-icon">✓</span>
                    <span className="action-name">{action.action}</span>
                    <span className="action-time">{action.timestamp}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="no-success">No actions executed yet</p>
            )}
          </div>
        </div>
      )}

      {responseReport && (
        <div className="response-report">
          <h3>Response Report</h3>
          <div className="report-summary">
            <div className="report-section">
              <h4>Actions Summary</h4>
              <div className="summary-grid">
                <div className="summary-card">
                  <span className="label">Total Planned:</span>
                  <span className="value">{responseReport.actions_summary?.total_planned || 0}</span>
                </div>
                <div className="summary-card">
                  <span className="label">Automated:</span>
                  <span className="value">{responseReport.actions_summary?.automated || 0}</span>
                </div>
                <div className="summary-card">
                  <span className="label">Manual:</span>
                  <span className="value">{responseReport.actions_summary?.manual || 0}</span>
                </div>
                <div className="summary-card">
                  <span className="label">Successful:</span>
                  <span className="value">{responseReport.actions_summary?.successful || 0}</span>
                </div>
                <div className="summary-card">
                  <span className="label">Failed:</span>
                  <span className="value">{responseReport.actions_summary?.failed || 0}</span>
                </div>
              </div>
            </div>

            <div className="report-section">
              <h4>Effectiveness Metrics</h4>
              <div className="metrics-grid">
                <div className="metric-item">
                  <span className="label">Overall Score:</span>
                  <span className={`value ${responseReport.effectiveness_metrics?.overall_score > 80 ? 'good' : 'needs-improvement'}`}>
                    {responseReport.effectiveness_metrics?.overall_score || 0}%
                  </span>
                </div>
                <div className="metric-item">
                  <span className="label">Time Efficiency:</span>
                  <span className="value">{responseReport.effectiveness_metrics?.time_efficiency || 'N/A'}</span>
                </div>
                <div className="metric-item">
                  <span className="label">Resource Utilization:</span>
                  <span className="value">{responseReport.effectiveness_metrics?.resource_utilization || 'N/A'}</span>
                </div>
              </div>
            </div>

            <div className="report-section">
              <h4>Lessons Learned</h4>
              <ul>
                {responseReport.lessons_learned?.map((lesson, index) => (
                  <li key={index}>{lesson}</li>
                ))}
              </ul>
            </div>

            <div className="report-section">
              <h4>Recommendations</h4>
              <ul>
                {responseReport.recommendations?.map((rec, index) => (
                  <li key={index}>{rec}</li>
                ))}
              </ul>
            </div>
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