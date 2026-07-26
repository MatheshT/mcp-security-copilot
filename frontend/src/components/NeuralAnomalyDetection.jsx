import React, { useState } from 'react';

const NeuralAnomalyDetection = () => {
  const [anomalyData, setAnomalyData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [securityData, setSecurityData] = useState({
    network: { bandwidth: 50, connections: 100, avg_packet_size: 512, unusual_ports: [] },
    auth: { login_attempts: 10, failed_attempts: 0, unusual_locations: [], off_hours_activity: false },
    system: { cpu_usage: 45, memory_usage: 60, disk_io: 25, unusual_processes: [] }
  });

  const runAnomalyDetection = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/anomaly-detection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(securityData)
      });
      const data = await response.json();
      setAnomalyData(data.anomaly_details);
    } catch (error) {
      console.error('Error running anomaly detection:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="neural-anomaly-detection">
      <div className="header">
        <h2>🧠 Neural Network Anomaly Detection</h2>
        <button 
          className="btn-primary"
          onClick={runAnomalyDetection}
          disabled={loading}
        >
          {loading ? 'Analyzing...' : 'Run Anomaly Detection'}
        </button>
      </div>

      <div className="data-input">
        <h3>Security Data Input</h3>
        <div className="data-sections">
          <div className="data-section">
            <h4>Network Data</h4>
            <div className="input-group">
              <label>Bandwidth Usage (Mbps):</label>
              <input
                type="number"
                value={securityData.network.bandwidth}
                onChange={(e) => setSecurityData({
                  ...securityData,
                  network: { ...securityData.network, bandwidth: parseInt(e.target.value) }
                })}
              />
            </div>
            <div className="input-group">
              <label>Connection Count:</label>
              <input
                type="number"
                value={securityData.network.connections}
                onChange={(e) => setSecurityData({
                  ...securityData,
                  network: { ...securityData.network, connections: parseInt(e.target.value) }
                })}
              />
            </div>
          </div>

          <div className="data-section">
            <h4>Authentication Data</h4>
            <div className="input-group">
              <label>Login Attempts:</label>
              <input
                type="number"
                value={securityData.auth.login_attempts}
                onChange={(e) => setSecurityData({
                  ...securityData,
                  auth: { ...securityData.auth, login_attempts: parseInt(e.target.value) }
                })}
              />
            </div>
            <div className="input-group">
              <label>Failed Attempts:</label>
              <input
                type="number"
                value={securityData.auth.failed_attempts}
                onChange={(e) => setSecurityData({
                  ...securityData,
                  auth: { ...securityData.auth, failed_attempts: parseInt(e.target.value) }
                })}
              />
            </div>
          </div>

          <div className="data-section">
            <h4>System Data</h4>
            <div className="input-group">
              <label>CPU Usage (%):</label>
              <input
                type="number"
                value={securityData.system.cpu_usage}
                onChange={(e) => setSecurityData({
                  ...securityData,
                  system: { ...securityData.system, cpu_usage: parseInt(e.target.value) }
                })}
              />
            </div>
            <div className="input-group">
              <label>Memory Usage (%):</label>
              <input
                type="number"
                value={securityData.system.memory_usage}
                onChange={(e) => setSecurityData({
                  ...securityData,
                  system: { ...securityData.system, memory_usage: parseInt(e.target.value) }
                })}
              />
            </div>
          </div>
        </div>
      </div>

      {anomalyData && (
        <div className="anomaly-results">
          <h3>Anomaly Detection Results</h3>
          
          <div className="overall-score">
            <div className="score-display">
              <div className="score-circle">
                <span className="score">{(anomalyData.overall_anomaly_score * 100).toFixed(0)}</span>
                <span className="label">Anomaly Score</span>
              </div>
              <div className={`status-indicator ${anomalyData.is_anomaly ? 'anomaly' : 'normal'}`}>
                {anomalyData.is_anomaly ? '⚠️ ANOMALY DETECTED' : '✓ Normal Behavior'}
              </div>
            </div>
          </div>

          <div className="analysis-breakdown">
            <div className="analysis-card">
              <h4>Network Analysis</h4>
              <div className="score-bar">
                <div 
                  className="score-fill"
                  style={{ width: `${anomalyData.network_analysis * 100}%` }}
                />
                <span className="score-text">{(anomalyData.network_analysis * 100).toFixed(0)}%</span>
              </div>
            </div>

            <div className="analysis-card">
              <h4>Authentication Analysis</h4>
              <div className="score-bar">
                <div 
                  className="score-fill"
                  style={{ width: `${anomalyData.authentication_analysis * 100}%` }}
                />
                <span className="score-text">{(anomalyData.authentication_analysis * 100).toFixed(0)}%</span>
              </div>
            </div>

            <div className="analysis-card">
              <h4>System Analysis</h4>
              <div className="score-bar">
                <div 
                  className="score-fill"
                  style={{ width: `${anomalyData.system_analysis * 100}%` }}
                />
                <span className="score-text">{(anomalyData.system_analysis * 100).toFixed(0)}%</span>
              </div>
            </div>
          </div>

          <div className="anomaly-details">
            <div className="detail-card">
              <h4>Anomaly Type</h4>
              <span className="anomaly-type">{anomalyData.anomaly_type}</span>
            </div>

            <div className="detail-card">
              <h4>Severity</h4>
              <span className={`severity ${anomalyData.anomaly_severity?.toLowerCase()}`}>
                {anomalyData.anomaly_severity}
              </span>
            </div>

            <div className="detail-card">
              <h4>Confidence Level</h4>
              <span className="confidence">{anomalyData.confidence_level}</span>
            </div>
          </div>

          <div className="potential-threats">
            <h4>Potential Threats Identified</h4>
            <ul>
              {anomalyData.potential_threats?.map((threat, index) => (
                <li key={index}>{threat}</li>
              ))}
            </ul>
          </div>

          <div className="recommended-actions">
            <h4>Recommended Actions</h4>
            <ul>
              {anomalyData.recommended_actions?.map((action, index) => (
                <li key={index}>{action}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};

export default NeuralAnomalyDetection;