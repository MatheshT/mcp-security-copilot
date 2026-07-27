import React, { useState } from 'react';

const NeuralAnomalyDetection = () => {
  const [anomalyData, setAnomalyData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [trendsData, setTrendsData] = useState(null);
  const [securityData, setSecurityData] = useState({
    network: { bandwidth: 50, connections: 100, avg_packet_size: 512, unusual_ports: [], external_connections: 0 },
    auth: { login_attempts: 10, failed_attempts: 0, unusual_locations: [], off_hours_activity: false, privilege_escalation: 0 },
    system: { cpu_usage: 45, memory_usage: 60, disk_io: 25, unusual_processes: [], registry_changes: 0 }
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

  const getAnomalyTrends = async () => {
    try {
      const response = await fetch('/api/anomaly/trends?time_range_hours=24');
      const data = await response.json();
      setTrendsData(data.trends);
    } catch (error) {
      console.error('Error fetching anomaly trends:', error);
    }
  };

  const resetBaseline = async () => {
    try {
      const response = await fetch('/api/anomaly/reset', { method: 'POST' });
      const data = await response.json();
      alert('Baseline reset: ' + data.status);
    } catch (error) {
      console.error('Error resetting baseline:', error);
    }
  };

  return (
    <div className="neural-anomaly-detection">
      <div className="header">
        <h2>🧠 Neural Network Anomaly Detection</h2>
        <div className="header-actions">
          <button 
            className="btn-secondary"
            onClick={getAnomalyTrends}
          >
            Get Trends
          </button>
          <button 
            className="btn-warning"
            onClick={resetBaseline}
          >
            Reset Baseline
          </button>
          <button 
            className="btn-primary"
            onClick={runAnomalyDetection}
            disabled={loading}
          >
            {loading ? 'Analyzing...' : 'Run Anomaly Detection'}
          </button>
        </div>
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
            <div className="input-group">
              <label>External Connections:</label>
              <input
                type="number"
                value={securityData.network.external_connections}
                onChange={(e) => setSecurityData({
                  ...securityData,
                  network: { ...securityData.network, external_connections: parseInt(e.target.value) }
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
            <div className="input-group">
              <label>Privilege Escalation Attempts:</label>
              <input
                type="number"
                value={securityData.auth.privilege_escalation}
                onChange={(e) => setSecurityData({
                  ...securityData,
                  auth: { ...securityData.auth, privilege_escalation: parseInt(e.target.value) }
                })}
              />
            </div>
            <div className="checkbox-group">
              <label>
                <input
                  type="checkbox"
                  checked={securityData.auth.off_hours_activity}
                  onChange={(e) => setSecurityData({
                    ...securityData,
                    auth: { ...securityData.auth, off_hours_activity: e.target.checked }
                  })}
                />
                Off-Hours Activity
              </label>
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
            <div className="input-group">
              <label>Disk I/O (MB/s):</label>
              <input
                type="number"
                value={securityData.system.disk_io}
                onChange={(e) => setSecurityData({
                  ...securityData,
                  system: { ...securityData.system, disk_io: parseInt(e.target.value) }
                })}
              />
            </div>
            <div className="input-group">
              <label>Registry Changes:</label>
              <input
                type="number"
                value={securityData.system.registry_changes}
                onChange={(e) => setSecurityData({
                  ...securityData,
                  system: { ...securityData.system, registry_changes: parseInt(e.target.value) }
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

          <div className="temporal-analysis">
            <h4>Temporal Analysis</h4>
            <div className="analysis-grid">
              <div className="analysis-item">
                <span className="label">Hourly Anomalies:</span>
                <span className="value">{anomalyData.temporal_analysis?.hourly_anomaly_count || 0}</span>
              </div>
              <div className="analysis-item">
                <span className="label">Daily Anomalies:</span>
                <span className="value">{anomalyData.temporal_analysis?.daily_anomaly_count || 0}</span>
              </div>
              <div className="analysis-item">
                <span className="label">Trend Direction:</span>
                <span className={`value ${anomalyData.temporal_analysis?.trend_direction}`}>{anomalyData.temporal_analysis?.trend_direction || 'stable'}</span>
              </div>
            </div>
          </div>

          <div className="pattern-recognition">
            <h4>Attack Pattern Recognition</h4>
            {anomalyData.pattern_recognition?.recurring_patterns?.length > 0 ? (
              <div className="patterns-list">
                {anomalyData.pattern_recognition.recurring_patterns.map((pattern, index) => (
                  <div key={index} className="pattern-item">
                    <span className="pattern">{pattern.pattern?.join(' → ')}</span>
                    <span className="frequency">{pattern.frequency}x</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="no-patterns">No recurring patterns detected</p>
            )}
          </div>

          <div className="risk-forecast">
            <h4>Risk Forecast</h4>
            <div className="forecast-grid">
              <div className="forecast-item">
                <span className="label">Current Risk:</span>
                <span className={`value ${anomalyData.risk_forecast?.current_risk_level?.toLowerCase()}`}>{anomalyData.risk_forecast?.current_risk_level || 'Unknown'}</span>
              </div>
              <div className="forecast-item">
                <span className="label">Trend:</span>
                <span className={`value ${anomalyData.risk_forecast?.trend}`}>{anomalyData.risk_forecast?.trend || 'stable'}</span>
              </div>
              <div className="forecast-item">
                <span className="label">Predicted Next Hour:</span>
                <span className={`value ${anomalyData.risk_forecast?.predicted_risk_next_hour?.toLowerCase()}`}>{anomalyData.risk_forecast?.predicted_risk_next_hour || 'Unknown'}</span>
              </div>
              <div className="forecast-item">
                <span className="label">Monitoring Level:</span>
                <span className="value">{anomalyData.risk_forecast?.recommended_monitoring_level || 'Normal'}</span>
              </div>
            </div>
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

      {trendsData && (
        <div className="trends-results">
          <h3>Anomaly Trends (24 Hours)</h3>
          <div className="trends-summary">
            <div className="trend-item">
              <span className="label">Total Anomalies:</span>
              <span className="value">{trendsData.total_anomalies}</span>
            </div>
            <div className="trend-item">
              <span className="label">Trend Direction:</span>
              <span className={`value ${trendsData.trend_direction}`}>{trendsData.trend_direction}</span>
            </div>
            <div className="trend-item">
              <span className="label">Average Severity:</span>
              <span className={`value ${trendsData.average_severity?.toLowerCase()}`}>{trendsData.average_severity}</span>
            </div>
          </div>
          <div className="severity-distribution">
            <h4>Severity Distribution</h4>
            {Object.entries(trendsData.severity_distribution || {}).map(([severity, count]) => (
              <div key={severity} className="severity-bar">
                <span className="severity-label">{severity}</span>
                <div className="bar-container">
                  <div 
                    className={`bar-fill ${severity.toLowerCase()}`}
                    style={{ width: `${(count / trendsData.total_anomalies) * 100}%` }}
                  />
                  <span className="count">{count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default NeuralAnomalyDetection;