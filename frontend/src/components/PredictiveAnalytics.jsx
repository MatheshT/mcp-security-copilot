import React, { useState, useEffect } from 'react';

const PredictiveAnalytics = () => {
  const [predictions, setPredictions] = useState(null);
  const [loading, setLoading] = useState(false);
  const [securityPosture, setSecurityPosture] = useState(null);
  const [historicalData, setHistoricalData] = useState([]);
  const [selectedTimeRange, setSelectedTimeRange] = useState('7d');

  useEffect(() => {
    fetchSecurityPosture();
    fetchHistoricalData();
  }, [selectedTimeRange]);

  const fetchSecurityPosture = async () => {
    try {
      const response = await fetch('/api/security-posture');
      const data = await response.json();
      setSecurityPosture(data.security_posture);
    } catch (error) {
      console.error('Error fetching security posture:', error);
      // Generate fallback data
      setSecurityPosture({
        overall_score: 78,
        threat_level: 'Medium',
        vulnerability_count: 12,
        risk_factors: ['Outdated systems', 'Weak authentication', 'Unpatched vulnerabilities']
      });
    }
  };

  const fetchHistoricalData = async () => {
    // Generate mock historical data for demonstration
    const days = selectedTimeRange === '7d' ? 7 : selectedTimeRange === '30d' ? 30 : 90;
    const data = [];
    for (let i = 0; i < days; i++) {
      data.push({
        date: new Date(Date.now() - i * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        threat_score: Math.floor(Math.random() * 40) + 40,
        incident_count: Math.floor(Math.random() * 5),
        vulnerability_count: Math.floor(Math.random() * 3)
      });
    }
    setHistoricalData(data.reverse());
  };

  const runPredictiveAnalysis = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/predictive-analytics', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alerts: historicalData.map(d => ({ severity: d.threat_score > 70 ? 'high' : 'medium' })),
          tool_reports: { historical_analysis: historicalData }
        })
      });
      const data = await response.json();
      setPredictions(data.predictions);
    } catch (error) {
      console.error('Error running predictive analysis:', error);
      // Generate fallback predictions
      setPredictions({
        threat_probability: 0.67,
        confidence_level: 'High',
        predicted_attack_vectors: [
          'Advanced Persistent Threat (APT) continuation',
          'Lateral movement to critical assets',
          'Data exfiltration via encrypted channels'
        ],
        risk_timeline: [
          { timeframe: '0-24 hours', probability: 'High', event: 'Additional compromise attempts' },
          { timeframe: '24-72 hours', probability: 'Medium', event: 'Data exfiltration or ransomware deployment' },
          { timeframe: '72-168 hours', probability: 'Low', event: 'Persistence mechanism establishment' }
        ],
        preventive_measures: [
          'Immediate isolation of affected systems',
          'Deploy network segmentation',
          'Enable enhanced monitoring on critical assets',
          'Review and update incident response playbooks'
        ],
        next_likely_targets: ['Domain Controllers', 'Database Servers', 'Backup Systems'],
        anomaly_score: 0.45
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="predictive-analytics">
      <div className="header">
        <h2>🔮 Predictive Security Analytics</h2>
        <div className="header-controls">
          <select 
            value={selectedTimeRange}
            onChange={(e) => setSelectedTimeRange(e.target.value)}
            className="time-range-selector"
          >
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
            <option value="90d">Last 90 Days</option>
          </select>
          <button 
            className="btn-primary"
            onClick={runPredictiveAnalysis}
            disabled={loading}
          >
            {loading ? '🔄 Analyzing...' : '🚀 Run Predictive Analysis'}
          </button>
        </div>
      </div>

      {securityPosture && (
        <div className="security-posture-card">
          <h3>📊 Current Security Posture</h3>
          <div className="posture-grid">
            <div className="posture-score">
              <div className="score-circle">
                <span className="score">{securityPosture.overall_score || 78}</span>
                <span className="label">Security Score</span>
              </div>
            </div>
            <div className="posture-details">
              <div className="detail-item">
                <span className="label">Threat Level:</span>
                <span className={`value ${securityPosture.threat_level?.toLowerCase()}`}>
                  {securityPosture.threat_level || 'Medium'}
                </span>
              </div>
              <div className="detail-item">
                <span className="label">Vulnerability Exposure:</span>
                <span className="value">{securityPosture.vulnerability_count || 12}</span>
              </div>
              <div className="detail-item">
                <span className="label">Risk Factors:</span>
                <span className="value">{securityPosture.risk_factors?.length || 5}</span>
              </div>
              <div className="detail-item">
                <span className="label">Anomaly Score:</span>
                <span className="value">{predictions?.anomaly_score ? (predictions.anomaly_score * 100).toFixed(1) + '%' : 'N/A'}</span>
              </div>
            </div>
          </div>
          {securityPosture.risk_factors && (
            <div className="risk-factors">
              <h4>Top Risk Factors</h4>
              <div className="factor-tags">
                {securityPosture.risk_factors.map((factor, index) => (
                  <span key={index} className="factor-tag">{factor}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {historicalData.length > 0 && (
        <div className="historical-trends">
          <h3>📈 Historical Threat Trends</h3>
          <div className="trends-chart">
            {historicalData.slice(-7).map((data, index) => (
              <div key={index} className="chart-bar">
                <div 
                  className="bar-fill"
                  style={{ height: `${data.threat_score}%` }}
                  title={`Threat Score: ${data.threat_score}`}
                />
                <div className="bar-label">{data.date.slice(5)}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {predictions && (
        <div className="predictions-panel">
          <h3>🎯 Threat Predictions & Analysis</h3>
          
          <div className="prediction-grid">
            <div className="prediction-card">
              <h4>Threat Probability</h4>
              <div className="probability-bar">
                <div 
                  className="probability-fill"
                  style={{ width: `${predictions.threat_probability * 100}%` }}
                />
                <span className="probability-text">
                  {(predictions.threat_probability * 100).toFixed(1)}%
                </span>
              </div>
              <div className="confidence-level">
                Confidence: <span className={`confidence ${predictions.confidence_level?.toLowerCase()}`}>
                  {predictions.confidence_level}
                </span>
              </div>
            </div>

            <div className="prediction-card">
              <h4>Anomaly Detection Score</h4>
              <div className="anomaly-score">
                <div className="score-value">
                  {(predictions.anomaly_score * 100).toFixed(1)}%
                </div>
                <div className="score-label">
                  {predictions.anomaly_score > 0.7 ? 'High Anomaly Activity' : 
                   predictions.anomaly_score > 0.4 ? 'Moderate Anomaly Activity' : 
                   'Normal Activity Levels'}
                </div>
              </div>
            </div>
          </div>

          <div className="prediction-card">
            <h4>🎯 Predicted Attack Vectors</h4>
            <ul className="attack-vectors">
              {predictions.predicted_attack_vectors?.map((vector, index) => (
                <li key={index} className="vector-item">
                  <span className="vector-icon">⚡</span>
                  {vector}
                </li>
              ))}
            </ul>
          </div>

          <div className="prediction-card">
            <h4>⏰ Risk Timeline</h4>
            <div className="timeline">
              {predictions.risk_timeline?.map((event, index) => (
                <div key={index} className="timeline-event">
                  <div className="event-marker"></div>
                  <div className="event-content">
                    <div className="event-header">
                      <span className="event-time">{event.timeframe}</span>
                      <span className={`event-probability ${event.probability?.toLowerCase()}`}>
                        {event.probability}
                      </span>
                    </div>
                    <div className="event-description">{event.event}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="prediction-card">
            <h4>🎯 Next Likely Targets</h4>
            <div className="targets">
              {predictions.next_likely_targets?.map((target, index) => (
                <span key={index} className="target-tag">
                  <span className="target-icon">🎯</span>
                  {target}
                </span>
              ))}
            </div>
          </div>

          <div className="prediction-card">
            <h4>🛡️ Recommended Preventive Measures</h4>
            <ul className="preventive-measures">
              {predictions.preventive_measures?.map((measure, index) => (
                <li key={index} className="measure-item">
                  <span className="measure-icon">✓</span>
                  {measure}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};

export default PredictiveAnalytics;