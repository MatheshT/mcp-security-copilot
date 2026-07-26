import React, { useState, useEffect } from 'react';

const PredictiveAnalytics = () => {
  const [predictions, setPredictions] = useState(null);
  const [loading, setLoading] = useState(false);
  const [securityPosture, setSecurityPosture] = useState(null);

  useEffect(() => {
    fetchSecurityPosture();
  }, []);

  const fetchSecurityPosture = async () => {
    try {
      const response = await fetch('/api/security-posture');
      const data = await response.json();
      setSecurityPosture(data.security_posture);
    } catch (error) {
      console.error('Error fetching security posture:', error);
    }
  };

  const runPredictiveAnalysis = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/predictive-analytics', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alerts: [],
          tool_reports: {}
        })
      });
      const data = await response.json();
      setPredictions(data.predictions);
    } catch (error) {
      console.error('Error running predictive analysis:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="predictive-analytics">
      <div className="header">
        <h2>🔮 Predictive Security Analytics</h2>
        <button 
          className="btn-primary"
          onClick={runPredictiveAnalysis}
          disabled={loading}
        >
          {loading ? 'Analyzing...' : 'Run Predictive Analysis'}
        </button>
      </div>

      {securityPosture && (
        <div className="security-posture-card">
          <h3>Current Security Posture</h3>
          <div className="posture-score">
            <div className="score-circle">
              <span className="score">{securityPosture.overall_score || 85}</span>
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
          </div>
        </div>
      )}

      {predictions && (
        <div className="predictions-panel">
          <h3>Threat Predictions</h3>
          
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
              Confidence: {predictions.confidence_level}
            </div>
          </div>

          <div className="prediction-card">
            <h4>Predicted Attack Vectors</h4>
            <ul className="attack-vectors">
              {predictions.predicted_attack_vectors?.map((vector, index) => (
                <li key={index}>{vector}</li>
              ))}
            </ul>
          </div>

          <div className="prediction-card">
            <h4>Risk Timeline</h4>
            <div className="timeline">
              {predictions.risk_timeline?.map((event, index) => (
                <div key={index} className="timeline-event">
                  <div className="event-time">{event.timeframe}</div>
                  <div className="event-probability">{event.probability}</div>
                  <div className="event-description">{event.event}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="prediction-card">
            <h4>Next Likely Targets</h4>
            <div className="targets">
              {predictions.next_likely_targets?.map((target, index) => (
                <span key={index} className="target-tag">{target}</span>
              ))}
            </div>
          </div>

          <div className="prediction-card">
            <h4>Preventive Measures</h4>
            <ul className="preventive-measures">
              {predictions.preventive_measures?.map((measure, index) => (
                <li key={index}>{measure}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};

export default PredictiveAnalytics;