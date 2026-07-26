import React, { useState } from 'react';

const ThreatActorPersona = () => {
  const [personaAnalysis, setPersonaAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [attackData, setAttackData] = useState({
    tools: [],
    techniques: [],
    targets: [],
    target_industries: [],
    uses_custom_malware: false,
    uses_zero_day: false,
    uses_encryption: false,
    uses_anti_forensics: false,
    uses_opsec: false
  });

  const analyzePersona = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/threat-actor-persona', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(attackData)
      });
      const data = await response.json();
      setPersonaAnalysis(data.persona_analysis);
    } catch (error) {
      console.error('Error analyzing threat actor persona:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="threat-actor-persona">
      <div className="header">
        <h2>🎭 Threat Actor Persona Analysis</h2>
        <button 
          className="btn-primary"
          onClick={analyzePersona}
          disabled={loading}
        >
          {loading ? 'Analyzing...' : 'Analyze Persona'}
        </button>
      </div>

      <div className="attack-data-input">
        <h3>Attack Data Input</h3>
        <div className="input-sections">
          <div className="input-section">
            <h4>Tools & Techniques</h4>
            <div className="checkbox-group">
              <label>
                <input
                  type="checkbox"
                  checked={attackData.uses_custom_malware}
                  onChange={(e) => setAttackData({ ...attackData, uses_custom_malware: e.target.checked })}
                />
                Custom Malware
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={attackData.uses_zero_day}
                  onChange={(e) => setAttackData({ ...attackData, uses_zero_day: e.target.checked })}
                />
                Zero-Day Exploits
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={attackData.uses_encryption}
                  onChange={(e) => setAttackData({ ...attackData, uses_encryption: e.target.checked })}
                />
                Encryption
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={attackData.uses_anti_forensics}
                  onChange={(e) => setAttackData({ ...attackData, uses_anti_forensics: e.target.checked })}
                />
                Anti-Forensics
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={attackData.uses_opsec}
                  onChange={(e) => setAttackData({ ...attackData, uses_opsec: e.target.checked })}
                />
                Operational Security
              </label>
            </div>
          </div>

          <div className="input-section">
            <h4>Target Information</h4>
            <div className="input-group">
              <label>Targets (comma-separated):</label>
              <input
                type="text"
                value={attackData.targets.join(', ')}
                onChange={(e) => setAttackData({ 
                  ...attackData, 
                  targets: e.target.value.split(',').map(t => t.trim()) 
                })}
                placeholder="e.g., government, finance, healthcare"
              />
            </div>
            <div className="input-group">
              <label>Target Industries (comma-separated):</label>
              <input
                type="text"
                value={attackData.target_industries.join(', ')}
                onChange={(e) => setAttackData({ 
                  ...attackData, 
                  target_industries: e.target.value.split(',').map(i => i.trim()) 
                })}
                placeholder="e.g., banking, energy, technology"
              />
            </div>
          </div>
        </div>
      </div>

      {personaAnalysis && (
        <div className="persona-results">
          <h3>Threat Actor Persona Profile</h3>
          
          <div className="actor-identification">
            <div className="actor-card">
              <h4>Identified Actor</h4>
              <div className="actor-name">{personaAnalysis.actor_identification?.name || 'Unknown Actor'}</div>
              <div className="actor-details">
                <div className="detail-item">
                  <span className="label">Origin:</span>
                  <span className="value">{personaAnalysis.actor_identification?.origin || 'Unknown'}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Risk Level:</span>
                  <span className={`value ${personaAnalysis.actor_identification?.risk_level?.toLowerCase()}`}>
                    {personaAnalysis.actor_identification?.risk_level || 'High'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="persona-profile">
            <h4>Persona Profile</h4>
            <div className="profile-traits">
              <div className="trait-item">
                <span className="trait-label">Personality:</span>
                <span className="trait-value">{personaAnalysis.persona_profile?.personality || 'Unknown'}</span>
              </div>
              <div className="trait-item">
                <span className="trait-label">Motivation:</span>
                <span className="trait-value">{personaAnalysis.persona_profile?.motivation || 'Unknown'}</span>
              </div>
              <div className="trait-item">
                <span className="trait-label">Attack Style:</span>
                <span className="trait-value">{personaAnalysis.persona_profile?.attack_style || 'Unknown'}</span>
              </div>
              <div className="trait-item">
                <span className="trait-label">Sophistication:</span>
                <span className="trait-value">{personaAnalysis.persona_profile?.sophistication || 'Unknown'}</span>
              </div>
            </div>
          </div>

          <div className="behavioral-predictions">
            <h4>Behavioral Predictions</h4>
            <div className="predictions-list">
              {personaAnalysis.behavioral_predictions?.likely_next_actions?.map((action, index) => (
                <div key={index} className="prediction-item">
                  <span className="action-text">{action.action}</span>
                  <span className="action-probability">{action.probability}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="countermeasures">
            <h4>Recommended Countermeasures</h4>
            <ul>
              {personaAnalysis.recommended_countermeasures?.map((countermeasure, index) => (
                <li key={index}>{countermeasure}</li>
              ))}
            </ul>
          </div>

          <div className="analysis-confidence">
            <div className="confidence-display">
              <span className="confidence-label">Analysis Confidence:</span>
              <span className="confidence-value">{personaAnalysis.confidence_level || 'Medium'}</span>
            </div>
          </div>

          <div className="similar-incidents">
            <h4>Similar Historical Incidents</h4>
            <ul>
              {personaAnalysis.similar_incidents?.map((incident, index) => (
                <li key={index}>{incident}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatActorPersona;