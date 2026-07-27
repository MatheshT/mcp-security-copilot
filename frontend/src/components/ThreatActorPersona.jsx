import React, { useState } from 'react';

const ThreatActorPersona = () => {
  const [personaAnalysis, setPersonaAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [attackData, setAttackData] = useState({
    tools: [],
    techniques: [],
    targets: [],
    target_industries: [],
    geographic_focus: 'Unknown',
    timestamps: [],
    uses_custom_malware: false,
    uses_zero_day: false,
    uses_encryption: false,
    uses_anti_forensics: false,
    uses_opsec: false
  });

  const getApiUrl = (path) => {
    const base = import.meta.env.VITE_API_URL?.trim();
    if (base) {
      return `${base.replace(/\/$/, '')}${path}`;
    }
    return path;
  };

  const analyzePersona = async () => {
    setLoading(true);
    try {
      const response = await fetch(getApiUrl('/api/threat-actor-persona'), {
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

  const loadSampleData = () => {
    setAttackData({
      tools: ['mimikatz', 'powershell', 'cobalt strike'],
      techniques: ['credential harvesting', 'lateral movement', 'privilege escalation'],
      targets: ['Active Directory', 'File Servers', 'Database Servers'],
      target_industries: ['finance', 'healthcare'],
      geographic_focus: 'Eastern Europe',
      timestamps: [new Date().toISOString()],
      uses_custom_malware: true,
      uses_zero_day: true,
      uses_encryption: true,
      uses_anti_forensics: true,
      uses_opsec: true
    });
  };

  return (
    <div className="threat-actor-persona">
      <div className="header">
        <h2>🎭 Threat Actor Persona Analysis</h2>
        <div className="header-actions">
          <button 
            className="btn-secondary"
            onClick={loadSampleData}
          >
            Load Sample Data
          </button>
          <button 
            className="btn-primary"
            onClick={analyzePersona}
            disabled={loading}
          >
            {loading ? 'Analyzing...' : 'Analyze Persona'}
          </button>
        </div>
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
            <div className="input-group">
              <label>Geographic Focus:</label>
              <select
                value={attackData.geographic_focus}
                onChange={(e) => setAttackData({ ...attackData, geographic_focus: e.target.value })}
                className="form-select"
              >
                <option value="Unknown">Unknown</option>
                <option value="Eastern Europe">Eastern Europe</option>
                <option value="Russia">Russia</option>
                <option value="North Korea">North Korea</option>
                <option value="China">China</option>
                <option value="Iran">Iran</option>
                <option value="Western">Western</option>
              </select>
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
            <div className="profile-sections">
              <div className="profile-section">
                <h5>Personality Traits</h5>
                <div className="traits-grid">
                  {Object.entries(personaAnalysis.persona_profile?.personality_traits || {}).map(([trait, value]) => (
                    <div key={trait} className="trait-card">
                      <span className="trait-name">{trait.charAt(0).toUpperCase() + trait.slice(1)}</span>
                      <span className={`trait-value ${value.toLowerCase()}`}>{value}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="profile-section">
                <h5>Motivation Analysis</h5>
                <div className="motivation-card">
                  <div className="motivation-primary">
                    <span className="label">Primary Motivation:</span>
                    <span className={`value ${personaAnalysis.persona_profile?.motivation?.primary_motivation?.toLowerCase()}`}>
                      {personaAnalysis.persona_profile?.motivation?.primary_motivation || 'Unknown'}
                    </span>
                  </div>
                  <div className="motivation-confidence">
                    <span className="label">Confidence:</span>
                    <div className="confidence-bar">
                      <div 
                        className="confidence-fill"
                        style={{ width: `${(personaAnalysis.persona_profile?.motivation?.confidence || 0) * 100}%` }}
                      />
                      <span className="confidence-text">{Math.round((personaAnalysis.persona_profile?.motivation?.confidence || 0) * 100)}%</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="profile-section">
                <h5>Behavioral Profile</h5>
                <div className="behavioral-grid">
                  {Object.entries(personaAnalysis.persona_profile?.behavioral_profile || {}).map(([behavior, value]) => (
                    <div key={behavior} className="behavior-item">
                      <span className="behavior-label">{behavior.replace(/_/g, ' ').replace(/([A-Z])/g, ' $1').trim()}</span>
                      <span className="behavior-value">{value}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="profile-section">
                <h5>Technical Profile</h5>
                <div className="technical-card">
                  <div className="technical-item">
                    <span className="label">Sophistication Level:</span>
                    <span className={`value ${personaAnalysis.persona_profile?.technical_profile?.sophistication_level?.toLowerCase()}`}>
                      {personaAnalysis.persona_profile?.technical_profile?.sophistication_level || 'Unknown'}
                    </span>
                  </div>
                  <div className="technical-item">
                    <span className="label">Complexity Score:</span>
                    <div className="score-bar">
                      <div 
                        className="score-fill"
                        style={{ width: `${personaAnalysis.persona_profile?.technical_profile?.complexity_score || 0}%` }}
                      />
                      <span className="score-text">{personaAnalysis.persona_profile?.technical_profile?.complexity_score || 0}/100</span>
                    </div>
                  </div>
                  <div className="capabilities-list">
                    <span className="label">Key Capabilities:</span>
                    <div className="capabilities">
                      {personaAnalysis.persona_profile?.technical_profile?.key_capabilities?.map((cap, index) => (
                        <span key={index} className="capability-tag">{cap}</span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="behavioral-predictions">
            <h4>Behavioral Predictions</h4>
            <div className="predictions-sections">
              <div className="prediction-section">
                <h5>Short-term Predictions</h5>
                <ul>
                  {personaAnalysis.behavioral_predictions?.short_term_predictions?.map((prediction, index) => (
                    <li key={index}>{prediction}</li>
                  ))}
                </ul>
              </div>
              <div className="prediction-section">
                <h5>Long-term Predictions</h5>
                <ul>
                  {personaAnalysis.behavioral_predictions?.long_term_predictions?.map((prediction, index) => (
                    <li key={index}>{prediction}</li>
                  ))}
                </ul>
              </div>
              <div className="prediction-section">
                <h5>Likely Next Targets</h5>
                <div className="targets-list">
                  {personaAnalysis.behavioral_predictions?.likely_next_targets?.map((target, index) => (
                    <span key={index} className="target-tag">{target}</span>
                  ))}
                </div>
              </div>
              <div className="prediction-section">
                <h5>Evolution Trajectory</h5>
                <p className="evolution-text">{personaAnalysis.behavioral_predictions?.evolution_trajectory || 'Unknown'}</p>
              </div>
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
            {personaAnalysis.similar_incidents?.length > 0 ? (
              <div className="incidents-grid">
                {personaAnalysis.similar_incidents.map((incident, index) => (
                  <div key={index} className="incident-card">
                    <div className="incident-pattern">{incident.pattern}</div>
                    <div className="incident-stats">
                      <span className="stat">Similar incidents: {incident.similar_incidents}</span>
                      <span className="confidence">Confidence: {Math.round(incident.confidence * 100)}%</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="no-incidents">No similar incidents found</p>
            )}
          </div>

          <div className="intelligence-gaps">
            <h4>Intelligence Gaps</h4>
            <ul>
              {personaAnalysis.threat_intelligence_gaps?.map((gap, index) => (
                <li key={index} className="gap-item">{gap}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatActorPersona;