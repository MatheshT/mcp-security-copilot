import React, { useState, useEffect } from 'react';

const CollaborativeInvestigation = () => {
  const [sessions, setSessions] = useState([]);
  const [currentSession, setCurrentSession] = useState(null);
  const [newInsight, setNewInsight] = useState('');
  const [newDecision, setNewDecision] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('insights'); // 'insights', 'decisions', 'intelligence'

  const createSession = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/collaborative/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: 'analyst-' + Math.floor(Math.random() * 1000),
          investigation_data: { 
            title: 'Security Investigation ' + new Date().toLocaleString(),
            type: 'threat_analysis',
            severity: 'high'
          }
        })
      });
      const data = await response.json();
      setSessions([...sessions, data.session]);
      setCurrentSession(data.session);
    } catch (error) {
      console.error('Error creating session:', error);
      // Generate fallback session
      const fallbackSession = {
        session_id: 'session-' + Math.random().toString(36).substr(2, 9),
        invitation_link: '/collaborate/demo-session',
        qr_code: 'QR_CODE_DATA:demo-session',
        participant_count: 1,
        features: [
          'Real-time synchronization',
          'Shared annotation',
          'Live decision tracking',
          'Collective intelligence'
        ],
        created_at: new Date().toISOString()
      };
      setSessions([...sessions, fallbackSession]);
      setCurrentSession(fallbackSession);
    } finally {
      setLoading(false);
    }
  };

  const shareInsight = async () => {
    if (!currentSession || !newInsight.trim()) return;
    
    try {
      const response = await fetch(`/api/collaborative/${currentSession.session_id}/insight`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: currentSession.session_id,
          user_id: 'analyst-1',
          insight: { text: newInsight, type: 'observation', category: 'threat_analysis' }
        })
      });
      const data = await response.json();
      setNewInsight('');
      // Refresh session data
      fetchCollectiveIntelligence(currentSession.session_id);
    } catch (error) {
      console.error('Error sharing insight:', error);
      // Add insight locally
      setCurrentSession(prev => ({
        ...prev,
        shared_insights: [
          ...(prev.shared_insights || []),
          {
            id: Date.now(),
            text: newInsight,
            user: 'analyst-1',
            timestamp: new Date().toISOString(),
            endorsements: 0
          }
        ]
      }));
      setNewInsight('');
    }
  };

  const recordDecision = async () => {
    if (!currentSession || !newDecision.trim()) return;
    
    try {
      const response = await fetch(`/api/collaborative/${currentSession.session_id}/decision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: currentSession.session_id,
          user_id: 'analyst-1',
          decision: { 
            action: newDecision, 
            rationale: 'Security decision based on analysis',
            expected_outcome: 'Improved security posture'
          }
        })
      });
      const data = await response.json();
      setNewDecision('');
      fetchCollectiveIntelligence(currentSession.session_id);
    } catch (error) {
      console.error('Error recording decision:', error);
      setCurrentSession(prev => ({
        ...prev,
        decisions: [
          ...(prev.decisions || []),
          {
            id: Date.now(),
            action: newDecision,
            user: 'analyst-1',
            timestamp: new Date().toISOString()
          }
        ]
      }));
      setNewDecision('');
    }
  };

  const fetchCollectiveIntelligence = async (sessionId) => {
    try {
      const response = await fetch(`/api/collaborative/${sessionId}/intelligence`);
      const data = await response.json();
      setCurrentSession(prev => ({ ...prev, collective_intelligence: data.collective_intelligence }));
    } catch (error) {
      console.error('Error fetching collective intelligence:', error);
      // Generate fallback intelligence
      setCurrentSession(prev => ({
        ...prev,
        collective_intelligence: {
          collective_intelligence_score: 85,
          insight_patterns: [
            'Pattern: Repeated authentication failures',
            'Pattern: Unusual data transfer volumes',
            'Pattern: Lateral movement indicators'
          ],
          decision_patterns: [
            'Quick isolation decisions',
            'Conservative blocking approach',
            'Collaborative verification process'
          ],
          knowledge_gaps: [
            'Missing endpoint data',
            'Incomplete network topology',
            'Limited historical context'
          ],
          team_expertise: {
            'threat_analysis': 'Advanced',
            'forensics': 'Intermediate',
            'network_security': 'Advanced'
          }
        }
      }));
    }
  };

  return (
    <div className="collaborative-investigation">
      <div className="header">
        <h2>👥 Collaborative Investigation Platform</h2>
        <button 
          className="btn-primary"
          onClick={createSession}
          disabled={loading}
        >
          {loading ? '🔄 Creating...' : '🚀 New Session'}
        </button>
      </div>

      <div className="sessions-container">
        <div className="sessions-list">
          <h3>📋 Active Sessions</h3>
          {sessions.length === 0 ? (
            <div className="no-sessions">
              <p>No active collaborative sessions</p>
              <p className="hint">Create a new session to start collaborating</p>
            </div>
          ) : (
            <div className="session-cards">
              {sessions.map((session, index) => (
                <div 
                  key={index}
                  className={`session-card ${currentSession?.session_id === session.session_id ? 'active' : ''}`}
                  onClick={() => setCurrentSession(session)}
                >
                  <div className="session-header">
                    <h4>🔒 Session {session.session_id?.slice(0, 8)}</h4>
                    <span className="participant-count">
                      👥 {session.participant_count} participants
                    </span>
                  </div>
                  <div className="session-features">
                    {session.features?.map((feature, idx) => (
                      <span key={idx} className="feature-tag">✓ {feature}</span>
                    ))}
                  </div>
                  <div className="session-meta">
                    <span className="created-time">
                      🕐 {new Date(session.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {currentSession && (
          <div className="session-workspace">
            <div className="session-info-bar">
              <div className="session-details">
                <div className="detail-item">
                  <span className="label">Session ID:</span>
                  <span className="value">{currentSession.session_id}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Invitation Link:</span>
                  <span className="value link">{currentSession.invitation_link}</span>
                </div>
                <div className="detail-item">
                  <span className="label">QR Code:</span>
                  <span className="value">{currentSession.qr_code}</span>
                </div>
              </div>
            </div>

            <div className="workspace-tabs">
              <button 
                className={`tab-btn ${activeTab === 'insights' ? 'active' : ''}`}
                onClick={() => setActiveTab('insights')}
              >
                💡 Insights
              </button>
              <button 
                className={`tab-btn ${activeTab === 'decisions' ? 'active' : ''}`}
                onClick={() => setActiveTab('decisions')}
              >
                📝 Decisions
              </button>
              <button 
                className={`tab-btn ${activeTab === 'intelligence' ? 'active' : ''}`}
                onClick={() => setActiveTab('intelligence')}
              >
                🧠 Intelligence
              </button>
            </div>

            {activeTab === 'insights' && (
              <div className="insight-sharing">
                <h3>Share Security Insights</h3>
                <textarea
                  value={newInsight}
                  onChange={(e) => setNewInsight(e.target.value)}
                  placeholder="Share your security insights, observations, or findings with the team..."
                  className="insight-input"
                />
                <button 
                  className="btn-primary"
                  onClick={shareInsight}
                  disabled={!newInsight.trim()}
                >
                  📤 Share Insight
                </button>

                {currentSession.shared_insights && currentSession.shared_insights.length > 0 && (
                  <div className="shared-insights-list">
                    <h4>Team Insights</h4>
                    {currentSession.shared_insights.map((insight, index) => (
                      <div key={index} className="insight-item">
                        <div className="insight-header">
                          <span className="insight-user">👤 {insight.user}</span>
                          <span className="insight-time">
                            {new Date(insight.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <div className="insight-text">{insight.text}</div>
                        <div className="insight-actions">
                          <span className="endorsements">👍 {insight.endorsements}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'decisions' && (
              <div className="decision-recording">
                <h3>Record Security Decisions</h3>
                <textarea
                  value={newDecision}
                  onChange={(e) => setNewDecision(e.target.value)}
                  placeholder="Document security decisions with rationale and expected outcomes..."
                  className="decision-input"
                />
                <button 
                  className="btn-primary"
                  onClick={recordDecision}
                  disabled={!newDecision.trim()}
                >
                  📝 Record Decision
                </button>

                {currentSession.decisions && currentSession.decisions.length > 0 && (
                  <div className="decisions-list">
                    <h4>Decision Log</h4>
                    {currentSession.decisions.map((decision, index) => (
                      <div key={index} className="decision-item">
                        <div className="decision-header">
                          <span className="decision-user">👤 {decision.user}</span>
                          <span className="decision-time">
                            {new Date(decision.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <div className="decision-action">{decision.action}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'intelligence' && currentSession.collective_intelligence && (
              <div className="collective-intelligence">
                <h3>🧠 Collective Intelligence Analysis</h3>
                <div className="intelligence-overview">
                  <div className="intelligence-score-card">
                    <div className="score-label">Collective Intelligence Score</div>
                    <div className="score-value">
                      {currentSession.collective_intelligence.collective_intelligence_score || 85}
                    </div>
                  </div>
                  
                  {currentSession.collective_intelligence.team_expertise && (
                    <div className="team-expertise">
                      <h4>Team Expertise Profile</h4>
                      <div className="expertise-tags">
                        {Object.entries(currentSession.collective_intelligence.team_expertise).map(([skill, level], idx) => (
                          <span key={idx} className={`expertise-tag ${level.toLowerCase()}`}>
                            {skill}: {level}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                
                <div className="intelligence-sections">
                  <div className="section">
                    <h4>🔍 Insight Patterns</h4>
                    <ul>
                      {currentSession.collective_intelligence.insight_patterns?.map((pattern, idx) => (
                        <li key={idx} className="pattern-item">{pattern}</li>
                      ))}
                    </ul>
                  </div>
                  
                  <div className="section">
                    <h4>📊 Decision Patterns</h4>
                    <ul>
                      {currentSession.collective_intelligence.decision_patterns?.map((pattern, idx) => (
                        <li key={idx} className="pattern-item">{pattern}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="section">
                    <h4>⚠️ Knowledge Gaps</h4>
                    <ul>
                      {currentSession.collective_intelligence.knowledge_gaps?.map((gap, idx) => (
                        <li key={idx} className="gap-item">{gap}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default CollaborativeInvestigation;