import React, { useState, useEffect } from 'react';

const CollaborativeInvestigation = () => {
  const [sessions, setSessions] = useState([]);
  const [currentSession, setCurrentSession] = useState(null);
  const [newInsight, setNewInsight] = useState('');
  const [loading, setLoading] = useState(false);

  const createSession = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/collaborative/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: 'analyst-1',
          investigation_data: { title: 'New Investigation' }
        })
      });
      const data = await response.json();
      setSessions([...sessions, data.session]);
      setCurrentSession(data.session);
    } catch (error) {
      console.error('Error creating session:', error);
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
          insight: { text: newInsight, type: 'observation' }
        })
      });
      const data = await response.json();
      setNewInsight('');
      // Refresh session data
      fetchCollectiveIntelligence(currentSession.session_id);
    } catch (error) {
      console.error('Error sharing insight:', error);
    }
  };

  const fetchCollectiveIntelligence = async (sessionId) => {
    try {
      const response = await fetch(`/api/collaborative/${sessionId}/intelligence`);
      const data = await response.json();
      setCurrentSession(prev => ({ ...prev, collective_intelligence: data.collective_intelligence }));
    } catch (error) {
      console.error('Error fetching collective intelligence:', error);
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
          {loading ? 'Creating...' : 'New Session'}
        </button>
      </div>

      <div className="sessions-list">
        <h3>Active Sessions</h3>
        {sessions.length === 0 ? (
          <p className="no-sessions">No active collaborative sessions</p>
        ) : (
          <div className="session-cards">
            {sessions.map((session, index) => (
              <div 
                key={index}
                className={`session-card ${currentSession?.session_id === session.session_id ? 'active' : ''}`}
                onClick={() => setCurrentSession(session)}
              >
                <div className="session-header">
                  <h4>Session {session.session_id?.slice(0, 8)}</h4>
                  <span className="participant-count">
                    {session.participant_count} participants
                  </span>
                </div>
                <div className="session-features">
                  {session.features?.map((feature, idx) => (
                    <span key={idx} className="feature-tag">{feature}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {currentSession && (
        <div className="session-workspace">
          <div className="session-info">
            <h3>Session Workspace</h3>
            <div className="session-details">
              <div className="detail-item">
                <span className="label">Session ID:</span>
                <span className="value">{currentSession.session_id}</span>
              </div>
              <div className="detail-item">
                <span className="label">Invitation Link:</span>
                <span className="value">{currentSession.invitation_link}</span>
              </div>
              <div className="detail-item">
                <span className="label">QR Code:</span>
                <span className="value">{currentSession.qr_code}</span>
              </div>
            </div>
          </div>

          <div className="insight-sharing">
            <h3>Share Insights</h3>
            <textarea
              value={newInsight}
              onChange={(e) => setNewInsight(e.target.value)}
              placeholder="Share your security insights with the team..."
              className="insight-input"
            />
            <button 
              className="btn-primary"
              onClick={shareInsight}
              disabled={!newInsight.trim()}
            >
              Share Insight
            </button>
          </div>

          {currentSession.collective_intelligence && (
            <div className="collective-intelligence">
              <h3>Collective Intelligence</h3>
              <div className="intelligence-score">
                <div className="score-display">
                  <span className="score-label">Collective Intelligence Score:</span>
                  <span className="score-value">
                    {currentSession.collective_intelligence.collective_intelligence_score || 85}
                  </span>
                </div>
              </div>
              
              <div className="intelligence-sections">
                <div className="section">
                  <h4>Insight Patterns</h4>
                  <ul>
                    {currentSession.collective_intelligence.insight_patterns?.map((pattern, idx) => (
                      <li key={idx}>{pattern}</li>
                    ))}
                  </ul>
                </div>
                
                <div className="section">
                  <h4>Decision Patterns</h4>
                  <ul>
                    {currentSession.collective_intelligence.decision_patterns?.map((pattern, idx) => (
                      <li key={idx}>{pattern}</li>
                    ))}
                  </ul>
                </div>

                <div className="section">
                  <h4>Knowledge Gaps</h4>
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
  );
};

export default CollaborativeInvestigation;