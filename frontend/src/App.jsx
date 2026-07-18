import { useMemo, useState } from 'react';

const starterMessages = [
  {
    id: 1,
    role: 'assistant',
    text: 'SecureAI Copilot is ready. Ask about alerts, IOCs, or investigation next steps.',
    time: '09:41'
  }
];

function App() {
  const [analyst, setAnalyst] = useState('Analyst');
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState(starterMessages);
  const [investigations, setInvestigations] = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const [loading, setLoading] = useState(false);
  const [darkMode, setDarkMode] = useState(true);

  const getApiUrl = (path) => {
    const base = import.meta.env.VITE_API_URL?.trim();
    if (base) {
      return `${base.replace(/\/$/, '')}${path}`;
    }
    return path;
  };

  const handleSend = async (event) => {
    event.preventDefault();
    if (!input.trim()) return;

    const question = input.trim();
    const userMessage = {
      id: Date.now(),
      role: 'user',
      text: question,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setLoading(true);

    try {
      const response = await fetch(getApiUrl('/api/investigate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: question })
      });

      if (!response.ok) {
        throw new Error(`Request failed with ${response.status}`);
      }

      const data = await response.json();
      const toolList = (data.required_tools || []).join(', ') || 'no specific tools';

      // ✅ FIXED: Store both the report AND the AI answer
      const aiMessage = {
        id: Date.now() + 1,
        role: 'assistant',
        report: data.report_json, // Store the full report
        ai_answer: data.ai_answer, // Store the AI natural language response
        text: `Intent: ${data.intent}. Query type: ${data.query_type}. Required tools: ${toolList}.`, // Keep for fallback
        time: new Date().toLocaleTimeString([], { 
          hour: '2-digit', 
          minute: '2-digit' 
        })
      };

      const newInvestigation = {
        id: Date.now() + 2,
        title: `${data.query_type || 'Investigation'} case`,
        status: data.unified_investigation?.severity || data.report_json?.severity || 'Open',
        summary: data.unified_investigation?.summary || 
                 data.report_json?.investigation_summary || 
                 data.recommendation || 
                 'Investigation completed.',
        updatedAt: new Date().toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })
      };

      setInvestigations((prev) => [newInvestigation, ...prev]);
      setSelectedCase(newInvestigation.id);
      setMessages((prev) => [...prev, aiMessage]);
    } catch (error) {
      console.error('API Error:', error);
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now() + 2,
          role: 'assistant',
          text: '⚠️ The security assistant is temporarily unavailable. Please retry in a moment.',
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const selectedInvestigation = useMemo(
    () => investigations.find((item) => item.id === selectedCase) || investigations[0] || null,
    [investigations, selectedCase]
  );

  // ✅ Helper function to render the AI answer with formatting
  const renderAiAnswer = (answer) => {
    if (!answer) return null;
    
    // Split by newlines and format
    const lines = answer.split('\n').filter(line => line.trim());
    
    return (
      <div className="ai-analysis">
        <div className="ai-analysis-header">
          <span className="ai-icon">🤖</span>
          <h3>AI Analysis</h3>
        </div>
        <div className="ai-analysis-body">
          {lines.map((line, index) => {
            // Check for bullet points
            if (line.trim().startsWith('•') || line.trim().startsWith('-')) {
              return <div key={index} className="ai-bullet">{line.trim()}</div>;
            }
            // Check for numbered items
            if (line.match(/^\d+\./)) {
              return <div key={index} className="ai-numbered">{line.trim()}</div>;
            }
            // Check for bold text (wrapped in **)
            if (line.includes('**')) {
              const parts = line.split(/\*\*/);
              return (
                <p key={index} className="ai-text">
                  {parts.map((part, i) => 
                    i % 2 === 1 ? <strong key={i}>{part}</strong> : part
                  )}
                </p>
              );
            }
            // Check for headers (lines ending with :)
            if (line.trim().endsWith(':') && line.trim().length < 50) {
              return <h4 key={index} className="ai-subheader">{line.trim()}</h4>;
            }
            // Regular paragraph
            if (line.trim()) {
              return <p key={index} className="ai-text">{line.trim()}</p>;
            }
            return null;
          })}
        </div>
      </div>
    );
  };

  // ✅ Helper function to render the report
  const renderReport = (report) => {
    if (!report) return null;

    return (
      <div className="report-card">
        <div className="report-header">
          <h3>🚨 AI Investigation Report</h3>
          <span className={`severity-badge severity-${(report.severity || '').toLowerCase()}`}>
            {report.severity || 'Unknown'}
          </span>
        </div>
        
        <div className="report-grid">
          {/* Incident Details */}
          <div className="report-section">
            <h4>📋 Incident Details</h4>
            <div className="detail-grid">
              <div className="detail-row">
                <span className="label">Alert ID:</span>
                <span className="value">{report.alert_id || 'N/A'}</span>
              </div>
              <div className="detail-row">
                <span className="label">Status:</span>
                <span className={`status-badge-small status-${(report.status || '').toLowerCase()}`}>
                  {report.status || 'Open'}
                </span>
              </div>
              <div className="detail-row">
                <span className="label">Attack Type:</span>
                <span className="value attack-type">{report.attack_type || 'Unknown'}</span>
              </div>
              <div className="detail-row">
                <span className="label">Affected Host:</span>
                <span className="value host">{report.affected_host || 'Unknown'}</span>
              </div>
              <div className="detail-row">
                <span className="label">Source IP:</span>
                <span className="value ip">{report.source_ip || 'N/A'}</span>
              </div>
              <div className="detail-row">
                <span className="label">Destination IP:</span>
                <span className="value ip">{report.destination_ip || 'N/A'}</span>
              </div>
              <div className="detail-row">
                <span className="label">MITRE Technique:</span>
                <span className="value mitre">{report.mitre_technique || 'N/A'}</span>
              </div>
            </div>
          </div>

          {/* Indicators of Compromise */}
          <div className="report-section">
            <h4>🌐 Indicators of Compromise</h4>
            {report.indicators_of_compromise && report.indicators_of_compromise.length > 0 ? (
              <div className="ioc-container">
                {report.indicators_of_compromise.map((ioc, index) => (
                  <span key={index} className="ioc-tag">
                    {ioc}
                  </span>
                ))}
              </div>
            ) : (
              <p className="no-data">No IOCs identified</p>
            )}
          </div>

          {/* Threat Intelligence */}
          <div className="report-section">
            <h4>🛡 Threat Intelligence</h4>
            {report.threat_intelligence && report.threat_intelligence.length > 0 ? (
              <ul className="threat-list">
                {report.threat_intelligence.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            ) : (
              <p className="no-data">No threat intelligence available</p>
            )}
          </div>

          {/* Investigation Summary */}
          <div className="report-section summary-section">
            <h4>📊 Investigation Summary</h4>
            <div className="summary-box">
              {report.investigation_summary || 'No summary available'}
            </div>
          </div>

          {/* Recommendations */}
          <div className="report-section">
            <h4>✅ Recommendations</h4>
            {report.recommendations && report.recommendations.length > 0 ? (
              <ul className="recommendations-list">
                {report.recommendations.map((item, index) => (
                  <li key={index}>
                    <span className="bullet">▸</span> {item}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="no-data">No recommendations available</p>
            )}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className={`app-shell ${darkMode ? 'dark' : 'light'}`}>
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-icon">🛡️</div>
          <div>
            <p className="eyebrow">AI-powered SOC</p>
            <h3>SecureAI Copilot</h3>
          </div>
        </div>

        <div className="sidebar-section">
          <div className="sidebar-title-row">
            <h4>Investigations</h4>
            <span className="pill">{investigations.length}</span>
          </div>
          <div className="investigation-list">
            {investigations.length === 0 ? (
              <div className="empty-card">No investigations yet. Send a query to begin.</div>
            ) : (
              investigations.map((item) => (
                <button 
                  key={item.id} 
                  className={`investigation-card ${selectedCase === item.id ? 'active' : ''}`} 
                  onClick={() => setSelectedCase(item.id)}
                >
                  <div className="investigation-head">
                    <strong>{item.title}</strong>
                    <span className={`status-${(item.status || '').toLowerCase()}`}>
                      {item.status}
                    </span>
                  </div>
                  <p className="investigation-summary">{item.summary}</p>
                  <small>{item.updatedAt}</small>
                </button>
              ))
            )}
          </div>
        </div>

        <div className="sidebar-footer">
          <p>Live alerts</p>
          <strong className="alert-count">24 critical</strong>
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div>
            <p className="eyebrow">Active case</p>
            <h2>{selectedInvestigation?.title || 'No investigation selected'}</h2>
          </div>
          <div className="topbar-actions">
            <button className="ghost-button" onClick={() => setDarkMode((prev) => !prev)}>
              {darkMode ? '☀️ Light' : '🌙 Dark'}
            </button>
            <div className="analyst-chip">{analyst}</div>
          </div>
        </header>

        <section className="insight-card">
          <div>
            <p className="eyebrow">Investigation summary</p>
            <p>{selectedInvestigation?.summary || 'Submit an investigation query and the copilot will provide a structured response.'}</p>
          </div>
          <div className={`status-badge threat-${(selectedInvestigation?.status || '').toLowerCase()}`}>
            Threat level: {selectedInvestigation?.status || 'Unknown'}
          </div>
        </section>

        <section className="chat-card">
          <div className="message-list">
            {messages.map((message) => (
              <div key={message.id} className={`message-row ${message.role}`}>
                <div className="message-bubble">
                  <div className="message-meta">
                    <strong>{message.role === 'user' ? 'Analyst' : 'Copilot'}</strong>
                    <span>{message.time}</span>
                  </div>
                  
                  {/* ✅ FIXED: Render both AI answer AND report */}
                  {message.report ? (
                    <>
                      {message.ai_answer && renderAiAnswer(message.ai_answer)}
                      {renderReport(message.report)}
                    </>
                  ) : (
                    <p className="message-text">{message.text}</p>
                  )}
                </div>
              </div>
            ))}
            
            {loading && (
              <div className="message-row assistant">
                <div className="message-bubble typing-indicator">
                  <span>🔍</span>
                  <span>Analyzing telemetry and correlating threat intelligence</span>
                  <span className="dots">...</span>
                </div>
              </div>
            )}
          </div>

          <form onSubmit={handleSend} className="composer">
            <textarea
              value={input}
              onChange={(event) => setInput(event.target.value)}
              placeholder="Ask the copilot to summarize an alert, inspect an IOC, or recommend containment steps..."
              rows={3}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleSend(e);
                }
              }}
              disabled={loading}
            />
            <button type="submit" disabled={loading || !input.trim()}>
              {loading ? '⏳ Processing...' : '📤 Send'}
            </button>
          </form>
        </section>
      </main>
    </div>
  );
}

export default App;