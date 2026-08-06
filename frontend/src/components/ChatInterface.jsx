import React, { useState } from 'react';

const ChatInterface = () => {
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState([
    {
      id: 1,
      role: 'assistant',
      text: '🤖 SecureAI Copilot is ready. Ask about alerts, IOCs, or investigation next steps.',
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [loading, setLoading] = useState(false);

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
      const response = await fetch('/api/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: question })
      });

      if (!response.ok) {
        throw new Error(`Request failed with ${response.status}`);
      }

      const data = await response.json();
      const toolList = (data.required_tools || []).join(', ') || 'no specific tools';

      const aiMessage = {
        id: Date.now() + 1,
        role: 'assistant',
        report: data.report_json,
        ai_answer: data.ai_answer,
        text: `Intent: ${data.intent}. Query type: ${data.query_type}. Required tools: ${toolList}.`,
        time: new Date().toLocaleTimeString([], { 
          hour: '2-digit', 
          minute: '2-digit' 
        })
      };

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

  return (
    <div className="chat-interface">
      <div className="messages-container">
        {messages.map((message) => (
          <div key={message.id} className={`message ${message.role}`}>
            <div className="message-content">
              <div className="message-text">
                {message.report ? (
                  <div className="report-content">
                    {message.ai_answer && (
                      <div className="ai-answer">
                        <strong>AI Analysis:</strong>
                        <p>{message.ai_answer}</p>
                      </div>
                    )}
                    {message.report.investigation_summary && (
                      <div className="investigation-summary">
                        <strong>Investigation Summary:</strong>
                        <p>{message.report.investigation_summary}</p>
                      </div>
                    )}
                    {message.report.severity && (
                      <div className="severity-badge">
                        Severity: {message.report.severity}
                      </div>
                    )}
                    {message.report.recommendation && (
                      <div className="recommendation">
                        <strong>Recommendation:</strong>
                        <p>{message.report.recommendation}</p>
                      </div>
                    )}
                  </div>
                ) : (
                  <p>{message.text}</p>
                )}
              </div>
              <div className="message-time">{message.time}</div>
            </div>
          </div>
        ))}
        {loading && (
          <div className="message assistant">
            <div className="message-content">
              <div className="message-text">
                <div className="typing-indicator">
                  <span></span>
                  <span></span>
                  <span></span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <form onSubmit={handleSend} className="chat-input-form">
        <div className="input-container">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about security investigations, threats, or IOC analysis..."
            disabled={loading}
          />
          <button type="submit" disabled={loading || !input.trim()}>
            {loading ? '⏳' : '🚀'}
          </button>
        </div>
      </form>
    </div>
  );
};

export default ChatInterface;