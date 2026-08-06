import { useMemo, useState } from 'react';
import SecurityDashboard from './components/security/SecurityDashboard';
import SimpleSecurityDashboard from './components/security/SimpleSecurityDashboard';
import AdminPanel from './components/AdminPanel';
import AuditLogs from './components/AuditLogs';
import BackupManagement from './components/BackupManagement';
import FeatureFlags from './components/FeatureFlags';
import Navigation from './components/Navigation';
import WazuhDashboard from './components/detection/WazuhDashboard';
import Alerts from './components/detection/Alerts';
import Agents from './components/detection/Agents';
import EventLogs from './components/detection/EventLogs';
import './styles/components.css';

const starterMessages = [
  {
    id: 1,
    role: 'assistant',
    text: '🛡️ SentinelAI X is ready! Welcome to the AI-powered Security Operations Center.',
    time: '09:41',
    showSocButton: true
  }
];

function App() {
  const [analyst, setAnalyst] = useState('Analyst');
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState(starterMessages);
  const [investigations, setInvestigations] = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const [loading, setLoading] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [currentView, setCurrentView] = useState('chat'); // default to AI chat
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [sortBy, setSortBy] = useState('newest');
  const [showSettings, setShowSettings] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [user, setUser] = useState({ username: 'Admin', roles: ['Administrator'] });
  const [toolStatus, setToolStatus] = useState({
    virustotal: 'online',
    windowslogs: 'online',
    windowsdefender: 'online',
    misp: 'online',
    shodan: 'online'
  });

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

  const handleFileUpload = async (file) => {
    setUploading(true);
    const userMessage = {
      id: Date.now(),
      role: 'user',
      text: `📎 File uploaded: ${file.name}`,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages((prev) => [...prev, userMessage]);
    setShowUploadModal(false);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch(getApiUrl('/api/upload'), {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error(`Upload failed with ${response.status}`);
      }

      const data = await response.json();
      const toolList = (data.required_tools || []).join(', ') || 'no specific tools';

      const aiMessage = {
        id: Date.now() + 1,
        role: 'assistant',
        report: data.report_json,
        ai_answer: data.ai_answer,
        text: `File analysis complete. Tools used: ${toolList}.`,
        time: new Date().toLocaleTimeString([], { 
          hour: '2-digit', 
          minute: '2-digit' 
        })
      };

      const newInvestigation = {
        id: Date.now() + 2,
        title: `File Analysis: ${file.name}`,
        status: data.unified_investigation?.severity || data.report_json?.severity || 'Open',
        summary: data.unified_investigation?.summary || 
                 data.report_json?.investigation_summary || 
                 'File analysis completed.',
        updatedAt: new Date().toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })
      };

      setInvestigations((prev) => [newInvestigation, ...prev]);
      setSelectedCase(newInvestigation.id);
      setMessages((prev) => [...prev, aiMessage]);
    } catch (error) {
      console.error('Upload Error:', error);
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now() + 2,
          role: 'assistant',
          text: '⚠️ File upload failed. Please try again.',
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } finally {
      setUploading(false);
    }
  };

  const selectedInvestigation = useMemo(
    () => investigations.find((item) => item.id === selectedCase) || investigations[0] || null,
    [investigations, selectedCase]
  );

  // Dashboard statistics
  const dashboardStats = useMemo(() => {
    const total = investigations.length;
    const critical = investigations.filter(inv => inv.status?.toLowerCase() === 'critical').length;
    const high = investigations.filter(inv => inv.status?.toLowerCase() === 'high').length;
    const medium = investigations.filter(inv => inv.status?.toLowerCase() === 'medium').length;
    const low = investigations.filter(inv => inv.status?.toLowerCase() === 'low').length;
    
    return {
      total,
      critical,
      high,
      medium,
      low,
      active: investigations.filter(inv => inv.status?.toLowerCase() !== 'resolved').length
    };
  }, [investigations]);

  // Filtered investigations
  const filteredInvestigations = useMemo(() => {
    let filtered = [...investigations];
    
    if (filterSeverity !== 'all') {
      filtered = filtered.filter(inv => inv.status?.toLowerCase() === filterSeverity);
    }
    
    if (filterStatus !== 'all') {
      filtered = filtered.filter(inv => {
        if (filterStatus === 'active') return inv.status?.toLowerCase() !== 'resolved';
        if (filterStatus === 'resolved') return inv.status?.toLowerCase() === 'resolved';
        return true;
      });
    }
    
    if (sortBy === 'newest') {
      filtered.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
    } else if (sortBy === 'oldest') {
      filtered.sort((a, b) => new Date(a.updatedAt) - new Date(b.updatedAt));
    }
    
    return filtered;
  }, [investigations, filterSeverity, filterStatus, sortBy]);

  const renderDashboard = () => (
    <div className="dashboard-view">
      <div className="dashboard-header">
        <h2>📊 Security Dashboard</h2>
        <div className="dashboard-stats">
          <div className="stat-card critical">
            <h3>{dashboardStats.critical}</h3>
            <p>Critical</p>
          </div>
          <div className="stat-card high">
            <h3>{dashboardStats.high}</h3>
            <p>High</p>
          </div>
          <div className="stat-card medium">
            <h3>{dashboardStats.medium}</h3>
            <p>Medium</p>
          </div>
          <div className="stat-card low">
            <h3>{dashboardStats.low}</h3>
            <p>Low</p>
          </div>
          <div className="stat-card total">
            <h3>{dashboardStats.total}</h3>
            <p>Total</p>
          </div>
        </div>
      </div>
      
      <div className="dashboard-controls">
        <select 
          value={filterSeverity} 
          onChange={(e) => setFilterSeverity(e.target.value)}
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        
        <select 
          value={filterStatus} 
          onChange={(e) => setFilterStatus(e.target.value)}
        >
          <option value="all">All Status</option>
          <option value="active">Active</option>
          <option value="resolved">Resolved</option>
        </select>
        
        <select 
          value={sortBy} 
          onChange={(e) => setSortBy(e.target.value)}
        >
          <option value="newest">Newest First</option>
          <option value="oldest">Oldest First</option>
        </select>
      </div>
      
      <div className="investigations-list">
        {filteredInvestigations.map((inv) => (
          <div 
            key={inv.id} 
            className={`investigation-card ${selectedCase === inv.id ? 'selected' : ''}`}
            onClick={() => setSelectedCase(inv.id)}
          >
            <h4>{inv.title}</h4>
            <p><strong>Status:</strong> {inv.status}</p>
            <p><strong>Updated:</strong> {inv.updatedAt}</p>
            <p><strong>Summary:</strong> {inv.summary}</p>
          </div>
        ))}
      </div>
    </div>
  );

  const renderPlaceholder = (title, message) => (
    <div className="placeholder-view">
      <h2>{title}</h2>
      <p>{message}</p>
      <p>This feature is coming soon. Use the AI Chat for {title.toLowerCase()}.</p>
    </div>
  );

  return (
    <div className={`app ${darkMode ? 'dark' : ''}`}>
      <Navigation 
        currentView={currentView} 
        setCurrentView={setCurrentView} 
        user={user} 
        onLogout={() => setUser(null)}
        sidebarCollapsed={sidebarCollapsed}
        setSidebarCollapsed={setSidebarCollapsed}
      />
      
      <div className="main-content">
        <header className="app-header">
          <h1>SentinelAI X</h1>
          <div className="header-actions">
            <button onClick={() => setDarkMode(!darkMode)}>
              {darkMode ? '☀️' : '🌙'}
            </button>
            <button onClick={() => setShowSettings(!showSettings)}>
              ⚙️
            </button>
          </div>
        </header>

        <main className="app-main">
          {currentView === 'chat' ? (
            <>
              <div className="chat-container">
                <div className="messages-container">
                  {messages.map((msg) => (
                    <div key={msg.id} className={`message ${msg.role}`}>
                      <div className="message-content">
                        {msg.report ? (
                          <div className="report-content">
                            <h3>📋 Investigation Report</h3>
                            <pre>{JSON.stringify(msg.report, null, 2)}</pre>
                          </div>
                        ) : (
                          <p>{msg.text}</p>
                        )}
                      </div>
                      <div className="message-time">{msg.time}</div>
                    </div>
                  ))}
                </div>
                <form onSubmit={handleSend} className="chat-input-form">
                  <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder="Ask about security incidents..."
                    disabled={loading}
                  />
                  <button type="submit" disabled={loading}>
                    {loading ? '⏳' : '📤'}
                  </button>
                </form>
              </div>
              {selectedInvestigation && (
                <div className="investigation-panel">
                  <h3>📋 Selected Investigation</h3>
                  <h4>{selectedInvestigation.title}</h4>
                  <p><strong>Status:</strong> {selectedInvestigation.status}</p>
                  <p><strong>Updated:</strong> {selectedInvestigation.updatedAt}</p>
                  <p><strong>Summary:</strong> {selectedInvestigation.summary}</p>
                </div>
              )}
            </>
          ) : currentView === 'dashboard' ? (
            <SimpleSecurityDashboard />
          ) : currentView === 'wazuh-dashboard' ? (
            <WazuhDashboard />
          ) : currentView === 'alerts' ? (
            <Alerts />
          ) : currentView === 'agents' ? (
            <Agents />
          ) : currentView === 'event-logs' ? (
            <EventLogs />
          ) : currentView === 'live-investigation' || currentView === 'investigation-history' || currentView === 'ai-reasoning' || currentView === 'investigation-timeline' ? (
            renderPlaceholder('🧠 AI Investigation', currentView.replace('-', ' ').toUpperCase())
          ) : currentView === 'virustotal' || currentView === 'mitre-attack' || currentView === 'abuseipdb' || currentView === 'sigma-rules' || currentView === 'ioc-explorer' ? (
            renderPlaceholder('🌐 Threat Intelligence', currentView.replace('-', ' ').toUpperCase())
          ) : currentView === 'ioc-search' || currentView === 'process-analysis' || currentView === 'host-analysis' || currentView === 'user-activity' ? (
            renderPlaceholder('🔍 Threat Hunting', currentView.replace('-', ' ').toUpperCase())
          ) : currentView === 'investigation-reports' || currentView === 'executive-reports' || currentView === 'pdf-export' || currentView === 'report-history' ? (
            renderPlaceholder('📄 Reports', currentView.replace('-', ' ').toUpperCase())
          ) : currentView === 'api-keys' || currentView === 'windows-collectors' || currentView === 'wazuh-settings' ? (
            renderPlaceholder('⚙️ Settings', currentView.replace('-', ' ').toUpperCase())
          ) : currentView === 'user-management' ? (
            <AdminPanel />
          ) : currentView === 'system-health' ? (
            <div className="placeholder-view">
              <h2>💚 System Health</h2>
              <p>System Status: Online</p>
              <p>Backend: Connected</p>
              <p>Wazuh: Configured</p>
              <p>VirusTotal: Connected</p>
            </div>
          ) : (
            renderDashboard()
          )}
        </main>

        {showUploadModal && (
          <div className="modal-overlay" onClick={() => setShowUploadModal(false)}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <h3>Upload File for Analysis</h3>
                <button onClick={() => setShowUploadModal(false)}>✕</button>
              </div>
              <div className="modal-body">
                <input
                  type="file"
                  onChange={(e) => {
                    const file = e.target.files[0];
                    if (file) handleFileUpload(file);
                  }}
                  accept="*/*"
                />
                <p>Supported: logs, images, screenshots, config files</p>
              </div>
            </div>
          </div>
        )}

        {showSettings && (
          <div className="modal-overlay" onClick={() => setShowSettings(false)}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <h3>System Settings</h3>
                <button onClick={() => setShowSettings(false)}>✕</button>
              </div>
              <div className="modal-body">
                <h4>Tool Status</h4>
                <div className="tool-status">
                  <span>VirusTotal: {toolStatus.virustotal}</span>
                  <span>Windows Logs: {toolStatus.windowslogs}</span>
                  <span>Windows Defender: {toolStatus.windowsdefender}</span>
                  <span>MISP: {toolStatus.misp}</span>
                  <span>Shodan: {toolStatus.shodan}</span>
                </div>
                <h4>API Configuration</h4>
                <p>Backend: {getApiUrl('')}</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
