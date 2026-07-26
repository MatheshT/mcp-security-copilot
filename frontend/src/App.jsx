import { useMemo, useState } from 'react';
import PredictiveAnalytics from './components/PredictiveAnalytics';
import CollaborativeInvestigation from './components/CollaborativeInvestigation';
import BlockchainEvidence from './components/BlockchainEvidence';
import NeuralAnomalyDetection from './components/NeuralAnomalyDetection';
import ThreatActorPersona from './components/ThreatActorPersona';
import AutomatedResponse from './components/AutomatedResponse';

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
  const [uploading, setUploading] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [currentView, setCurrentView] = useState('chat'); // 'chat', 'dashboard', 'analytics', 'predictive', 'collaborative', 'blockchain', 'anomaly', 'threat-actor', 'response'
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [sortBy, setSortBy] = useState('newest');
  const [showSettings, setShowSettings] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [toolStatus, setToolStatus] = useState({
    virustotal: 'online',
    wazuh: 'online',
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
        const status = inv.status?.toLowerCase();
        if (filterStatus === 'active') return status !== 'resolved';
        if (filterStatus === 'resolved') return status === 'resolved';
        return true;
      });
    }
    
    if (sortBy === 'newest') {
      filtered.sort((a, b) => b.id - a.id);
    } else if (sortBy === 'oldest') {
      filtered.sort((a, b) => a.id - b.id);
    } else if (sortBy === 'severity') {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      filtered.sort((a, b) => {
        const aSeverity = severityOrder[a.status?.toLowerCase()] || 4;
        const bSeverity = severityOrder[b.status?.toLowerCase()] || 4;
        return aSeverity - bSeverity;
      });
    }
    
    return filtered;
  }, [investigations, filterSeverity, filterStatus, sortBy]);

  const renderAiAnswer = (answer) => {
    if (!answer) return null;
    
    const lines = answer.split('\n').filter(line => line.trim());
    
    return (
      <div className="ai-analysis">
        <div className="ai-analysis-header">
          <span className="ai-icon">🤖</span>
          <h3>AI Analysis</h3>
        </div>
        <div className="ai-analysis-body">
          {lines.map((line, index) => {
            if (line.trim().startsWith('•') || line.trim().startsWith('-')) {
              return <div key={index} className="ai-bullet">{line.trim()}</div>;
            }
            if (line.match(/^\d+\./)) {
              return <div key={index} className="ai-numbered">{line.trim()}</div>;
            }
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
            if (line.trim().endsWith(':') && line.trim().length < 50) {
              return <h4 key={index} className="ai-subheader">{line.trim()}</h4>;
            }
            if (line.trim()) {
              return <p key={index} className="ai-text">{line.trim()}</p>;
            }
            return null;
          })}
        </div>
      </div>
    );
  };

  const renderToolReports = (report) => {
    if (!report || !report.tool_reports) return null;

    const toolReports = report.tool_reports;
    const activeTools = Object.entries(toolReports).filter(([_, data]) => data !== null);

    if (activeTools.length === 0) return null;

    return (
      <div className="tool-reports-section">
        <h4>🔧 Per-Tool Analysis Reports</h4>
        <div className="tool-reports-grid">
          {activeTools.map(([toolName, toolData]) => (
            <div key={toolName} className={`tool-report-card tool-${toolName.toLowerCase()}`}>
              <div className="tool-report-header">
                <span className="tool-icon">{getToolIcon(toolName)}</span>
                <h5>{toolData.tool || toolName}</h5>
                {toolData.visual_data && (
                  <span className={`risk-badge risk-${toolData.visual_data.risk_level?.toLowerCase() || 'medium'}`}>
                    {toolData.visual_data.risk_level || 'Medium'}
                  </span>
                )}
              </div>
              <div className="tool-report-content">
                {renderToolSpecificContent(toolName, toolData)}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const getToolIcon = (toolName) => {
    const icons = {
      'virustotal_report': '🦠',
      'wazuh_report': '🛡️',
      'misp_report': '🎯',
      'shodan_report': '🔍'
    };
    return icons[toolName] || '🔧';
  };

  const renderToolSpecificContent = (toolName, toolData) => {
    switch (toolName) {
      case 'virustotal_report':
        return (
          <>
            <div className="tool-metric">
              <span className="metric-label">Reputation:</span>
              <span className={`metric-value ${toolData.reputation?.toLowerCase()}`}>
                {toolData.reputation}
              </span>
            </div>
            <div className="tool-metric">
              <span className="metric-label">Detections:</span>
              <span className="metric-value">{toolData.detections}</span>
            </div>
            {toolData.visual_data && (
              <div className="visual-bar">
                <div className="bar-label">Detection Ratio</div>
                <div className="progress-bar">
                  <div 
                    className="progress-fill malicious" 
                    style={{ width: toolData.visual_data.detection_ratio }}
                  />
                </div>
              </div>
            )}
            <div className="tool-details">
              <div>🌍 {toolData.country}</div>
              <div>🏢 {toolData.as_owner}</div>
            </div>
          </>
        );
      case 'wazuh_report':
        return (
          <>
            <div className="tool-metric">
              <span className="metric-label">Alert ID:</span>
              <span className="metric-value">{toolData.alert_id}</span>
            </div>
            <div className="tool-metric">
              <span className="metric-label">Severity:</span>
              <span className={`metric-value severity-${toolData.severity?.toLowerCase()}`}>
                {toolData.severity}
              </span>
            </div>
            <div className="tool-details">
              <div>🎯 {toolData.title}</div>
              <div>💻 {toolData.destination_host}</div>
              <div>🔄 {toolData.mitre}</div>
            </div>
            {toolData.visual_data && (
              <div className="attack-chain">
                <div className="chain-label">Attack Chain:</div>
                {toolData.visual_data.attack_chain.map((step, i) => (
                  <div key={i} className="chain-step">
                    <span className="step-number">{i + 1}</span>
                    <span className="step-name">{step}</span>
                  </div>
                ))}
              </div>
            )}
          </>
        );
      case 'misp_report':
        return (
          <>
            <div className="tool-metric">
              <span className="metric-label">Threat Actor:</span>
              <span className="metric-value">{toolData.threat_actor}</span>
            </div>
            <div className="tool-metric">
              <span className="metric-label">Campaign:</span>
              <span className="metric-value">{toolData.campaign}</span>
            </div>
            <div className="tool-details">
              <div>🎯 IOC: {toolData.ioc}</div>
              <div>⚠️ Level: {toolData.threat_level}</div>
            </div>
            {toolData.visual_data && (
              <div className="threat-info">
                <div className="threat-score">
                  <span>Threat Score:</span>
                  <div className="score-bar">
                    <div 
                      className="score-fill" 
                      style={{ width: `${toolData.visual_data.threat_score}%` }}
                    />
                  </div>
                </div>
                <div className="threat-meta">
                  <span>Type: {toolData.visual_data.actor_type}</span>
                  <span>Sophistication: {toolData.visual_data.sophistication}</span>
                </div>
              </div>
            )}
          </>
        );
      case 'shodan_report':
        return (
          <>
            <div className="tool-metric">
              <span className="metric-label">IP:</span>
              <span className="metric-value">{toolData.ip}</span>
            </div>
            <div className="tool-metric">
              <span className="metric-label">Organization:</span>
              <span className="metric-value">{toolData.org}</span>
            </div>
            <div className="tool-details">
              <div>🌍 {toolData.country}, {toolData.city}</div>
              <div>💻 OS: {toolData.os}</div>
            </div>
            {toolData.visual_data && (
              <div className="exposure-info">
                <div className="exposure-score">
                  <span>Exposure Score:</span>
                  <div className="score-bar">
                    <div 
                      className="score-fill high" 
                      style={{ width: `${toolData.visual_data.exposure_score}%` }}
                    />
                  </div>
                </div>
                <div className="ports-vulns">
                  <span>🔌 Ports: {toolData.visual_data.port_count}</span>
                  <span>⚠️ Vulns: {toolData.visual_data.vulnerability_count}</span>
                </div>
              </div>
            )}
          </>
        );
      default:
        return <div className="tool-details">No detailed data available</div>;
    }
  };

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
        
        {renderToolReports(report)}
        
        <div className="report-grid">
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

          <div className="report-section">
            <h4>🛡 Threat Intelligence</h4>
            {report.threat_intelligence && report.threat_intelligence.length > 0 ? (
              <div className="intel-list">
                {report.threat_intelligence.map((intel, index) => (
                  <div key={index} className="intel-item">
                    {intel}
                  </div>
                ))}
              </div>
            ) : (
              <p className="no-data">No threat intelligence available</p>
            )}
          </div>

          <div className="report-section">
            <h4>📝 Investigation Summary</h4>
            <p className="summary-text">{report.investigation_summary || 'No summary available'}</p>
          </div>

          <div className="report-section">
            <h4>✅ Recommendations</h4>
            {report.recommendations && report.recommendations.length > 0 ? (
              <div className="recommendations-list">
                {report.recommendations.map((rec, index) => (
                  <div key={index} className="recommendation-item">
                    <span className="rec-number">{index + 1}</span>
                    <span className="rec-text">{rec}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="no-data">No recommendations available</p>
            )}
          </div>
        </div>
      </div>
    );
  };

  const renderDashboard = () => (
    <div className="dashboard-view">
      <div className="dashboard-header">
        <h1>📊 Security Dashboard</h1>
        <div className="dashboard-controls">
          <select 
            value={filterSeverity} 
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="filter-select"
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
            className="filter-select"
          >
            <option value="all">All Status</option>
            <option value="active">Active</option>
            <option value="resolved">Resolved</option>
          </select>
          <select 
            value={sortBy} 
            onChange={(e) => setSortBy(e.target.value)}
            className="filter-select"
          >
            <option value="newest">Newest First</option>
            <option value="oldest">Oldest First</option>
            <option value="severity">By Severity</option>
          </select>
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card stat-total">
          <div className="stat-icon">📋</div>
          <div className="stat-content">
            <div className="stat-value">{dashboardStats.total}</div>
            <div className="stat-label">Total Investigations</div>
          </div>
        </div>
        <div className="stat-card stat-critical">
          <div className="stat-icon">🚨</div>
          <div className="stat-content">
            <div className="stat-value">{dashboardStats.critical}</div>
            <div className="stat-label">Critical</div>
          </div>
        </div>
        <div className="stat-card stat-high">
          <div className="stat-icon">⚠️</div>
          <div className="stat-content">
            <div className="stat-value">{dashboardStats.high}</div>
            <div className="stat-label">High</div>
          </div>
        </div>
        <div className="stat-card stat-active">
          <div className="stat-icon">🔄</div>
          <div className="stat-content">
            <div className="stat-value">{dashboardStats.active}</div>
            <div className="stat-label">Active Cases</div>
          </div>
        </div>
      </div>

      <div className="dashboard-content">
        <div className="dashboard-section">
          <h3>🔧 Tool Status</h3>
          <div className="tool-status-grid">
            {Object.entries(toolStatus).map(([tool, status]) => (
              <div key={tool} className={`tool-status-card status-${status}`}>
                <div className="tool-status-header">
                  <span className="tool-status-icon">{getToolIcon(`${tool}_report`)}</span>
                  <span className="tool-status-name">{tool.charAt(0).toUpperCase() + tool.slice(1)}</span>
                  <span className={`tool-status-indicator ${status}`}>
                    {status === 'online' ? '●' : '○'}
                  </span>
                </div>
                <div className="tool-status-details">
                  <span className="status-text">{status.charAt(0).toUpperCase() + status.slice(1)}</span>
                  <span className="last-checked">Last checked: Just now</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="dashboard-section">
          <h3>📈 Recent Investigations</h3>
          <div className="investigations-table">
            <div className="table-header">
              <div className="table-cell">Title</div>
              <div className="table-cell">Severity</div>
              <div className="table-cell">Status</div>
              <div className="table-cell">Time</div>
              <div className="table-cell">Actions</div>
            </div>
            {filteredInvestigations.slice(0, 10).map((inv) => (
              <div key={inv.id} className="table-row">
                <div className="table-cell cell-title">{inv.title}</div>
                <div className="table-cell">
                  <span className={`severity-badge severity-${inv.status?.toLowerCase()}`}>
                    {inv.status}
                  </span>
                </div>
                <div className="table-cell">
                  <span className={`status-badge-small status-${inv.status?.toLowerCase()}`}>
                    {inv.status}
                  </span>
                </div>
                <div className="table-cell cell-time">{inv.updatedAt}</div>
                <div className="table-cell cell-actions">
                  <button 
                    onClick={() => {
                      setSelectedCase(inv.id);
                      setCurrentView('chat');
                    }}
                    className="action-button"
                  >
                    View
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );

  const renderSidebar = () => (
    <div className={`sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-header">
        <div className="brand">
          <span className="brand-icon">🔒</span>
          <span className={`brand-text ${sidebarCollapsed ? 'hidden' : ''}`}>Security Copilot</span>
        </div>
        <div className="sidebar-actions">
          <button 
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="collapse-button"
            title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {sidebarCollapsed ? '→' : '←'}
          </button>
          <button 
            onClick={() => setShowSettings(true)}
            className="settings-button"
            title="Settings"
          >
            ⚙️
          </button>
          <button 
            onClick={() => setDarkMode(!darkMode)}
            className="theme-toggle"
            title={darkMode ? 'Light mode' : 'Dark mode'}
          >
            {darkMode ? '☀️' : '🌙'}
          </button>
        </div>
      </div>
      
      <div className="sidebar-nav">
        <button 
          className={`nav-item ${currentView === 'chat' ? 'active' : ''}`}
          onClick={() => setCurrentView('chat')}
        >
          <span className="nav-icon">💬</span>
          <span className={`nav-text ${sidebarCollapsed ? 'hidden' : ''}`}>Chat</span>
        </button>
        <button 
          className={`nav-item ${currentView === 'dashboard' ? 'active' : ''}`}
          onClick={() => setCurrentView('dashboard')}
        >
          <span className="nav-icon">📊</span>
          <span className={`nav-text ${sidebarCollapsed ? 'hidden' : ''}`}>Dashboard</span>
        </button>
        <div className="nav-divider"></div>
        <button
          className={`nav-item ${currentView === 'predictive' ? 'active' : ''}`}
          onClick={() => setCurrentView('predictive')}
        >
          <span className="nav-icon">🔮</span>
          <span className={`nav-text ${sidebarCollapsed ? 'hidden' : ''}`}>Predictive Analytics</span>
        </button>
        <button
          className={`nav-item ${currentView === 'collaborative' ? 'active' : ''}`}
          onClick={() => setCurrentView('collaborative')}
        >
          <span className="nav-icon">👥</span>
          <span className={`nav-text ${sidebarCollapsed ? 'hidden' : ''}`}>Collaborative</span>
        </button>
        <button
          className={`nav-item ${currentView === 'blockchain' ? 'active' : ''}`}
          onClick={() => setCurrentView('blockchain')}
        >
          <span className="nav-icon">⛓️</span>
          <span className={`nav-text ${sidebarCollapsed ? 'hidden' : ''}`}>Blockchain Evidence</span>
        </button>
        <button
          className={`nav-item ${currentView === 'anomaly' ? 'active' : ''}`}
          onClick={() => setCurrentView('anomaly')}
        >
          <span className="nav-icon">🧠</span>
          <span className={`nav-text ${sidebarCollapsed ? 'hidden' : ''}`}>Neural Anomaly</span>
        </button>
        <button
          className={`nav-item ${currentView === 'threat-actor' ? 'active' : ''}`}
          onClick={() => setCurrentView('threat-actor')}
        >
          <span className="nav-icon">🎭</span>
          <span className={`nav-text ${sidebarCollapsed ? 'hidden' : ''}`}>Threat Actor Persona</span>
        </button>
        <button
          className={`nav-item ${currentView === 'response' ? 'active' : ''}`}
          onClick={() => setCurrentView('response')}
        >
          <span className="nav-icon">⚡</span>
          <span className={`nav-text ${sidebarCollapsed ? 'hidden' : ''}`}>Automated Response</span>
        </button>
      </div>
      
      <div className={`investigations-list ${sidebarCollapsed ? 'hidden' : ''}`}>
        <div className="list-header">
          <h3>Investigations</h3>
          <span className="list-count">{investigations.length}</span>
        </div>
        {investigations.map((inv) => (
          <div 
            key={inv.id}
            className={`investigation-item ${selectedCase === inv.id ? 'active' : ''}`}
            onClick={() => {
              setSelectedCase(inv.id);
              setCurrentView('chat');
            }}
          >
            <div className="inv-header">
              <span className="inv-title">{inv.title}</span>
              <span className={`inv-status status-${inv.status?.toLowerCase()}`}>
                {inv.status}
              </span>
            </div>
            <div className="inv-meta">
              <span className="inv-time">{inv.updatedAt}</span>
            </div>
            <div className="inv-summary">{inv.summary}</div>
          </div>
        ))}
      </div>
    </div>
  );

  const renderSettingsModal = () => (
    showSettings && (
      <div className="modal-overlay" onClick={() => setShowSettings(false)}>
        <div className="modal-content settings-modal" onClick={(e) => e.stopPropagation()}>
          <div className="modal-header">
            <h3>⚙️ Settings</h3>
            <button 
              onClick={() => setShowSettings(false)}
              className="modal-close"
            >
              ✕
            </button>
          </div>
          <div className="modal-body">
            <div className="settings-section">
              <h4>Appearance</h4>
              <div className="setting-item">
                <label>Dark Mode</label>
                <button 
                  onClick={() => setDarkMode(!darkMode)}
                  className={`toggle-button ${darkMode ? 'active' : ''}`}
                >
                  {darkMode ? 'ON' : 'OFF'}
                </button>
              </div>
            </div>
            <div className="settings-section">
              <h4>Tool Configuration</h4>
              <div className="setting-item">
                <label>VirusTotal</label>
                <select className="setting-select">
                  <option>Online</option>
                  <option>Offline</option>
                </select>
              </div>
              <div className="setting-item">
                <label>Wazuh SIEM</label>
                <select className="setting-select">
                  <option>Online</option>
                  <option>Offline</option>
                </select>
              </div>
              <div className="setting-item">
                <label>MISP</label>
                <select className="setting-select">
                  <option>Online</option>
                  <option>Offline</option>
                </select>
              </div>
              <div className="setting-item">
                <label>Shodan</label>
                <select className="setting-select">
                  <option>Online</option>
                  <option>Offline</option>
                </select>
              </div>
            </div>
            <div className="settings-section">
              <h4>Notifications</h4>
              <div className="setting-item">
                <label>Alert Notifications</label>
                <button className={`toggle-button active`}>ON</button>
              </div>
              <div className="setting-item">
                <label>Sound Effects</label>
                <button className={`toggle-button`}>OFF</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    )
  );

  return (
    <div className={`app-container ${darkMode ? 'dark' : 'light'}`}>
      {renderSidebar()}
      
      <div className="main-content">
        {currentView === 'chat' ? (
          <>
            <div className="chat-header">
              <h1>Security Investigation Hub</h1>
              <div className="header-actions">
                <button 
                  onClick={() => setCurrentView('dashboard')}
                  className="dashboard-btn-header"
                >
                  📊 Dashboard
                </button>
                <button 
                  onClick={() => setShowUploadModal(true)}
                  className="upload-btn-header"
                  disabled={uploading}
                >
                  📎 Upload File
                </button>
              </div>
            </div>

            <div className="messages-container">
              {messages.map((message) => (
                <div key={message.id} className={`message ${message.role}`}>
                  <div className="message-content">
                    {message.role === 'assistant' && message.report ? (
                      <>
                        {renderAiAnswer(message.ai_answer)}
                        {renderReport(message.report)}
                      </>
                    ) : (
                      <p>{message.text}</p>
                    )}
                  </div>
                  <div className="message-time">{message.time}</div>
                </div>
              ))}
              {loading && (
                <div className="message assistant">
                  <div className="message-content">
                    <p>🔄 Analyzing security data...</p>
                  </div>
                </div>
              )}
            </div>

            <form onSubmit={handleSend} className="input-form">
              <button
                type="button"
                onClick={() => setShowUploadModal(true)}
                className="upload-button"
                disabled={uploading}
                title="Upload file for analysis"
              >
                {uploading ? '⏳' : '📎'}
              </button>
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask about alerts, IOCs, or investigation steps..."
                className="input-field"
                disabled={loading}
              />
              <button 
                type="submit" 
                className="send-button"
                disabled={loading || !input.trim()}
              >
                {loading ? '⏳' : '➤'}
              </button>
            </form>
          </>
        ) : currentView === 'dashboard' ? (
          renderDashboard()
        ) : currentView === 'predictive' ? (
          <PredictiveAnalytics />
        ) : currentView === 'collaborative' ? (
          <CollaborativeInvestigation />
        ) : currentView === 'blockchain' ? (
          <BlockchainEvidence />
        ) : currentView === 'anomaly' ? (
          <NeuralAnomalyDetection />
        ) : currentView === 'threat-actor' ? (
          <ThreatActorPersona />
        ) : currentView === 'response' ? (
          <AutomatedResponse />
        ) : (
          renderDashboard()
        )}
      </div>

      {showUploadModal && (
        <div className="modal-overlay" onClick={() => setShowUploadModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>📎 Upload File for Analysis</h3>
              <button 
                onClick={() => setShowUploadModal(false)}
                className="modal-close"
              >
                ✕
              </button>
            </div>
            <div className="modal-body">
              <div 
                className="upload-zone"
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  const file = e.dataTransfer.files[0];
                  if (file) handleFileUpload(file);
                }}
              >
                <input
                  type="file"
                  id="file-upload"
                  className="file-input"
                  onChange={(e) => {
                    const file = e.target.files[0];
                    if (file) handleFileUpload(file);
                  }}
                />
                <label htmlFor="file-upload" className="upload-label">
                  <div className="upload-icon">📁</div>
                  <p>Drag & drop a file here or click to select</p>
                  <p className="upload-hint">Supports: logs, images, screenshots, config files</p>
                </label>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
