import React from 'react';

const Navigation = ({ currentView, setCurrentView, user, onLogout, sidebarCollapsed, setSidebarCollapsed }) => {
  const menuItems = [
    { section: 'Home', items: [
      { id: 'chat', label: '💬 AI Chat', icon: '💬' }
    ]},
    { section: 'Detection', items: [
      { id: 'wazuh-dashboard', label: '📊 Wazuh Dashboard', icon: '📊' },
      { id: 'alerts', label: '🚨 Alerts', icon: '🚨' },
      { id: 'agents', label: '🖥️ Agents', icon: '🖥️' },
      { id: 'event-logs', label: '📋 Event Logs', icon: '📋' }
    ]},
    { section: 'AI Investigation', items: [
      { id: 'live-investigation', label: '🔍 Live Investigation', icon: '🔍' },
      { id: 'investigation-history', label: '📜 Investigation History', icon: '📜' },
      { id: 'ai-reasoning', label: '🧠 AI Reasoning', icon: '🧠' },
      { id: 'investigation-timeline', label: '⏱️ Investigation Timeline', icon: '⏱️' }
    ]},
    { section: 'Threat Intelligence', items: [
      { id: 'virustotal', label: '🦠 VirusTotal', icon: '🦠' },
      { id: 'mitre-attack', label: '🎯 MITRE ATT&CK', icon: '🎯' },
      { id: 'abuseipdb', label: '🌐 AbuseIPDB', icon: '🌐' },
      { id: 'sigma-rules', label: '📜 Sigma Rules', icon: '📜' },
      { id: 'ioc-explorer', label: '🔍 IOC Explorer', icon: '🔍' }
    ]},
    { section: 'Threat Hunting', items: [
      { id: 'ioc-search', label: '🔎 Search IOC', icon: '🔎' },
      { id: 'process-analysis', label: '⚙️ Process Analysis', icon: '⚙️' },
      { id: 'host-analysis', label: '🖥️ Host Analysis', icon: '🖥️' },
      { id: 'user-activity', label: '👤 User Activity', icon: '👤' }
    ]},
    { section: 'Reports', items: [
      { id: 'investigation-reports', label: '📄 Investigation Reports', icon: '📄' },
      { id: 'executive-reports', label: '👔 Executive Reports', icon: '👔' },
      { id: 'pdf-export', label: '📑 PDF Export', icon: '📑' },
      { id: 'report-history', label: '📚 Report History', icon: '📚' }
    ]},
    { section: 'Settings', items: [
      { id: 'api-keys', label: '🔑 API Keys', icon: '🔑' },
      { id: 'windows-collectors', label: '🪟 Windows Collectors', icon: '🪟' },
      { id: 'wazuh-settings', label: '⚙️ Wazuh Settings', icon: '⚙️' },
      { id: 'user-management', label: '👥 User Management', icon: '👥' },
      { id: 'system-health', label: '💚 System Health', icon: '💚' }
    ]}
  ];

  return (
    <div className={`sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-header">
        <div className="brand">
          <span className="brand-icon">🛡️</span>
          <span className={`brand-text ${sidebarCollapsed ? 'hidden' : ''}`}>
            SentinelAI X
          </span>
        </div>
        <div className="sidebar-actions">
          <button 
            className="collapse-button"
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {sidebarCollapsed ? '→' : '←'}
          </button>
        </div>
      </div>

      <nav className="sidebar-nav">
        {menuItems.map((section) => (
          <div key={section.section} className="nav-section">
            <h3 className={`nav-section-title ${sidebarCollapsed ? 'hidden' : ''}`}>
              {section.section}
            </h3>
            {section.items.map((item) => (
              <button
                key={item.id}
                className={`nav-item ${currentView === item.id ? 'active' : ''}`}
                onClick={() => setCurrentView(item.id)}
                title={item.label}
              >
                <span className="nav-icon">{item.icon}</span>
                <span className={`nav-text ${sidebarCollapsed ? 'hidden' : ''}`}>
                  {item.label}
                </span>
              </button>
            ))}
          </div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className={`user-info ${sidebarCollapsed ? 'hidden' : ''}`}>
          <p className="user-name">{user?.username || 'Admin'}</p>
          <p className="user-roles">
            {user?.roles?.join(', ') || 'Administrator'}
          </p>
        </div>
        <button 
          className="logout-btn"
          onClick={onLogout}
          title="Logout"
        >
          🚪
        </button>
      </div>
    </div>
  );
};

export default Navigation;