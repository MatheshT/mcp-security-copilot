import { useState, useEffect } from 'react';
import Login from './components/Login';
import Register from './components/Register';
import AdminPanel from './components/AdminPanel';
import AuditLogs from './components/AuditLogs';
import BackupManagement from './components/BackupManagement';
import FeatureFlags from './components/FeatureFlags';
import Navigation from './components/Navigation';
import ChatInterface from './components/ChatInterface';
import WazuhDashboard from './components/detection/WazuhDashboard';
import Alerts from './components/detection/Alerts';
import Agents from './components/detection/Agents';
import EventLogs from './components/detection/EventLogs';
import LiveInvestigation from './components/detection/LiveInvestigation';
import InvestigationHistory from './components/detection/InvestigationHistory';
import ThreatIntelligence from './components/security/ThreatIntelligence';
import ThreatHunting from './components/security/ThreatHunting';
import ReportsPanel from './components/security/ReportsPanel';
import SettingsPanel from './components/security/SettingsPanel';
import './styles/components.css';
import './styles/auth.css';
import './styles/enterprise.css';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [currentView, setCurrentView] = useState('chat');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [showRegister, setShowRegister] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    if (token && savedUser) {
      setIsAuthenticated(true);
      setUser(JSON.parse(savedUser));
    }
  }, []);

  const handleLogin = (userData) => {
    setIsAuthenticated(true);
    setUser(userData);
  };

  const handleRegister = (userData) => {
    setShowRegister(false);
    handleLogin(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setIsAuthenticated(false);
    setUser(null);
  };

  if (!isAuthenticated) {
    if (showRegister) {
      return <Register onRegister={handleRegister} onLogin={() => setShowRegister(false)} />;
    }
    return <Login onLogin={handleLogin} onRegister={() => setShowRegister(true)} />;
  }

  const renderContent = () => {
    switch (currentView) {

      /* ── HOME ── */
      case 'chat':
        return <ChatInterface />;

      case 'dashboard':
        return <WazuhDashboard />;

      /* ── DETECTION ── */
      case 'wazuh-dashboard':
        return <WazuhDashboard />;
      case 'alerts':
        return <Alerts />;
      case 'agents':
        return <Agents />;
      case 'event-logs':
        return <EventLogs />;

      /* ── AI INVESTIGATION ── */
      case 'live-investigation':
        return <LiveInvestigation />;
      case 'investigation-history':
        return <InvestigationHistory />;
      case 'ai-reasoning':
        return <LiveInvestigation />;
      case 'investigation-timeline':
        return <InvestigationHistory />;

      /* ── THREAT INTELLIGENCE ── */
      case 'virustotal':
      case 'mitre-attack':
      case 'abuseipdb':
      case 'sigma-rules':
      case 'ioc-explorer':
        return <ThreatIntelligence view={currentView} />;

      /* ── THREAT HUNTING ── */
      case 'ioc-search':
      case 'process-analysis':
      case 'host-analysis':
      case 'user-activity':
        return <ThreatHunting view={currentView} />;

      /* ── REPORTS ── */
      case 'investigation-reports':
      case 'executive-reports':
      case 'pdf-export':
      case 'report-history':
        return <ReportsPanel view={currentView} />;

      /* ── SETTINGS ── */
      case 'api-keys':
      case 'windows-collectors':
      case 'wazuh-settings':
        return <SettingsPanel view={currentView} />;

      case 'system-health':
        return <SettingsPanel view="system-health" />;

      /* ── ADMIN ── */
      case 'admin':
      case 'user-management':
        return <AdminPanel />;

      case 'audit':
        return <AuditLogs />;

      case 'backup':
        return <BackupManagement />;

      case 'features':
        return <FeatureFlags />;

      default:
        return (
          <div style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
            height: '60vh', gap: '12px', color: 'var(--text-muted)'
          }}>
            <span style={{ fontSize: '48px' }}>🛡️</span>
            <span style={{ fontSize: '16px' }}>Select a view from the sidebar</span>
          </div>
        );
    }
  };

  return (
    <div className={`app-container ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
      <Navigation
        currentView={currentView}
        setCurrentView={setCurrentView}
        user={user}
        onLogout={handleLogout}
        sidebarCollapsed={sidebarCollapsed}
        setSidebarCollapsed={setSidebarCollapsed}
      />

      {/* Main Content */}
      <div className="main-content">
        <header className="top-bar">
          <h1>SentinelAI X</h1>
          <div className="status-indicators">
            <span className="status-badge online">● API Online</span>
            <span className="status-badge online">● Database Connected</span>
            <span className="status-badge online">● Cache Active</span>
          </div>
        </header>

        <main className="content-area">
          {renderContent()}
        </main>
      </div>
    </div>
  );
}

export default App;