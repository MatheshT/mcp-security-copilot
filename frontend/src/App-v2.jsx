import { useState } from 'react';
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
import './styles/enterprise.css';

function App() {
  const [currentView, setCurrentView] = useState('chat');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [user] = useState({ username: 'Admin', roles: ['Administrator'] });

  const handleLogout = () => {
    // Logout functionality disabled - authentication removed
    console.log('Logout clicked');
  };

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
      <div
        className="main-content"
        style={{
          marginLeft: sidebarCollapsed ? 80 : 280,
          width: `calc(100% - ${sidebarCollapsed ? 80 : 280}px)`,
          transition: 'margin-left 300ms ease, width 300ms ease',
          minHeight: '100vh',
          padding: '24px 32px 32px',
          position: 'relative',
          zIndex: 0,
          boxSizing: 'border-box'
        }}
      >
        <header className="top-bar" style={{ marginBottom: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '16px' }}>
            <div>
              <h1 style={{ margin: 0 }}>SentinelAI X</h1>
              <p style={{ margin: '8px 0 0', color: 'var(--text-muted)', fontSize: '0.95rem' }}>
                Your AI security operations dashboard.
              </p>
            </div>
            <div className="status-indicators" style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
              <span className="status-badge online">● API Online</span>
              <span className="status-badge online">● Database Connected</span>
              <span className="status-badge online">● Cache Active</span>
            </div>
          </div>
        </header>

        <main className="content-area" style={{ minHeight: 'calc(100vh - 120px)' }}>
          {renderContent()}
        </main>
      </div>
    </div>
  );
}

export default App;