import { useState, useEffect, Suspense, lazy } from 'react';
import Navigation from './components/Navigation';
import HUDHeader from './components/HUDHeader';
import { cyberAudio } from './utils/cyberSound';
import { applyThemeToDom, getStoredTheme } from './theme/cyberThemes';
import './styles/components.css';

// Lazy load route components for ultra-fast initial rendering
const ChatInterface = lazy(() => import('./components/ChatInterface'));
const HomeDashboard = lazy(() => import('./components/HomeDashboard'));
const SecurityDashboardModule = lazy(() => import('./components/SecurityDashboard'));
const InvestigationDashboard = lazy(() => import('./components/InvestigationDashboard'));
const ReportsDashboard = lazy(() => import('./components/ReportsDashboard'));
const Alerts = lazy(() => import('./components/detection/Alerts'));
const ThreatIntelDashboard = lazy(() => import('./components/ThreatIntelDashboard'));
const CyberRange = lazy(() => import('./components/CyberRange'));
const SOARPanel = lazy(() => import('./components/SOARPanel'));
const MitreMatrix = lazy(() => import('./components/MitreMatrix'));
const SwarmHub = lazy(() => import('./components/SwarmHub'));

const PageLoader = () => (
  <div style={{
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    height: '60vh',
    gap: 16
  }}>
    <div style={{
      width: 48,
      height: 48,
      borderRadius: '50%',
      border: '3px solid rgba(0, 245, 212, 0.2)',
      borderTopColor: 'var(--primary-color, #00f5d4)',
      boxShadow: '0 0 16px var(--primary-color, #00f5d4)',
      animation: 'spin-fast 0.65s linear infinite'
    }} />
    <div style={{
      color: 'var(--primary-color, #00f5d4)',
      fontSize: '0.78rem',
      fontWeight: 800,
      letterSpacing: '0.14em',
      fontFamily: 'JetBrains Mono, monospace'
    }}>
      CALIBRATING QUANTUM HUD TELEMETRY…
    </div>
  </div>
);

function App() {
  const [currentView, setCurrentView] = useState('home');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [scanlinesActive, setScanlinesActive] = useState(() => {
    return localStorage.getItem('sentinel_scanlines') === 'true';
  });
  const [user] = useState({ username: 'Admin', roles: ['Enterprise SOC Commander'] });

  // Initialize Cyber Theme
  useEffect(() => {
    applyThemeToDom(getStoredTheme());
  }, []);

  // Sync scanlines
  useEffect(() => {
    localStorage.setItem('sentinel_scanlines', scanlinesActive ? 'true' : 'false');
  }, [scanlinesActive]);

  // Alt + 1..9 fast navigation hotkeys
  useEffect(() => {
    const handleGlobalHotkeys = (e) => {
      if (e.altKey && !e.ctrlKey && !e.metaKey) {
        const viewMap = {
          '1': 'home',
          '2': 'simulator',
          '3': 'soar',
          '4': 'mitre',
          '5': 'chat',
          '6': 'alerts',
          '7': 'investigation',
          '8': 'intel',
          '9': 'reports'
        };
        if (viewMap[e.key]) {
          e.preventDefault();
          cyberAudio.playNav();
          setCurrentView(viewMap[e.key]);
        }
      }
    };
    window.addEventListener('keydown', handleGlobalHotkeys);
    return () => window.removeEventListener('keydown', handleGlobalHotkeys);
  }, []);

  const renderView = () => {
    switch (currentView) {
      case 'home': return <HomeDashboard setCurrentView={setCurrentView} />;
      case 'simulator': return <CyberRange />;
      case 'soar': return <SOARPanel />;
      case 'mitre': return <MitreMatrix />;
      case 'chat': return <ChatInterface />;
      case 'alerts': return <Alerts />;
      case 'investigation': return <InvestigationDashboard />;
      case 'intel': return <ThreatIntelDashboard />;
      case 'reports': return <ReportsDashboard />;
      case 'swarm': return <SwarmHub />;
      case 'security': return <SecurityDashboardModule />;
      default: return <HomeDashboard setCurrentView={setCurrentView} />;
    }
  };

  return (
    <div
      className={scanlinesActive ? 'cyber-scanlines-active' : ''}
      style={{
        background: 'var(--bg-deepest, #02040a)',
        color: 'var(--text-primary, #e0fbfc)',
        minHeight: '100vh',
        display: 'flex',
        position: 'relative',
        overflowX: 'hidden'
      }}
    >
      {/* Dynamic Cyber Grid & Radiant Field Overlay */}
      <div style={{
        position: 'fixed',
        inset: 0,
        backgroundImage: `
          radial-gradient(circle at 18% 22%, rgba(0, 245, 212, 0.07) 0%, transparent 45%),
          radial-gradient(circle at 82% 78%, rgba(139, 92, 246, 0.08) 0%, transparent 45%),
          linear-gradient(rgba(255, 255, 255, 0.018) 1px, transparent 1px),
          linear-gradient(90deg, rgba(255, 255, 255, 0.018) 1px, transparent 1px)
        `,
        backgroundSize: '100% 100%, 100% 100%, 36px 36px, 36px 36px',
        pointerEvents: 'none',
        zIndex: 0
      }} />

      {/* Navigation Sidebar */}
      <Navigation
        currentView={currentView}
        setCurrentView={(id) => {
          cyberAudio.playNav();
          setCurrentView(id);
        }}
        user={user}
        sidebarCollapsed={sidebarCollapsed}
        setSidebarCollapsed={setSidebarCollapsed}
      />

      {/* Main Command View Area */}
      <div style={{
        flex: 1,
        marginLeft: sidebarCollapsed ? '80px' : '280px',
        display: 'flex',
        flexDirection: 'column',
        minHeight: '100vh',
        transition: 'margin-left 300ms cubic-bezier(0.25, 0.8, 0.25, 1)',
        position: 'relative',
        zIndex: 1
      }}>
        {/* Holographic Top HUD Header */}
        <HUDHeader
          currentView={currentView}
          setCurrentView={(id) => {
            cyberAudio.playNav();
            setCurrentView(id);
          }}
          scanlinesActive={scanlinesActive}
          setScanlinesActive={setScanlinesActive}
        />

        {/* Dynamic Route Content */}
        <main style={{
          flex: 1,
          padding: '24px 28px',
          overflowY: 'auto'
        }}>
          <Suspense fallback={<PageLoader />}>
            {renderView()}
          </Suspense>
        </main>
      </div>
    </div>
  );
}

export default App;
