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
const SwarmHub = lazy(() => import('./components/SwarmHub'));
const MLThreatDetection = lazy(() => import('./components/MLThreatDetection'));

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
      width: 44,
      height: 44,
      borderRadius: '50%',
      border: '3px solid rgba(59, 130, 246, 0.2)',
      borderTopColor: '#3b82f6',
      animation: 'spin-fast 0.65s linear infinite'
    }} />
    <div style={{
      color: '#94a3b8',
      fontSize: '0.78rem',
      fontWeight: 700,
      letterSpacing: '0.1em',
      fontFamily: 'JetBrains Mono, monospace'
    }}>
      LOADING ENTERPRISE SOC MODULE…
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

  // Alt + 1..8 fast navigation hotkeys
  useEffect(() => {
    const handleGlobalHotkeys = (e) => {
      if (e.altKey && !e.ctrlKey && !e.metaKey) {
        const viewMap = {
          '1': 'home',
          '2': 'chat',
          '3': 'mldetection',
          '4': 'alerts',
          '5': 'investigation',
          '6': 'intel',
          '7': 'reports',
          '8': 'swarm',
          'm': 'mldetection',
          'M': 'mldetection'
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
      case 'chat': return <ChatInterface />;
      case 'mldetection': return <MLThreatDetection />;
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
        background: 'var(--bg-deepest, #0b0f19)',
        color: 'var(--text-primary, #f8fafc)',
        minHeight: '100vh',
        display: 'flex',
        position: 'relative',
        overflowX: 'hidden'
      }}
    >
      {/* Clean Subtle Grid Overlay */}
      <div style={{
        position: 'fixed',
        inset: 0,
        backgroundImage: `
          linear-gradient(rgba(255, 255, 255, 0.015) 1px, transparent 1px),
          linear-gradient(90deg, rgba(255, 255, 255, 0.015) 1px, transparent 1px)
        `,
        backgroundSize: '36px 36px',
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
