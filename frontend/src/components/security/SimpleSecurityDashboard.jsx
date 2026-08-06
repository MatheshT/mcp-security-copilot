import React, { useState, useEffect } from 'react';

const SimpleSecurityDashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Initialize with mock data
    initializeMockData();
  }, []);

  const initializeMockData = () => {
    const mockStats = {
      total_investigations: 47,
      active_investigations: 5,
      total_iocs: 234,
      high_risk_iocs: 12,
      total_alerts: 156,
      open_alerts: 23,
      critical_alerts: 3,
      logs_collected_24h: 15420
    };
    setStats(mockStats);
    setLoading(false);
  };

  const startInvestigation = () => {
    const newId = `INV-2024-${String(Math.floor(Math.random() * 1000)).padStart(3, '0')}`;
    setStats(prev => ({
      ...prev,
      total_investigations: prev.total_investigations + 1,
      active_investigations: prev.active_investigations + 1
    }));
    alert(`Investigation ${newId} started successfully`);
  };

  const collectLogs = () => {
    const logsCollected = Math.floor(Math.random() * 5000) + 10000;
    setStats(prev => ({
      ...prev,
      logs_collected_24h: prev.logs_collected_24h + logsCollected
    }));
    alert(`Log collection completed. Collected ${logsCollected} logs.`);
  };

  if (loading) {
    return (
      <div style={{ padding: '24px', textAlign: 'center' }}>
        <div style={{ fontSize: '18px', color: '#666' }}>Loading security dashboard...</div>
      </div>
    );
  }

  const StatCard = ({ title, value, color, trend }) => (
    <div style={{ 
      padding: '20px', 
      backgroundColor: 'white', 
      border: '1px solid #e0e0e0', 
      borderRadius: '8px',
      boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
        <h3 style={{ fontSize: '14px', fontWeight: '500', color: '#333', margin: 0 }}>{title}</h3>
        <div style={{ width: '16px', height: '16px', borderRadius: '50%', backgroundColor: color }}></div>
      </div>
      <div style={{ fontSize: '28px', fontWeight: 'bold', color: '#333' }}>{value}</div>
      {trend && (
        <p style={{ fontSize: '12px', color: '#666', marginTop: '5px', margin: 0 }}>
          {trend}
        </p>
      )}
    </div>
  );

  return (
    <div style={{ padding: '24px', backgroundColor: '#f5f5f5', minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        marginBottom: '24px',
        backgroundColor: 'white',
        padding: '20px',
        borderRadius: '8px',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
      }}>
        <div>
          <h1 style={{ fontSize: '32px', fontWeight: 'bold', color: '#333', margin: '0 0 8px 0' }}>
            🛡️ Security Operations Center
          </h1>
          <p style={{ fontSize: '16px', color: '#666', margin: 0 }}>
            Real-time security monitoring and analysis
          </p>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <button
            onClick={collectLogs}
            style={{
              padding: '10px 20px',
              backgroundColor: 'white',
              border: '1px solid #d0d0d0',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: '500',
              color: '#333'
            }}
          >
            📡 Collect Logs
          </button>
          <button
            onClick={startInvestigation}
            style={{
              padding: '10px 20px',
              backgroundColor: '#1976d2',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: '500',
              color: 'white'
            }}
          >
            🛡️ Start Investigation
          </button>
        </div>
      </div>

      {/* Critical Alerts Section */}
      {(stats?.critical_alerts > 0 || stats?.open_alerts > 0) && (
        <div style={{ 
          padding: '16px', 
          backgroundColor: '#ffebee', 
          border: '1px solid #ffcdd2', 
          borderRadius: '8px',
          marginBottom: '24px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px'
        }}>
          <span style={{ fontSize: '24px' }}>⚠️</span>
          <span style={{ color: '#c62828' }}>
            {stats?.critical_alerts > 0 && (
              <strong>{stats.critical_alerts} critical alerts</strong>
            )}
            {stats?.critical_alerts > 0 && stats?.open_alerts > 0 && ' and '}
            {stats?.open_alerts > 0 && (
              <span>{stats.open_alerts} open alerts</span>
            )}
            {' '}require immediate attention.
          </span>
        </div>
      )}

      {/* Stats Grid */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', 
        gap: '16px',
        marginBottom: '24px'
      }}>
        <StatCard
          title="Total Investigations"
          value={stats?.total_investigations || 0}
          color="#1976d2"
          trend="Last 30 days"
        />
        <StatCard
          title="Active Investigations"
          value={stats?.active_investigations || 0}
          color="#f57c00"
          trend="Currently running"
        />
        <StatCard
          title="Total IOCs"
          value={stats?.total_iocs || 0}
          color="#7b1fa2"
          trend="All time"
        />
        <StatCard
          title="High Risk IOCs"
          value={stats?.high_risk_iocs || 0}
          color="#d32f2f"
          trend="Requires attention"
        />
        <StatCard
          title="Total Alerts"
          value={stats?.total_alerts || 0}
          color="#1976d2"
          trend="All time"
        />
        <StatCard
          title="Open Alerts"
          value={stats?.open_alerts || 0}
          color="#f57c00"
          trend="Pending review"
        />
        <StatCard
          title="Critical Alerts"
          value={stats?.critical_alerts || 0}
          color="#c62828"
          trend="Immediate action"
        />
        <StatCard
          title="Logs (24h)"
          value={stats?.logs_collected_24h || 0}
          color="#388e3c"
          trend="Last 24 hours"
        />
      </div>

      {/* Feature Info */}
      <div style={{ 
        backgroundColor: 'white', 
        border: '1px solid #e0e0e0', 
        borderRadius: '8px',
        padding: '20px',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
      }}>
        <h3 style={{ fontSize: '18px', fontWeight: '600', color: '#333', marginBottom: '16px' }}>
          🚀 New Autonomous SOC Features
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
          <div style={{ padding: '16px', backgroundColor: '#e3f2fd', borderRadius: '6px' }}>
            <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#1976d2', marginBottom: '8px' }}>🔍 Automated Log Analysis</h4>
            <p style={{ fontSize: '13px', color: '#666', margin: 0 }}>
              Continuous monitoring and analysis of security logs from multiple sources including Windows Event Logs, Sysmon, and Defender.
            </p>
          </div>
          <div style={{ padding: '16px', backgroundColor: '#e8f5e9', borderRadius: '6px' }}>
            <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#388e3c', marginBottom: '8px' }}>🎯 IOC Extraction</h4>
            <p style={{ fontSize: '13px', color: '#666', margin: 0 }}>
              Automatic extraction and management of Indicators of Compromise including IPs, domains, hashes, and file paths.
            </p>
          </div>
          <div style={{ padding: '16px', backgroundColor: '#fff3e0', borderRadius: '6px' }}>
            <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#f57c00', marginBottom: '8px' }}>⚡ Real-time Alerting</h4>
            <p style={{ fontSize: '13px', color: '#666', margin: 0 }}>
              Instant alerts for critical security events with severity-based routing and automated response capabilities.
            </p>
          </div>
          <div style={{ padding: '16px', backgroundColor: '#f3e5f5', borderRadius: '6px' }}>
            <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#7b1fa2', marginBottom: '8px' }}>📊 Analytics Dashboard</h4>
            <p style={{ fontSize: '13px', color: '#666', margin: 0 }}>
              Comprehensive security analytics with trend analysis, threat hunting tools, and customizable reporting.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SimpleSecurityDashboard;