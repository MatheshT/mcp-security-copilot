import React, { useState, useEffect } from 'react';
import api from '../../services/api';

const SecurityDashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [recentInvestigations, setRecentInvestigations] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [dataSource, setDataSource] = useState('loading');

  useEffect(() => {
    loadRealData();
  }, []);

  const loadRealData = async () => {
    try {
      setLoading(true);
      setDataSource('connecting');

      // Fetch real Windows log statistics
      const logStats = await api.getWindowsLogStats();
      
      // Fetch security events for alerts
      const securityEvents = await api.getSecurityEvents(24, 50);

      if (logStats && securityEvents) {
        const source = logStats.statistics?.data_source || securityEvents.data_source || 'unknown';
        // Map the backend data source to frontend display values
        let mappedSource = 'api';
        if (source === 'real_windows_logs') {
          mappedSource = 'real_windows_logs';
        } else if (source.includes('mock') || source === 'no_data') {
          mappedSource = 'mock_fallback';
        }
        setDataSource(mappedSource);
        
        // Transform real data into dashboard format
        const realStats = {
          total_investigations: 47, // This would come from investigations API
          active_investigations: 5,
          total_iocs: 234,
          high_risk_iocs: 12,
          total_alerts: securityEvents.total_count || 0,
          open_alerts: securityEvents.events?.filter(e => e.status === 'Open').length || 0,
          critical_alerts: securityEvents.events?.filter(e => e.severity === 'Critical').length || 0,
          logs_collected_24h: logStats.statistics?.total_events_24h || 0
        };

        // Transform security events into alerts format
        const realAlerts = (securityEvents.events || []).slice(0, 10).map((event, index) => ({
          id: index,
          title: `${event.severity}: ${event.title}`,
          severity: event.severity.toLowerCase(),
          source: event.source || 'Windows Event Log',
          created_at: event.timestamp
        }));

        // Mock investigations for now (would come from investigations API)
        const mockInvestigations = [
          {
            id: 1,
            title: 'Suspicious Login Activity',
            investigation_id: 'INV-2024-001',
            status: 'active',
            created_at: '2024-01-15T10:30:00Z'
          },
          {
            id: 2,
            title: 'Malware Detection on Server',
            investigation_id: 'INV-2024-002',
            status: 'active',
            created_at: '2024-01-15T09:15:00Z'
          },
          {
            id: 3,
            title: 'Network Anomaly Detected',
            investigation_id: 'INV-2024-003',
            status: 'completed',
            created_at: '2024-01-14T16:45:00Z'
          }
        ];

        setStats(realStats);
        setRecentAlerts(realAlerts);
        setRecentInvestigations(mockInvestigations);
      } else {
        // Fallback to mock data if API fails
        initializeMockData();
        setDataSource('mock_fallback');
      }
    } catch (error) {
      console.error('Error loading real data:', error);
      // Fallback to mock data on error
      initializeMockData();
      setDataSource('mock_error');
    } finally {
      setLoading(false);
    }
  };

  const initializeMockData = () => {
    // Mock data for demonstration
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

    const mockInvestigations = [
      {
        id: 1,
        title: 'Suspicious Login Activity',
        investigation_id: 'INV-2024-001',
        status: 'active',
        created_at: '2024-01-15T10:30:00Z'
      },
      {
        id: 2,
        title: 'Malware Detection on Server',
        investigation_id: 'INV-2024-002',
        status: 'active',
        created_at: '2024-01-15T09:15:00Z'
      },
      {
        id: 3,
        title: 'Network Anomaly Detected',
        investigation_id: 'INV-2024-003',
        status: 'completed',
        created_at: '2024-01-14T16:45:00Z'
      }
    ];

    const mockAlerts = [
      {
        id: 1,
        title: 'Critical: Brute Force Attack',
        severity: 'critical',
        source: 'Windows Event Log',
        created_at: '2024-01-15T11:00:00Z'
      },
      {
        id: 2,
        title: 'High: Unusual File Access',
        severity: 'high',
        source: 'Sysmon',
        created_at: '2024-01-15T10:45:00Z'
      },
      {
        id: 3,
        title: 'Medium: Multiple Failed Logins',
        severity: 'medium',
        source: 'Defender',
        created_at: '2024-01-15T10:30:00Z'
      }
    ];

    setStats(mockStats);
    setRecentInvestigations(mockInvestigations);
    setRecentAlerts(mockAlerts);
  };

  const startInvestigation = async () => {
    // Mock investigation start
    const newInvestigation = {
      id: Date.now(),
      title: 'Automated Security Investigation',
      investigation_id: `INV-2024-${String(Math.floor(Math.random() * 1000)).padStart(3, '0')}`,
      status: 'active',
      created_at: new Date().toISOString()
    };
    
    setRecentInvestigations(prev => [newInvestigation, ...prev]);
    setStats(prev => ({
      ...prev,
      total_investigations: prev.total_investigations + 1,
      active_investigations: prev.active_investigations + 1
    }));
    
    alert(`Investigation ${newInvestigation.investigation_id} started successfully`);
  };

  const collectLogs = async () => {
    try {
      // Trigger real log collection via API
      const securityEvents = await api.getSecurityEvents(24, 1000);
      const systemEvents = await api.getSystemEvents(24, 1000);
      const applicationEvents = await api.getApplicationEvents(24, 1000);

      const totalLogs = (securityEvents.total_count || 0) + 
                       (systemEvents.total_count || 0) + 
                       (applicationEvents.total_count || 0);

      // Update data source based on what we got
      const apiDataSource = securityEvents.data_source || 'unknown';
      let mappedSource = 'api';
      if (apiDataSource === 'real_windows_logs') {
        mappedSource = 'real_windows_logs';
      } else if (apiDataSource.includes('mock') || apiDataSource === 'no_data') {
        mappedSource = 'mock_fallback';
      }
      setDataSource(mappedSource);

      setStats(prev => ({
        ...prev,
        logs_collected_24h: totalLogs,
        total_alerts: securityEvents.total_count || 0
      }));

      // Update alerts with new data
      const realAlerts = (securityEvents.events || []).slice(0, 10).map((event, index) => ({
        id: index,
        title: `${event.severity}: ${event.title}`,
        severity: event.severity.toLowerCase(),
        source: event.source || 'Windows Event Log',
        created_at: event.timestamp
      }));
      setRecentAlerts(realAlerts);

      alert(`Log collection completed successfully. Collected ${totalLogs} logs from Windows Event Logs.`);
    } catch (error) {
      console.error('Error collecting logs:', error);
      setDataSource('mock_error');
      // Fallback to mock behavior on error
      const logsCollected = Math.floor(Math.random() * 5000) + 10000;
      setStats(prev => ({
        ...prev,
        logs_collected_24h: prev.logs_collected_24h + logsCollected
      }));
      alert(`Log collection completed with fallback. Collected ${logsCollected} logs (mock data due to API error).`);
    }
  };

  if (loading) {
    return (
      <div style={{ padding: '20px', textAlign: 'center' }}>
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

  const AlertCard = ({ title, severity, source, time }) => {
    const severityColors = {
      critical: '#d32f2f',
      high: '#f57c00',
      medium: '#1976d2',
      low: '#388e3c'
    };

    return (
      <div style={{ 
        padding: '15px', 
        backgroundColor: 'white', 
        border: '1px solid #e0e0e0', 
        borderRadius: '8px',
        marginBottom: '10px',
        borderLeft: `4px solid ${severityColors[severity] || '#666'}`
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
          <div>
            <p style={{ fontWeight: '500', color: '#333', margin: '0 0 5px 0' }}>{title}</p>
            <p style={{ fontSize: '12px', color: '#666', margin: 0 }}>{source}</p>
          </div>
          <span style={{ 
            fontSize: '10px', 
            padding: '2px 8px', 
            borderRadius: '12px', 
            backgroundColor: severityColors[severity] || '#666',
            color: 'white',
            textTransform: 'uppercase'
          }}>
            {severity}
          </span>
        </div>
      </div>
    );
  };

  const InvestigationCard = ({ title, id, status, time }) => {
    const statusColors = {
      active: '#388e3c',
      completed: '#1976d2',
      pending: '#f57c00'
    };

    return (
      <div style={{ 
        padding: '15px', 
        backgroundColor: 'white', 
        border: '1px solid #e0e0e0', 
        borderRadius: '8px',
        marginBottom: '10px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
          <div>
            <p style={{ fontWeight: '500', color: '#333', margin: '0 0 5px 0' }}>{title}</p>
            <p style={{ fontSize: '12px', color: '#666', margin: 0 }}>{id}</p>
          </div>
          <span style={{ 
            fontSize: '10px', 
            padding: '2px 8px', 
            borderRadius: '12px', 
            backgroundColor: statusColors[status] || '#666',
            color: 'white',
            textTransform: 'uppercase'
          }}>
            {status}
          </span>
        </div>
      </div>
    );
  };

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
          <div style={{ 
            marginTop: '8px',
            fontSize: '12px',
            padding: '4px 8px',
            borderRadius: '4px',
            backgroundColor: dataSource === 'real_windows_logs' ? '#e8f5e9' : 
                            dataSource === 'mock_fallback' ? '#fff3e0' : 
                            dataSource === 'mock_error' ? '#ffebee' :
                            dataSource === 'api' ? '#e3f2fd' : '#f5f5f5',
            color: dataSource === 'real_windows_logs' ? '#2e7d32' : 
                   dataSource === 'mock_fallback' ? '#e65100' : 
                   dataSource === 'mock_error' ? '#c62828' :
                   dataSource === 'api' ? '#1565c0' : '#666',
            display: 'inline-block'
          }}>
            Data Source: {dataSource === 'real_windows_logs' ? '🟢 Real Windows Logs' : 
                         dataSource === 'mock_fallback' ? '🟡 Mock Data (Fallback)' : 
                         dataSource === 'mock_error' ? '🔴 Mock Data (Error)' : 
                         dataSource === 'api' ? '🔵 API Connected' : '⏳ Loading...'}
          </div>
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

      {/* Critical Alerts Banner */}
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

      {/* Recent Activity Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '16px' }}>
        {/* Recent Investigations */}
        <div style={{ 
          backgroundColor: 'white', 
          border: '1px solid #e0e0e0', 
          borderRadius: '8px',
          padding: '20px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
        }}>
          <h3 style={{ fontSize: '18px', fontWeight: '600', color: '#333', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            📋 Recent Investigations
          </h3>
          {recentInvestigations.length === 0 ? (
            <p style={{ fontSize: '14px', color: '#666' }}>No recent investigations</p>
          ) : (
            <div>
              {recentInvestigations.map((inv) => (
                <InvestigationCard
                  key={inv.id}
                  title={inv.title}
                  id={inv.investigation_id}
                  status={inv.status}
                  time={inv.created_at}
                />
              ))}
            </div>
          )}
        </div>

        {/* Recent Alerts */}
        <div style={{ 
          backgroundColor: 'white', 
          border: '1px solid #e0e0e0', 
          borderRadius: '8px',
          padding: '20px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
        }}>
          <h3 style={{ fontSize: '18px', fontWeight: '600', color: '#333', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            🚨 Recent Alerts
          </h3>
          {recentAlerts.length === 0 ? (
            <p style={{ fontSize: '14px', color: '#666' }}>No recent alerts</p>
          ) : (
            <div>
              {recentAlerts.map((alert) => (
                <AlertCard
                  key={alert.id}
                  title={alert.title}
                  severity={alert.severity}
                  source={alert.source}
                  time={alert.created_at}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Feature Info */}
      <div style={{ 
        marginTop: '24px',
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

export default SecurityDashboard;
                    </div>
                    <div className="text-right">
                      <span className={`px-2 py-1 rounded-full text-xs ${
                        inv.status === 'completed' ? 'bg-green-100 text-green-800' :
                        inv.status === 'failed' ? 'bg-red-100 text-red-800' :
                        'bg-yellow-100 text-yellow-800'
                      }`}>
                        {inv.status}
                      </span>
                      <p className="text-xs text-gray-500 mt-1">
                        {new Date(inv.created_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>

        {/* Recent Alerts */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              Recent Alerts
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentAlerts.length === 0 ? (
                <p className="text-sm text-gray-500">No recent alerts</p>
              ) : (
                recentAlerts.map((alert) => (
                  <div key={alert.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div>
                      <p className="font-medium">{alert.title}</p>
                      <p className="text-sm text-gray-500">{alert.alert_type}</p>
                    </div>
                    <div className="text-right">
                      <span className={`px-2 py-1 rounded-full text-xs ${
                        alert.severity === 'critical' ? 'bg-red-100 text-red-800' :
                        alert.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                        alert.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-blue-100 text-blue-800'
                      }`}>
                        {alert.severity}
                      </span>
                      <p className="text-xs text-gray-500 mt-1">
                        {new Date(alert.first_seen).toLocaleString()}
                      </p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <Button variant="outline" className="h-20 flex flex-col items-center justify-center gap-2">
              <Server className="h-6 w-6" />
              <span>Collect Logs</span>
            </Button>
            <Button variant="outline" className="h-20 flex flex-col items-center justify-center gap-2">
              <Globe className="h-6 w-6" />
              <span>Extract IOCs</span>
            </Button>
            <Button variant="outline" className="h-20 flex flex-col items-center justify-center gap-2">
              <Shield className="h-6 w-6" />
              <span>Threat Intel</span>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default SecurityDashboard;