import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Button } from '../ui/Button';
import { 
  Activity, 
  Clock, 
  CheckCircle, 
  XCircle, 
  AlertTriangle,
  Shield,
  FileText,
  Calendar,
  User,
  TrendingUp
} from 'lucide-react';

const InvestigationViewer = () => {
  const [investigations, setInvestigations] = useState([]);
  const [selectedInvestigation, setSelectedInvestigation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');

  const statusFilters = [
    { value: 'all', label: 'All Status' },
    { value: 'planning', label: 'Planning' },
    { value: 'evidence_collection', label: 'Evidence Collection' },
    { value: 'ioc_extraction', label: 'IOC Extraction' },
    { value: 'threat_intel_analysis', label: 'Threat Intel' },
    { value: 'correlation_analysis', label: 'Correlation' },
    { value: 'risk_assessment', label: 'Risk Assessment' },
    { value: 'reporting', label: 'Reporting' },
    { value: 'completed', label: 'Completed' },
    { value: 'failed', label: 'Failed' }
  ];

  useEffect(() => {
    fetchInvestigations();
  }, [filter]);

  const fetchInvestigations = async () => {
    try {
      setLoading(true);
      const params = filter !== 'all' ? `?status=${filter}` : '';
      const response = await fetch(`/api/log-analysis/investigation${params}`);
      const data = await response.json();
      
      if (data.status === 'success') {
        setInvestigations(data.investigations);
        setError(null);
      } else {
        setError('Failed to fetch investigations');
      }
    } catch (err) {
      setError('Error connecting to server');
      console.error('Investigation fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchInvestigationDetails = async (investigationId) => {
    try {
      const response = await fetch(`/api/log-analysis/investigation/${investigationId}`);
      const data = await response.json();
      
      if (data.status === 'success') {
        setSelectedInvestigation(data.investigation);
      }
    } catch (err) {
      console.error('Failed to fetch investigation details:', err);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'bg-green-100 text-green-800 border-green-200';
      case 'failed': return 'bg-red-100 text-red-800 border-red-200';
      case 'reporting': return 'bg-blue-100 text-blue-800 border-blue-200';
      case 'risk_assessment': return 'bg-purple-100 text-purple-800 border-purple-200';
      case 'correlation_analysis': return 'bg-indigo-100 text-indigo-800 border-indigo-200';
      case 'threat_intel_analysis': return 'bg-cyan-100 text-cyan-800 border-cyan-200';
      case 'ioc_extraction': return 'bg-teal-100 text-teal-800 border-teal-200';
      case 'evidence_collection': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'planning': return 'bg-gray-100 text-gray-800 border-gray-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4" />;
      case 'failed': return <XCircle className="h-4 w-4" />;
      default: return <Clock className="h-4 w-4" />;
    }
  };

  const getRiskColor = (riskLevel) => {
    switch (riskLevel) {
      case 'critical': return 'text-red-600';
      case 'high': return 'text-orange-600';
      case 'medium': return 'text-yellow-600';
      case 'low': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p>Loading investigations...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Security Investigations</h1>
          <p className="text-muted-foreground">Autonomous SOC investigation management</p>
        </div>
        
        <div className="flex items-center gap-2">
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="px-3 py-2 border rounded-md"
          >
            {statusFilters.map(f => (
              <option key={f.value} value={f.value}>{f.label}</option>
            ))}
          </select>
          
          <Button onClick={() => fetchInvestigations()}>
            <Activity className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {/* Investigation List */}
      <div className="grid gap-4">
        {investigations.length === 0 ? (
          <Card>
            <CardContent className="text-center py-8 text-muted-foreground">
              No investigations found
            </CardContent>
          </Card>
        ) : (
          investigations.map((inv) => (
            <Card key={inv.id} className="hover:shadow-md transition-shadow">
              <CardContent className="p-6">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="text-lg font-semibold">{inv.title}</h3>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getStatusColor(inv.status)}`}>
                        <span className="flex items-center gap-1">
                          {getStatusIcon(inv.status)}
                          {inv.status.replace('_', ' ')}
                        </span>
                      </span>
                    </div>
                    
                    <p className="text-sm text-muted-foreground mb-3">
                      {inv.description || 'No description provided'}
                    </p>
                    
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <p className="text-muted-foreground">Investigation ID</p>
                        <p className="font-medium">{inv.investigation_id}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Type</p>
                        <p className="font-medium capitalize">{inv.investigation_type}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Risk Score</p>
                        <p className={`font-medium ${getRiskColor(inv.risk_level)}`}>
                          {inv.risk_score}/100 ({inv.risk_level})
                        </p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Created</p>
                        <p className="font-medium">
                          {new Date(inv.created_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex flex-col gap-2 ml-4">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => fetchInvestigationDetails(inv.id)}
                    >
                      <FileText className="h-4 w-4 mr-1" />
                      View Details
                    </Button>
                    
                    {inv.status === 'completed' && inv.recommendations && (
                      <Button size="sm" variant="outline">
                        <Shield className="h-4 w-4 mr-1" />
                        View Report
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      {/* Investigation Detail Modal */}
      {selectedInvestigation && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
          <Card className="max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <CardHeader>
              <div className="flex justify-between items-start">
                <div>
                  <CardTitle className="text-2xl">{selectedInvestigation.title}</CardTitle>
                  <p className="text-muted-foreground mt-1">
                    {selectedInvestigation.investigation_id}
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setSelectedInvestigation(null)}
                >
                  ×
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Overview */}
              <div>
                <h3 className="font-semibold mb-3">Overview</h3>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  <div>
                    <p className="text-sm text-muted-foreground">Status</p>
                    <p className="font-medium capitalize">{selectedInvestigation.status}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Type</p>
                    <p className="font-medium capitalize">{selectedInvestigation.investigation_type}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Priority</p>
                    <p className="font-medium capitalize">{selectedInvestigation.priority}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Risk Score</p>
                    <p className={`font-medium ${getRiskColor(selectedInvestigation.risk_level)}`}>
                      {selectedInvestigation.risk_score}/100
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Risk Level</p>
                    <p className={`font-medium capitalize ${getRiskColor(selectedInvestigation.risk_level)}`}>
                      {selectedInvestigation.risk_level}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Time Range</p>
                    <p className="font-medium">{selectedInvestigation.time_range_hours} hours</p>
                  </div>
                </div>
              </div>

              {/* Investigation Parameters */}
              {selectedInvestigation.log_sources && (
                <div>
                  <h3 className="font-semibold mb-3">Investigation Parameters</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-sm text-muted-foreground">Log Sources</p>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {selectedInvestigation.log_sources.map(source => (
                          <span key={source} className="px-2 py-1 bg-muted rounded text-xs capitalize">
                            {source}
                          </span>
                        ))}
                      </div>
                    </div>
                    {selectedInvestigation.priority_areas && (
                      <div>
                        <p className="text-sm text-muted-foreground">Priority Areas</p>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {selectedInvestigation.priority_areas.map(area => (
                            <span key={area} className="px-2 py-1 bg-muted rounded text-xs">
                              {area}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Executive Summary */}
              {selectedInvestigation.executive_summary && (
                <div>
                  <h3 className="font-semibold mb-3">Executive Summary</h3>
                  <div className="bg-muted p-4 rounded-lg">
                    <p className="text-sm whitespace-pre-wrap">{selectedInvestigation.executive_summary}</p>
                  </div>
                </div>
              )}

              {/* Recommendations */}
              {selectedInvestigation.recommendations && selectedInvestigation.recommendations.length > 0 && (
                <div>
                  <h3 className="font-semibold mb-3">Recommendations</h3>
                  <div className="space-y-2">
                    {selectedInvestigation.recommendations.map((rec, index) => (
                      <div key={index} className="flex items-start gap-2 p-3 border rounded-lg">
                        <Shield className="h-5 w-5 text-blue-600 mt-0.5" />
                        <p className="text-sm">{rec}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Timeline */}
              <div>
                <h3 className="font-semibold mb-3">Timeline</h3>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Started</span>
                    <span>{new Date(selectedInvestigation.start_time).toLocaleString()}</span>
                  </div>
                  {selectedInvestigation.end_time && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Ended</span>
                      <span>{new Date(selectedInvestigation.end_time).toLocaleString()}</span>
                    </div>
                  )}
                  {selectedInvestigation.start_time && selectedInvestigation.end_time && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Duration</span>
                      <span>
                        {Math.round((new Date(selectedInvestigation.end_time) - new Date(selectedInvestigation.start_time)) / 1000 / 60)} minutes
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};

export default InvestigationViewer;