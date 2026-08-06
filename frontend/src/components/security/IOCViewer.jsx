import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { 
  Globe, 
  FileText, 
  AlertTriangle, 
  Search, 
  Filter,
  ExternalLink,
  Shield,
  X
} from 'lucide-react';

const IOCViewer = () => {
  const [iocs, setIOCs] = useState([]);
  const [filteredIOCs, setFilteredIOCs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({
    type: 'all',
    riskLevel: 'all',
    search: ''
  });

  const iocTypes = [
    { value: 'all', label: 'All Types' },
    { value: 'ip_address', label: 'IP Addresses' },
    { value: 'domain', label: 'Domains' },
    { value: 'url', label: 'URLs' },
    { value: 'file_hash', label: 'File Hashes' },
    { value: 'email', label: 'Email Addresses' },
    { value: 'registry_key', label: 'Registry Keys' },
    { value: 'file_path', label: 'File Paths' },
    { value: 'process', label: 'Processes' },
    { value: 'user', label: 'Users' }
  ];

  const riskLevels = [
    { value: 'all', label: 'All Risk Levels' },
    { value: 'critical', label: 'Critical' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'low', label: 'Low' }
  ];

  useEffect(() => {
    fetchIOCs();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [iocs, filters]);

  const fetchIOCs = async () => {
    try {
      const response = await fetch('/api/log-analysis/iocs');
      const data = await response.json();
      
      if (data.status === 'success') {
        setIOCs(data.iocs);
        setError(null);
      } else {
        setError('Failed to fetch IOCs');
      }
    } catch (err) {
      setError('Error connecting to server');
      console.error('IOC fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = [...iocs];

    // Apply type filter
    if (filters.type !== 'all') {
      filtered = filtered.filter(ioc => ioc.ioc_type === filters.type);
    }

    // Apply risk level filter
    if (filters.riskLevel !== 'all') {
      filtered = filtered.filter(ioc => ioc.risk_level === filters.riskLevel);
    }

    // Apply search filter
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      filtered = filtered.filter(ioc => 
        ioc.ioc_value.toLowerCase().includes(searchLower) ||
        (ioc.notes && ioc.notes.toLowerCase().includes(searchLower))
      );
    }

    setFilteredIOCs(filtered);
  };

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const getRiskColor = (riskLevel) => {
    switch (riskLevel) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getIOCIcon = (iocType) => {
    switch (iocType) {
      case 'ip_address': return <Globe className="h-4 w-4" />;
      case 'domain': return <Globe className="h-4 w-4" />;
      case 'url': return <ExternalLink className="h-4 w-4" />;
      case 'file_hash': return <FileText className="h-4 w-4" />;
      default: return <Shield className="h-4 w-4" />;
    }
  };

  const analyzeIOC = async (iocId) => {
    try {
      const response = await fetch('/api/log-analysis/threat-intel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ioc_ids: [iocId],
          sources: ['virustotal', 'abuseipdb', 'mitre_attack']
        })
      });
      
      const data = await response.json();
      if (data.status === 'success') {
        alert('Threat intelligence analysis completed');
        fetchIOCs();
      }
    } catch (err) {
      console.error('Failed to analyze IOC:', err);
      alert('Failed to analyze IOC');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p>Loading IOCs...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">Indicators of Compromise</h1>
        <p className="text-muted-foreground">View and manage extracted IOCs</p>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Filter className="h-5 w-5" />
            Filters
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-4">
            <div>
              <label className="text-sm font-medium mb-1 block">Search</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search IOCs..."
                  value={filters.search}
                  onChange={(e) => handleFilterChange('search', e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            
            <div>
              <label className="text-sm font-medium mb-1 block">IOC Type</label>
              <select
                value={filters.type}
                onChange={(e) => handleFilterChange('type', e.target.value)}
                className="w-full px-3 py-2 border rounded-md"
              >
                {iocTypes.map(type => (
                  <option key={type.value} value={type.value}>{type.label}</option>
                ))}
              </select>
            </div>
            
            <div>
              <label className="text-sm font-medium mb-1 block">Risk Level</label>
              <select
                value={filters.riskLevel}
                onChange={(e) => handleFilterChange('riskLevel', e.target.value)}
                className="w-full px-3 py-2 border rounded-md"
              >
                {riskLevels.map(level => (
                  <option key={level.value} value={level.value}>{level.label}</option>
                ))}
              </select>
            </div>

            <div className="flex items-end">
              <Button
                onClick={() => setFilters({ type: 'all', riskLevel: 'all', search: '' })}
                variant="outline"
                className="w-full"
              >
                <X className="h-4 w-4 mr-2" />
                Clear Filters
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* IOC List */}
      <Card>
        <CardHeader>
          <CardTitle>
            IOCs ({filteredIOCs.length} / {iocs.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {filteredIOCs.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No IOCs found matching the current filters
            </div>
          ) : (
            <div className="space-y-3">
              {filteredIOCs.map((ioc) => (
                <div key={ioc.id} className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50">
                  <div className="flex items-center gap-3 flex-1">
                    <div className="p-2 bg-muted rounded">
                      {getIOCIcon(ioc.ioc_type)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-medium truncate">{ioc.ioc_value}</p>
                      <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <span className="capitalize">{ioc.ioc_type.replace('_', ' ')}</span>
                        {ioc.ioc_subtype && <span>• {ioc.ioc_subtype}</span>}
                        <span>• First seen: {new Date(ioc.first_seen).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getRiskColor(ioc.risk_level)}`}>
                      {ioc.risk_level}
                    </span>
                    
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => analyzeIOC(ioc.id)}
                    >
                      <Shield className="h-4 w-4 mr-1" />
                      Analyze
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default IOCViewer;