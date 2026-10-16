import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

console.log('=== API Configuration ===');
console.log('API Base URL:', API_BASE_URL);
console.log('Environment VITE_API_URL:', import.meta.env.VITE_API_URL);

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000, // 30 second timeout for API calls (Wazuh can be slow)
});

// Separate instance for Wazuh endpoints with extended timeout
const wazuhApi = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 40000, // 40 second timeout for Wazuh endpoints
});

// Request interceptor for main API
api.interceptors.request.use(
  (config) => {
    console.log('🚀 API Request:', config.method?.toUpperCase(), config.url);
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    console.error('❌ API Request error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor for main API
api.interceptors.response.use(
  (response) => {
    console.log('✅ API Response successful:', response.config.url, response.status);
    return response;
  },
  (error) => {
    console.error('❌ API Response error:', error.config?.url, error.message);
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Add same interceptors to Wazuh API
wazuhApi.interceptors.request.use(
  (config) => {
    console.log('🚀 Wazuh API Request:', config.method?.toUpperCase(), config.url);
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    console.error('❌ Wazuh API Request error:', error);
    return Promise.reject(error);
  }
);

wazuhApi.interceptors.response.use(
  (response) => {
    console.log('✅ Wazuh API Response successful:', response.config.url, response.status);
    return response;
  },
  (error) => {
    console.error('❌ Wazuh API Response error:', error.config?.url, error.message);
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Dashboard APIs
export const getDashboardData = async () => {
  const response = await api.get('/api/dashboard');
  return response.data;
};

export const getSecurityOverview = async () => {
  const response = await api.get('/api/dashboard/security-overview');
  return response.data;
};

export const getThreatTimeline = async () => {
  const response = await api.get('/api/dashboard/threat-timeline');
  return response.data;
};

// Investigation APIs
export const investigateQuery = async (query) => {
  const response = await api.post('/api/investigation/investigate', { query });
  return response.data;
};

export const chatWithAI = async (message) => {
  const response = await api.post('/api/investigation/chat', { query: message, message });
  return response.data;
};

export const comprehensiveInvestigation = async (query, options = {}) => {
  const response = await api.post('/api/investigation/comprehensive', {
    query,
    use_all_tools: options.useAllTools !== false,
    focus_wazuh: options.focusWazuh !== false
  });
  return response.data;
};

export const getInvestigationStatus = async () => {
  const response = await api.get('/api/investigation/status');
  return response.data;
};

export const switchInvestigationMode = async (enhanced = true) => {
  const response = await api.post('/api/investigation/switch-mode', null, {
    params: { enhanced }
  });
  return response.data;
};

export const uploadInvestigationFile = async (file) => {
  const formData = new FormData();
  formData.append('file', file);
  const response = await api.post('/api/investigation/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
};

// Wazuh APIs (using extended timeout)
export const getWazuhAlerts = async (params = {}) => {
  const response = await wazuhApi.get('/api/detection/wazuh/alerts', { params });
  return response.data;
};

export const getAlerts = async (params = {}) => {
  // Alias for Wazuh alerts to maintain compatibility
  return getWazuhAlerts(params);
};

export const getWazuhAgents = async () => {
  const response = await wazuhApi.get('/api/detection/wazuh/agents');
  return response.data;
};

export const getWazuhStatistics = async () => {
  const response = await wazuhApi.get('/api/detection/wazuh/statistics');
  return response.data;
};

export const collectWazuhLogs = async (params = {}) => {
  const response = await wazuhApi.get('/api/detection/wazuh/logs/collect', { params });
  return response.data;
};

export const restartWazuhAgent = async (agentId) => {
  const response = await api.post(`/api/detection/wazuh/agents/${agentId}/restart`);
  return response.data;
};

export const updateAlertStatus = async (alertId, status) => {
  const response = await api.put(`/api/detection/alerts/${alertId}/status`, { status });
  return response.data;
};

export const getEventLogs = async (timeRange = '24h') => {
  try {
    const response = await api.get('/api/logs/events', { params: { time_range: timeRange } });
    return response.data;
  } catch (error) {
    console.error('Error loading event logs:', error);
    // Return empty logs if endpoint doesn't exist
    return { logs: [], total: 0 };
  }
};

export const getWazuhDashboard = async () => {
  try {
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8001';
    console.log('=== Fetching Wazuh Dashboard ===');
    console.log('API URL:', apiUrl);
    console.log('Full endpoint:', `${apiUrl}/api/dashboard/wazuh`);
    
    const response = await api.get('/api/dashboard/wazuh');
    console.log('Wazuh dashboard API call successful:', response.data);
    console.log('Response connected status:', response.data?.connected);
    return response.data;
  } catch (error) {
    console.error('❌ Wazuh dashboard API call failed:', error);
    console.error('Error details:', error.response?.data || error.message);
    throw error;
  }
};

// Search APIs
export const searchSecurityEvents = async (query, filters = {}) => {
  const response = await api.post('/api/search/events', { query, filters });
  return response.data;
};

export const searchThreats = async (indicators) => {
  const response = await api.post('/api/search/threats', { indicators });
  return response.data;
};

// Report APIs
export const generateInvestigationReport = async (data) => {
  const response = await api.post('/api/report/investigation', data);
  return response.data;
};

export const getReportHistory = async () => {
  const response = await api.get('/api/report/history');
  return response.data;
};

// User APIs
export const login = async (credentials) => {
  const response = await api.post('/api/users/login', credentials);
  return response.data;
};

export const logout = async () => {
  const response = await api.post('/api/users/logout');
  return response.data;
};

export const getUserProfile = async () => {
  const response = await api.get('/api/users/profile');
  return response.data;
};

// Health Check
export const healthCheck = async () => {
  const response = await api.get('/api/health');
  return response.data;
};

export const systemInfo = async () => {
  const response = await api.get('/api/info');
  return response.data;
};

export default api;