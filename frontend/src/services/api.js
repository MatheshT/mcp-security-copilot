const API_BASE_URL = import.meta.env.VITE_API_URL || '';

class ApiService {
  constructor() {
    this.baseURL = API_BASE_URL;
  }

  getHeaders() {
    const token = localStorage.getItem('token');
    const headers = {
      'Content-Type': 'application/json'
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      ...options,
      headers: {
        ...this.getHeaders(),
        ...options.headers
      }
    };

    try {
      const response = await fetch(url, config);
      
      if (response.status === 401) {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = '/login';
        return null;
      }

      if (!response.ok) {
        throw new Error(`Request failed: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('API Error:', error);
      throw error;
    }
  }

  // Auth endpoints
  async login(username, password) {
    return this.request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });
  }

  async register(userData) {
    return this.request('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData)
    });
  }

  async logout() {
    await this.request('/api/auth/logout', { method: 'POST' });
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  }

  async getCurrentUser() {
    return this.request('/api/auth/me');
  }

  // Investigation endpoints
  async investigate(query) {
    return this.request('/api/investigate', {
      method: 'POST',
      body: JSON.stringify({ query })
    });
  }

  async uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    const token = localStorage.getItem('token');
    const response = await fetch(`${this.baseURL}/api/upload`, {
      method: 'POST',
      headers: {
        ...(token && { 'Authorization': `Bearer ${token}` })
      },
      body: formData
    });

    if (!response.ok) {
      throw new Error('Upload failed');
    }

    return response.json();
  }

  // User management
  async getUsers() {
    return this.request('/api/users/');
  }

  async createUser(userData) {
    return this.request('/api/users/', {
      method: 'POST',
      body: JSON.stringify(userData)
    });
  }

  async deleteUser(userId) {
    return this.request(`/api/users/${userId}`, {
      method: 'DELETE'
    });
  }

  // Audit logs
  async getAuditLogs(filters = {}) {
    const params = new URLSearchParams(filters);
    return this.request(`/api/audit/?${params}`);
  }

  // Backup management
  async getBackups() {
    return this.request('/api/backup/list');
  }

  async createBackup(backupName) {
    return this.request('/api/backup/create', {
      method: 'POST',
      body: JSON.stringify({ backup_name: backupName })
    });
  }

  async restoreBackup(backupName) {
    return this.request(`/api/backup/restore/${backupName}`, {
      method: 'POST'
    });
  }

  async deleteBackup(backupName) {
    return this.request(`/api/backup/${backupName}`, {
      method: 'DELETE'
    });
  }

  async cleanupBackups() {
    return this.request('/api/backup/cleanup', {
      method: 'POST'
    });
  }

  // Feature flags
  async getFeatureFlags() {
    return this.request('/api/feature-flags/');
  }

  async updateFeatureFlag(flagName, data) {
    return this.request(`/api/feature-flags/${flagName}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }

  // Windows Logs endpoints
  async getSecurityEvents(hours = 24, limit = 100) {
    return this.request(`/api/windows-logs/security?hours=${hours}&limit=${limit}`);
  }

  async getSystemEvents(hours = 24, limit = 100) {
    return this.request(`/api/windows-logs/system?hours=${hours}&limit=${limit}`);
  }

  async getApplicationEvents(hours = 24, limit = 100) {
    return this.request(`/api/windows-logs/application?hours=${hours}&limit=${limit}`);
  }

  async getWindowsLogStats() {
    return this.request('/api/windows-logs/stats');
  }

  // Detection endpoints
  async getWazuhAlerts(timeRange = '24h') {
    return this.request(`/api/detection/wazuh/alerts?time_range=${timeRange}`);
  }

  async getWazuhAgents() {
    return this.request('/api/detection/wazuh/agents');
  }

  async getAlerts(filters = {}) {
    const params = new URLSearchParams(filters);
    return this.request(`/api/detection/alerts?${params}`);
  }

  async updateAlertStatus(alertId, status) {
    return this.request(`/api/detection/alerts/${alertId}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status })
    });
  }

  async getEventLogs(timeRange = '24h', filters = {}) {
    const params = new URLSearchParams({ ...filters, time_range: timeRange });
    return this.request(`/api/detection/event-logs?${params}`);
  }

  async restartWazuhAgent(agentId) {
    return this.request(`/api/detection/wazuh/agents/${agentId}/restart`, {
      method: 'POST'
    });
  }

  async getDetectionStatistics() {
    return this.request('/api/detection/statistics');
  }
}

export default new ApiService();