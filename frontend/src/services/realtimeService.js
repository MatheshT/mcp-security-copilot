/**
 * Real-time service for live dashboard updates
 * Handles WebSocket connections and polling for live statistics
 */

class RealtimeService {
  constructor() {
    this.socket = null;
    this.listeners = new Map();
    this.pollingInterval = null;
    this.pollingFrequency = 5000; // 5 seconds
    this.isConnected = false;
  }

  connect(url) {
    try {
      this.socket = new WebSocket(url);
      
      this.socket.onopen = () => {
        console.log('WebSocket connected');
        this.isConnected = true;
        this.notifyListeners('connected', { status: 'connected' });
      };

      this.socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.notifyListeners(data.type, data.payload);
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };

      this.socket.onclose = () => {
        console.log('WebSocket disconnected');
        this.isConnected = false;
        this.notifyListeners('disconnected', { status: 'disconnected' });
        // Attempt to reconnect after 5 seconds
        setTimeout(() => this.connect(url), 5000);
      };

      this.socket.onerror = (error) => {
        console.error('WebSocket error:', error);
        this.isConnected = false;
      };
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      // Fallback to polling
      this.startPolling();
    }
  }

  disconnect() {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.stopPolling();
    this.isConnected = false;
  }

  subscribe(eventType, callback) {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set());
    }
    this.listeners.get(eventType).add(callback);
  }

  unsubscribe(eventType, callback) {
    if (this.listeners.has(eventType)) {
      this.listeners.get(eventType).delete(callback);
    }
  }

  notifyListeners(eventType, data) {
    if (this.listeners.has(eventType)) {
      this.listeners.get(eventType).forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error('Error in listener callback:', error);
        }
      });
    }
  }

  startPolling(endpoint = '/api/dashboard/stats') {
    if (this.pollingInterval) {
      return;
    }

    this.pollingInterval = setInterval(async () => {
      try {
        const response = await fetch(endpoint);
        if (response.ok) {
          const data = await response.json();
          this.notifyListeners('stats_update', data);
        }
      } catch (error) {
        console.error('Polling error:', error);
      }
    }, this.pollingFrequency);
  }

  stopPolling() {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }
  }

  setPollingFrequency(milliseconds) {
    this.pollingFrequency = milliseconds;
    if (this.pollingInterval) {
      this.stopPolling();
      this.startPolling();
    }
  }

  send(type, payload) {
    if (this.socket && this.isConnected) {
      this.socket.send(JSON.stringify({ type, payload }));
    } else {
      console.warn('Cannot send message: WebSocket not connected');
    }
  }
}

// Export singleton instance
export const realtimeService = new RealtimeService();

// Export class for testing
export default RealtimeService;