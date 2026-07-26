/**
 * Validation utilities for the Security Copilot application
 * Provides input validation, data sanitization, and error handling
 */

export const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

export const validateIP = (ip) => {
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipRegex.test(ip);
};

export const validateHash = (hash) => {
  // Supports MD5 (32), SHA1 (40), SHA256 (64)
  const hashRegex = /^[a-fA-F0-9]{32,64}$/;
  return hashRegex.test(hash);
};

export const validateURL = (url) => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input
    .replace(/[<>]/g, '') // Remove potential HTML tags
    .trim()
    .substring(0, 1000); // Limit length
};

export const validateInvestigationQuery = (query) => {
  if (!query || typeof query !== 'string') {
    return { valid: false, error: 'Query must be a non-empty string' };
  }
  
  if (query.length < 3) {
    return { valid: false, error: 'Query must be at least 3 characters long' };
  }
  
  if (query.length > 1000) {
    return { valid: false, error: 'Query must be less than 1000 characters' };
  }
  
  return { valid: true };
};

export const validateFileUpload = (file) => {
  if (!file) {
    return { valid: false, error: 'No file provided' };
  }
  
  const maxSize = 50 * 1024 * 1024; // 50MB
  if (file.size > maxSize) {
    return { valid: false, error: 'File size must be less than 50MB' };
  }
  
  const allowedTypes = [
    'text/plain',
    'text/log',
    'application/json',
    'application/xml',
    'text/csv',
    'image/png',
    'image/jpeg',
    'image/gif',
    'image/webp'
  ];
  
  if (!allowedTypes.includes(file.type) && !file.name.match(/\.(log|txt|json|xml|csv|png|jpg|jpeg|gif|webp)$/i)) {
    return { valid: false, error: 'File type not supported' };
  }
  
  return { valid: true };
};

export const validateSessionData = (data) => {
  if (!data || typeof data !== 'object') {
    return { valid: false, error: 'Session data must be an object' };
  }
  
  if (!data.user_id || typeof data.user_id !== 'string') {
    return { valid: false, error: 'Valid user ID is required' };
  }
  
  return { valid: true };
};

export const validateEvidenceData = (data) => {
  if (!data || typeof data !== 'object') {
    return { valid: false, error: 'Evidence data must be an object' };
  }
  
  if (!data.type || !['log', 'screenshot', 'network_capture', 'memory_dump', 'file_hash'].includes(data.type)) {
    return { valid: false, error: 'Valid evidence type is required' };
  }
  
  if (!data.data || typeof data.data !== 'string') {
    return { valid: false, error: 'Evidence data is required' };
  }
  
  return { valid: true };
};

export const handleApiError = (error) => {
  console.error('API Error:', error);
  
  if (error.response) {
    // Server responded with error status
    return {
      message: error.response.data?.message || 'Server error occurred',
      status: error.response.status,
      type: 'server_error'
    };
  } else if (error.request) {
    // Request made but no response
    return {
      message: 'No response from server. Please check your connection.',
      type: 'network_error'
    };
  } else {
    // Error in request setup
    return {
      message: error.message || 'An unexpected error occurred',
      type: 'client_error'
    };
  }
};

export const createErrorResponse = (message, type = 'error', details = null) => {
  return {
    success: false,
    message,
    type,
    details,
    timestamp: new Date().toISOString()
  };
};

export const createSuccessResponse = (data, message = 'Success') => {
  return {
    success: true,
    message,
    data,
    timestamp: new Date().toISOString()
  };
};