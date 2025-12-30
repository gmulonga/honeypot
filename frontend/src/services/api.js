import axios from 'axios';

// Create axios instance with base URL
const api = axios.create({
  baseURL: 'http://localhost:8000/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000, // 30 second timeout
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    return response.data;
  },
  (error) => {
    if (error.response) {
      // Server responded with error
      const message = error.response.data?.detail ||
        error.response.data?.message ||
        error.response.statusText;

      console.error('API Error:', {
        status: error.response.status,
        message: message,
        url: error.config.url,
      });

      if (error.response.status === 401) {
        localStorage.removeItem('token');
        window.location.href = '/login';
      }
    } else if (error.request) {
      // Request was made but no response
      console.error('Network Error:', error.request);
    } else {
      // Something else happened
      console.error('Error:', error.message);
    }

    return Promise.reject(error);
  }
);

// Helper function for file uploads
export const uploadFile = async (file, honeypotType, description = '') => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('honeypot_type', honeypotType);
  formData.append('description', description);

  return api.post('/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
};

// Helper function for honeypot connection
export const connectHoneypot = async (connectionData) => {
  return api.post('/connect', connectionData);
};

// Helper function for dashboard stats
export const getDashboardStats = async () => {
  return api.get('/dashboard/stats');
};

// Helper function for analysis
export const analyzeLogs = async (analysisRequest) => {
  return api.post('/analyze', analysisRequest);
};

// Helper function for STIX report
export const generateStixReport = async (attackIds) => {
  return api.post('/stix/generate', { attack_ids: attackIds });
};

// Helper function for downloading reports
export const downloadReport = async (reportType) => {
  return api.get(`/report/download/${reportType}`, {
    responseType: 'blob',
  });
};

// Helper function for MITRE mapping
export const mapToMitre = async (attackId) => {
  return api.get(`/mitre/map/${attackId}`);
};

// NEW: Get all uploaded files
export const getUploadedFiles = async (skip = 0, limit = 10) => {
  return api.get(`/uploads?skip=${skip}&limit=${limit}`);
};

// NEW: Get file analysis
export const getFileAnalysis = async (fileId) => {
  return api.get(`/uploads/${fileId}/analysis`);
};

// NEW: Get attack logs for a file
export const getFileAttackLogs = async (fileId, skip = 0, limit = 100) => {
  return api.get(`/uploads/${fileId}/attack-logs?skip=${skip}&limit=${limit}`);
};

// NEW: Get STIX report for a file
export const getFileStixReport = async (fileId) => {
  return api.get(`/uploads/${fileId}/stix`);
};

export { api };