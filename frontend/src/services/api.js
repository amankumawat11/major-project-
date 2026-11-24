import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 45000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const scanService = {
  // Execute a new website scan
  performScan: async (target, scanMode = 'quick', authorized = true) => {
    const response = await api.post('/scan', {
      target,
      scan_mode: scanMode,
      authorized,
    });
    return response.data;
  },

  // Fetch all completed scans for history & dashboard
  getScans: async () => {
    const response = await api.get('/scans');
    return response.data;
  },

  // Fetch individual scan details
  getScan: async (scanId) => {
    const response = await api.get(`/scans/${scanId}`);
    return response.data;
  },

  // Delete a scan record
  deleteScan: async (scanId) => {
    const response = await api.delete(`/scans/${scanId}`);
    return response.data;
  },

  // Compare two scans
  compareScans: async (scanId1, scanId2) => {
    const response = await api.post('/scans/compare', {
      scan_id_1: scanId1,
      scan_id_2: scanId2,
    });
    return response.data;
  },

  // Dashboard statistics
  getDashboardStats: async () => {
    const response = await api.get('/dashboard/stats');
    return response.data;
  },

  // Vulnerabilities list with optional filters
  getVulnerabilities: async (filters = {}) => {
    const response = await api.get('/vulnerabilities', { params: filters });
    return response.data;
  },

  // Update vulnerability remediation status
  updateVulnerabilityStatus: async (vulnId, remediationStatus) => {
    const response = await api.patch(`/vulnerabilities/${vulnId}`, {
      remediation_status: remediationStatus,
    });
    return response.data;
  },

  // AI Vulnerability Explanation on demand
  explainVulnerability: async (vulnData) => {
    const response = await api.post('/ai/explain', vulnData);
    return response.data;
  },

  // AI Security Assistant Chat
  chatWithAssistant: async (message, sessionId = 'default', scanId = null) => {
    const response = await api.post('/ai/chat', {
      message,
      session_id: sessionId,
      scan_id: scanId,
    });
    return response.data;
  },

  // Get chat history
  getChatHistory: async (sessionId = 'default') => {
    const response = await api.get(`/ai/chat/${sessionId}`);
    return response.data;
  },

  // Download PDF Report URL
  getReportDownloadUrl: (scanId) => {
    return `${API_BASE_URL}/reports/${scanId}`;
  },

  // Check backend health
  checkHealth: async () => {
    const response = await api.get('/health');
    return response.data;
  },
};

export default scanService;
