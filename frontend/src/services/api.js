import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || '';

export const api = {
  // Upload PCAP
  async uploadPcap(file) {
    const formData = new FormData();
    formData.append('file', file);
    const res = await axios.post(`${API_BASE}/api/upload`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return res.data;
  },

  // Get job details
  async getAnalysis(jobId) {
    const res = await axios.get(`${API_BASE}/api/analysis/${jobId}`);
    return res.data;
  },

  // Get sessions
  async getSessions(jobId, params = {}) {
    const res = await axios.get(`${API_BASE}/api/analysis/${jobId}/sessions`, { params });
    return res.data;
  },

  // Get findings
  async getFindings(jobId, params = {}) {
    const res = await axios.get(`${API_BASE}/api/analysis/${jobId}/findings`, { params });
    return res.data;
  },

  // Get certificates
  async getCertificates(jobId) {
    const res = await axios.get(`${API_BASE}/api/analysis/${jobId}/certificates`);
    return res.data;
  },

  // Get risk breakdown
  async getRisk(jobId) {
    const res = await axios.get(`${API_BASE}/api/analysis/${jobId}/risk`);
    return res.data;
  },

  // List analyses
  async listAnalyses() {
    const res = await axios.get(`${API_BASE}/api/analyses`);
    return res.data;
  },

  // Get ML metrics
  async getMLMetrics() {
    const res = await axios.get(`${API_BASE}/api/ml/metrics`);
    return res.data;
  },

  // Health check
  async getHealth() {
    const res = await axios.get(`${API_BASE}/api/health`);
    return res.data;
  },

  // Export URLs
  getExportUrl(jobId, format) {
    return `${API_BASE}/api/analysis/${jobId}/export/${format}`;
  }
};
