import axios from 'axios';

export const API_BASE_URL = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');

export function apiUrl(path) {
  return `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;
}

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: false,
});

// Auto-attach token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('ng_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401 responses
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('ng_token');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export default api;
