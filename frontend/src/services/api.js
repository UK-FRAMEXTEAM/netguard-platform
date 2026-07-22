import axios from 'axios';
import toast from 'react-hot-toast';

export const API_BASE_URL = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');

export function apiUrl(path) {
  return `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;
}

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: false,
});

function retryAfterSeconds(error) {
  const bodyValue = Number(error.response?.data?.retryAfterSeconds);
  if (Number.isFinite(bodyValue) && bodyValue > 0) return Math.ceil(bodyValue);
  const headerValue = Number(error.response?.headers?.['retry-after']);
  return Number.isFinite(headerValue) && headerValue > 0 ? Math.ceil(headerValue) : 0;
}

export function apiErrorMessage(error, fallback = 'Request failed') {
  if (!error.response) return 'NetGuard API is temporarily unreachable. Please try again.';
  if (error.response.status === 429) {
    const seconds = retryAfterSeconds(error);
    if (seconds) {
      const wait = seconds >= 60 ? `${Math.ceil(seconds / 60)} minute(s)` : `${seconds} second(s)`;
      return `Request limit reached. Please retry in ${wait}.`;
    }
  }
  return error.response?.data?.message || fallback;
}

export function notifyApiError(error, fallback) {
  const message = apiErrorMessage(error, fallback);
  toast.error(message, {
    // Reuse one toast so repeated clicks or parallel page loads cannot stack
    // identical errors down the screen.
    id: error.response?.status === 429 ? 'netguard-rate-limit' : 'netguard-api-error',
    duration: error.response?.status === 429 ? 6000 : 4000,
  });
  return message;
}

// Auto-attach token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('ng_token') || sessionStorage.getItem('ng_token');
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
      const url = String(err.config?.url || '');
      const isCredentialAttempt = [
        '/api/auth/login',
        '/api/auth/admin-login',
        '/api/auth/register',
      ].some((path) => url.includes(path));
      const hasStoredSession = Boolean(
        localStorage.getItem('ng_token') || sessionStorage.getItem('ng_token')
      );
      if (hasStoredSession && !isCredentialAttempt) {
        localStorage.removeItem('ng_token');
        sessionStorage.removeItem('ng_token');
        localStorage.removeItem('ng_user');
        sessionStorage.removeItem('ng_user');
        if (window.location.pathname !== '/login') window.location.assign('/login');
      }
    }
    return Promise.reject(err);
  }
);

export default api;
