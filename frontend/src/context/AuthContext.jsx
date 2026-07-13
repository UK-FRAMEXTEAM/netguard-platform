import { createContext, useContext, useEffect, useState } from 'react';
import api, { apiUrl } from '../services/api';

const AuthContext = createContext(null);

function tokenFromCallback() {
  const hash = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  const query = new URLSearchParams(window.location.search);
  return hash.get('token') || query.get('token');
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [token, setTokenState] = useState(() => localStorage.getItem('ng_token'));

  const persistToken = (nextToken) => {
    if (nextToken) {
      localStorage.setItem('ng_token', nextToken);
      api.defaults.headers.common.Authorization = `Bearer ${nextToken}`;
    } else {
      localStorage.removeItem('ng_token');
      delete api.defaults.headers.common.Authorization;
    }
    setTokenState(nextToken || null);
  };

  const loadUser = async (activeToken) => {
    try {
      api.defaults.headers.common.Authorization = `Bearer ${activeToken}`;
      const response = await api.get('/api/auth/me');
      if (!response.data.success) throw new Error('Authentication failed');
      setUser(response.data.user);
      return response.data.user;
    } catch {
      persistToken(null);
      setUser(null);
      return null;
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const callbackToken = tokenFromCallback();
    const activeToken = callbackToken || localStorage.getItem('ng_token');

    if (!activeToken) {
      setLoading(false);
      return;
    }

    persistToken(activeToken);
    loadUser(activeToken).then((loadedUser) => {
      if (callbackToken) {
        window.history.replaceState({}, '', loadedUser ? '/dashboard' : '/login?error=auth_failed');
      }
    });
  }, []);

  useEffect(() => {
    if (user && token) {
      window.postMessage({ source: 'NETGUARD_WEB', type: 'NETGUARD_AUTH', token }, window.location.origin);
    }
  }, [user, token]);

  const login = () => {
    window.location.assign(apiUrl('/api/auth/google'));
  };

  const setToken = (nextToken, nextUser = null) => {
    persistToken(nextToken);
    if (nextUser) setUser(nextUser);
  };

  const logout = () => {
    window.postMessage({ source: 'NETGUARD_WEB', type: 'NETGUARD_LOGOUT' }, window.location.origin);
    persistToken(null);
    setUser(null);
    window.location.assign('/');
  };

  const refreshUser = async () => {
    const activeToken = localStorage.getItem('ng_token');
    if (activeToken) await loadUser(activeToken);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, refreshUser, token, setToken }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
}
