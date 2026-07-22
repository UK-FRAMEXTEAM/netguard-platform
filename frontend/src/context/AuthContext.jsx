import { createContext, useContext, useEffect, useState } from 'react';
import api, { apiUrl } from '../services/api';

const AuthContext = createContext(null);

function storedToken() {
  return localStorage.getItem('ng_token') || sessionStorage.getItem('ng_token');
}

function storedUser() {
  const value = localStorage.getItem('ng_user') || sessionStorage.getItem('ng_user');
  if (!value) return null;
  try { return JSON.parse(value); }
  catch { return null; }
}

function clearStoredAuth() {
  localStorage.removeItem('ng_token');
  sessionStorage.removeItem('ng_token');
  localStorage.removeItem('ng_user');
  sessionStorage.removeItem('ng_user');
}

function tokenFromCallback() {
  const hash = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  const query = new URLSearchParams(window.location.search);
  return hash.get('token') || query.get('token');
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(storedUser);
  const [loading, setLoading] = useState(true);
  const [token, setTokenState] = useState(storedToken);

  const persistToken = (nextToken, remember = true) => {
    localStorage.removeItem('ng_token');
    sessionStorage.removeItem('ng_token');
    if (nextToken) {
      const storage = remember ? localStorage : sessionStorage;
      storage.setItem('ng_token', nextToken);
      api.defaults.headers.common.Authorization = `Bearer ${nextToken}`;
    } else {
      delete api.defaults.headers.common.Authorization;
    }
    setTokenState(nextToken || null);
  };

  const persistUser = (nextUser, remember = true) => {
    localStorage.removeItem('ng_user');
    sessionStorage.removeItem('ng_user');
    if (nextUser) {
      const storage = remember ? localStorage : sessionStorage;
      storage.setItem('ng_user', JSON.stringify(nextUser));
    }
  };

  const loadUser = async (activeToken) => {
    try {
      api.defaults.headers.common.Authorization = `Bearer ${activeToken}`;
      const response = await api.get('/api/auth/me');
      if (!response.data.success) throw new Error('Authentication failed');
      setUser(response.data.user);
      persistUser(response.data.user, localStorage.getItem('ng_token') === activeToken);
      return response.data.user;
    } catch (error) {
      if (error.response?.status === 401) {
        clearStoredAuth();
        delete api.defaults.headers.common.Authorization;
        setTokenState(null);
        setUser(null);
        return null;
      }
      // A temporary 429/network failure must not destroy a valid session.
      const cachedUser = storedUser();
      setUser(cachedUser);
      return cachedUser;
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const callbackToken = tokenFromCallback();
    const activeToken = callbackToken || storedToken();

    if (!activeToken) {
      setLoading(false);
      return;
    }

    const remember = Boolean(callbackToken || localStorage.getItem('ng_token') === activeToken);
    persistToken(activeToken, remember);
    loadUser(activeToken).then((loadedUser) => {
      if (callbackToken) {
        // React Router does not observe a bare history.replaceState call here.
        // Reload the target route so the callback screen cannot remain mounted
        // after the address bar has already changed to /dashboard.
        window.location.replace(loadedUser ? '/dashboard' : '/login?error=auth_failed');
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

  const setToken = (nextToken, nextUser = null, remember = true) => {
    persistToken(nextToken, remember);
    if (nextUser) {
      persistUser(nextUser, remember);
      setUser(nextUser);
    }
  };

  const logout = () => {
    window.postMessage({ source: 'NETGUARD_WEB', type: 'NETGUARD_LOGOUT' }, window.location.origin);
    clearStoredAuth();
    delete api.defaults.headers.common.Authorization;
    setTokenState(null);
    setUser(null);
    window.location.assign('/');
  };

  const refreshUser = async () => {
    const activeToken = storedToken();
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
