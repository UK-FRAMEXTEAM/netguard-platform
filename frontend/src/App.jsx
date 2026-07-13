import { lazy, Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './context/AuthContext';
import Landing from './pages/Landing';
import Login from './pages/Login';
import Install from './pages/Install';
import Layout from './components/Layout';

const Dashboard = lazy(() => import('./pages/Dashboard'));
const Threats = lazy(() => import('./pages/Threats'));
const Analytics = lazy(() => import('./pages/Analytics'));
const ProtectedSites = lazy(() => import('./pages/ProtectedSites'));
const Settings = lazy(() => import('./pages/Settings'));
const AdminPanel = lazy(() => import('./pages/AdminPanel'));

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen bg-dark flex items-center justify-center">
        <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-primary"></div>
      </div>
    );
  }
  if (!user) return <Navigate to="/login" />;
  return children;
}

function AdminRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user || user.role !== 'admin') return <Navigate to="/dashboard" />;
  return children;
}

export default function App() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-dark flex items-center justify-center">
        <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-primary"></div>
      </div>
    }>
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      <Route path="/install" element={<Install />} />
      <Route path="/auth/callback" element={
        <div className="min-h-screen bg-dark flex items-center justify-center text-gray-400">
          Completing secure sign-in...
        </div>
      } />

      <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="threats" element={<Threats />} />
        <Route path="analytics" element={<Analytics />} />
        <Route path="sites" element={<ProtectedSites />} />
        <Route path="settings" element={<Settings />} />
        <Route path="admin" element={<AdminRoute><AdminPanel /></AdminRoute>} />
      </Route>
    </Routes>
    </Suspense>
  );
}
