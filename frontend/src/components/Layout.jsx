import { Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import Sidebar from './Sidebar';
import { Shield } from 'lucide-react';
import SecurityAssistant from './SecurityAssistant';

export default function Layout() {
  const { user } = useAuth();

  return (
    <div className="flex min-h-screen bg-dark">
      <Sidebar />
      <div className="flex-1 flex flex-col ml-64">
        {/* Top Bar */}
        <header className="h-16 bg-card border-b border-border flex items-center justify-between px-6 sticky top-0 z-30">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-primary" />
            <span className="font-semibold text-gray-200">NetGuard Cloud</span>
            <span className="text-xs bg-primary/20 text-primary px-2 py-0.5 rounded-full font-mono">v3.4</span>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="text-sm font-medium text-gray-200">{user?.name}</div>
              <div className="text-xs text-gray-500">{user?.role === 'admin' ? ' Admin' : 'User'}</div>
            </div>
            {user?.avatar && (
              <img src={user.avatar} alt="avatar" className="w-9 h-9 rounded-full border-2 border-border" />
            )}
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 p-6 overflow-auto">
          <Outlet />
        </main>
      </div>
      <SecurityAssistant />
    </div>
  );
}
