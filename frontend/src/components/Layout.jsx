import { Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import Sidebar from './Sidebar';
import { useState } from 'react';
import { Menu, Shield } from 'lucide-react';
import SecurityAssistant from './SecurityAssistant';

export default function Layout() {
  const { user } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <div className="flex min-h-screen bg-dark">
      <Sidebar mobileOpen={menuOpen} onClose={() => setMenuOpen(false)} />
      <div className="flex-1 flex flex-col ml-0 md:ml-64 min-w-0">
        {/* Top Bar */}
        <header className="h-16 bg-card border-b border-border flex items-center justify-between px-4 md:px-6 sticky top-0 z-30">
          <div className="flex items-center gap-3">
            <button onClick={() => setMenuOpen(true)} className="md:hidden p-2 -ml-2 rounded-lg hover:bg-white/5" aria-label="Open navigation">
              <Menu className="w-5 h-5 text-gray-300" />
            </button>
            <Shield className="w-5 h-5 text-primary" />
            <span className="font-semibold text-gray-200">NetGuard Cloud</span>
            <span className="text-xs bg-primary/20 text-primary px-2 py-0.5 rounded-full font-mono">v3.5</span>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="text-sm font-medium text-gray-200">{user?.name}</div>
              <div className="text-xs text-gray-500">{user?.role === 'admin' ? 'Admin' : 'User'}</div>
            </div>
            {user?.avatar && (
              <img src={user.avatar} alt="avatar" className="w-9 h-9 rounded-full border-2 border-border" />
            )}
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 p-4 md:p-6 overflow-auto min-w-0">
          <Outlet />
        </main>
      </div>
      <SecurityAssistant />
    </div>
  );
}
