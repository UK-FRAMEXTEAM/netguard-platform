import { useEffect, useState } from 'react';
import {
  Users, Shield, AlertTriangle, Globe, TrendingUp,
  Eye, ChevronLeft, ChevronRight, Search
} from 'lucide-react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import api from '../services/api';

const SEVERITY_COLORS = {
  critical: '#ff3b5c',
  high: '#ff6432',
  medium: '#ffa726',
  low: '#00e676',
};

export default function AdminPanel() {
  const [stats, setStats] = useState(null);
  const [users, setUsers] = useState([]);
  const [trendData, setTrendData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [userPagination, setUserPagination] = useState({});
  const [currentPage, setCurrentPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedUser, setSelectedUser] = useState(null);

  useEffect(() => {
    loadAdminData();
  }, [currentPage]);

  const loadAdminData = async () => {
    try {
      const [statsRes, usersRes, trendRes] = await Promise.all([
        api.get('/api/admin/stats'),
        api.get('/api/admin/users', { params: { page: currentPage, limit: 10 } }),
        api.get('/api/admin/threat-trend'),
      ]);

      if (statsRes.data.success) setStats(statsRes.data.data);
      if (usersRes.data.success) {
        setUsers(usersRes.data.data.users);
        setUserPagination(usersRes.data.data.pagination);
      }
      if (trendRes.data.success) setTrendData(trendRes.data.data);
    } catch (err) {
      console.error('Admin data load error:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadUserDetails = async (userId) => {
    try {
      const res = await api.get(`/api/admin/users/${userId}`);
      if (res.data.success) {
        setSelectedUser(res.data.data);
      }
    } catch (err) {
      console.error('Error loading user details:', err);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Admin Panel</h1>
        <p className="text-gray-500 text-sm mt-1">Monitor all users and platform-wide security metrics</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        {[
          { id: 'overview', label: 'Overview', icon: TrendingUp },
          { id: 'users', label: 'Users', icon: Users },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
              activeTab === tab.id
                ? 'bg-primary/10 text-primary'
                : 'bg-surface text-gray-400 hover:text-gray-200 border border-border'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && stats && (
        <>
          {/* Platform Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="stat-card border-l-4 border-l-primary">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Total Users</span>
                <Users className="w-5 h-5 text-primary" />
              </div>
              <div className="text-3xl font-bold text-gray-100">{stats.totalUsers}</div>
              <div className="text-xs text-gray-500">{stats.activeUsers} active this week</div>
            </div>
            <div className="stat-card border-l-4 border-l-danger">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Total Threats</span>
                <AlertTriangle className="w-5 h-5 text-danger" />
              </div>
              <div className="text-3xl font-bold text-gray-100">{stats.totalThreats?.toLocaleString()}</div>
              <div className="text-xs text-gray-500">All-time threats detected</div>
            </div>
            <div className="stat-card border-l-4 border-l-safe">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Protected Sites</span>
                <Globe className="w-5 h-5 text-safe" />
              </div>
              <div className="text-3xl font-bold text-gray-100">{stats.totalSites}</div>
              <div className="text-xs text-gray-500">Sites under protection</div>
            </div>
            <div className="stat-card border-l-4 border-l-warning">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Threat Categories</span>
                <Eye className="w-5 h-5 text-warning" />
              </div>
              <div className="text-3xl font-bold text-gray-100">{stats.categoryBreakdown?.length || 0}</div>
              <div className="text-xs text-gray-500">Unique threat types</div>
            </div>
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Threat Trend */}
            <div className="card">
              <h3 className="text-sm font-semibold text-gray-300 mb-4">Platform Threat Trend (30 days)</h3>
              {trendData.length > 0 ? (
                <ResponsiveContainer width="100%" height={250}>
                  <LineChart data={trendData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a2d3e" />
                    <XAxis dataKey="_id" stroke="#5a7a99" fontSize={10} tickFormatter={(v) => v?.slice(5)} />
                    <YAxis stroke="#5a7a99" fontSize={11} />
                    <Tooltip contentStyle={{ background: '#1e2130', border: '1px solid #2a2d3e', borderRadius: 8 }} />
                    <Legend wrapperStyle={{ fontSize: 12 }} />
                    <Line type="monotone" dataKey="count" stroke="#ff3b5c" name="Total" strokeWidth={2} />
                    <Line type="monotone" dataKey="blocked" stroke="#00e676" name="Blocked" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-64 flex items-center justify-center text-gray-600">No data</div>
              )}
            </div>

            {/* Severity Breakdown */}
            <div className="card">
              <h3 className="text-sm font-semibold text-gray-300 mb-4">Severity Distribution</h3>
              {stats.severityBreakdown?.length > 0 ? (
                <ResponsiveContainer width="100%" height={250}>
                  <PieChart>
                    <Pie
                      data={stats.severityBreakdown}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={80}
                      dataKey="count"
                      nameKey="_id"
                      label={({ _id, count }) => `${_id}: ${count}`}
                    >
                      {stats.severityBreakdown.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry._id] || '#4f8ef7'} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#1e2130', border: '1px solid #2a2d3e', borderRadius: 8 }} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-64 flex items-center justify-center text-gray-600">No data</div>
              )}
            </div>
          </div>

          {/* Top Threat Categories */}
          <div className="card">
            <h3 className="text-sm font-semibold text-gray-300 mb-4">Top Threat Categories</h3>
            {stats.categoryBreakdown?.length > 0 ? (
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
                {stats.categoryBreakdown.map((cat) => (
                  <div key={cat._id} className="bg-surface rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-gray-100">{cat.count}</div>
                    <div className="text-xs text-gray-500 mt-1">{cat._id}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center text-gray-600 py-8">No category data</div>
            )}
          </div>
        </>
      )}

      {activeTab === 'users' && (
        <>
          {/* Search */}
          <div className="card">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                type="text"
                placeholder="Search users by name or email..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="input-field pl-10 w-full"
              />
            </div>
          </div>

          {/* Users Table */}
          <div className="card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider py-3 px-4">User</th>
                    <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider py-3 px-4">Role</th>
                    <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider py-3 px-4">Threats</th>
                    <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider py-3 px-4">Trackers</th>
                    <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider py-3 px-4">Sites</th>
                    <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider py-3 px-4">Last Login</th>
                    <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider py-3 px-4">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users
                    .filter(u =>
                      u.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                      u.email?.toLowerCase().includes(searchQuery.toLowerCase())
                    )
                    .map(user => (
                      <tr key={user._id} className="border-b border-border/50 hover:bg-white/2 transition-colors">
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-3">
                            {user.avatar ? (
                              <img src={user.avatar} alt="" className="w-8 h-8 rounded-full" />
                            ) : (
                              <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-sm text-primary font-medium">
                                {user.name?.charAt(0)}
                              </div>
                            )}
                            <div>
                              <div className="text-sm font-medium text-gray-200">{user.name}</div>
                              <div className="text-xs text-gray-500">{user.email}</div>
                            </div>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <span className={`badge ${user.role === 'admin' ? 'badge-warning' : 'badge-info'}`}>
                            {user.role}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-sm text-gray-300">{user.stats?.threatsBlocked || 0}</td>
                        <td className="py-3 px-4 text-sm text-gray-300">{user.stats?.trackersDetected || 0}</td>
                        <td className="py-3 px-4 text-sm text-gray-300">{user.protectedSites?.length || 0}</td>
                        <td className="py-3 px-4 text-sm text-gray-500">
                          {new Date(user.lastLogin).toLocaleDateString()}
                        </td>
                        <td className="py-3 px-4">
                          <button
                            onClick={() => loadUserDetails(user._id)}
                            className="text-xs text-primary hover:text-blue-400 font-medium"
                          >
                            View Details
                          </button>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Pagination */}
          {userPagination.pages > 1 && (
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-500">
                Page {currentPage} of {userPagination.pages}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  className="p-2 rounded-lg bg-surface border border-border disabled:opacity-30"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setCurrentPage(p => Math.min(userPagination.pages, p + 1))}
                  disabled={currentPage === userPagination.pages}
                  className="p-2 rounded-lg bg-surface border border-border disabled:opacity-30"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* User Detail Modal */}
      {selectedUser && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-6">
          <div className="card w-full max-w-2xl max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-bold text-gray-100">User Details</h2>
              <button onClick={() => setSelectedUser(null)} className="text-gray-500 hover:text-gray-300 text-xl">×</button>
            </div>

            <div className="space-y-4">
              <div className="flex items-center gap-4">
                {selectedUser.avatar && <img src={selectedUser.avatar} className="w-14 h-14 rounded-full" />}
                <div>
                  <h3 className="text-lg font-semibold text-gray-100">{selectedUser.name}</h3>
                  <p className="text-sm text-gray-500">{selectedUser.email}</p>
                  <span className={`badge mt-1 ${selectedUser.role === 'admin' ? 'badge-warning' : 'badge-info'}`}>
                    {selectedUser.role}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="bg-surface rounded-lg p-4">
                  <div className="text-xs text-gray-500">Threats Blocked</div>
                  <div className="text-xl font-bold text-danger">{selectedUser.stats?.threatsBlocked || 0}</div>
                </div>
                <div className="bg-surface rounded-lg p-4">
                  <div className="text-xs text-gray-500">Trackers Detected</div>
                  <div className="text-xl font-bold text-warning">{selectedUser.stats?.trackersDetected || 0}</div>
                </div>
              </div>

              {selectedUser.threats?.length > 0 && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-300 mb-3">Recent Threats</h4>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {selectedUser.threats.slice(0, 10).map((t, i) => (
                      <div key={i} className="flex items-center gap-3 p-2 bg-surface rounded text-sm">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[t.severity] }}></span>
                        <span className="text-gray-300 flex-1 truncate">{t.detail}</span>
                        <span className="text-xs text-gray-600">{t.category}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
