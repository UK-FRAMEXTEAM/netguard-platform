import { useEffect, useState } from 'react';
import { Shield, AlertTriangle, Eye, Globe, TrendingUp, Copy, CheckCircle, Download, RefreshCw } from 'lucide-react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import api from '../services/api';
import toast from 'react-hot-toast';

const COLORS = ['#ff3b5c', '#ffa726', '#4f8ef7', '#a78bfa', '#00e676'];

const CATEGORY_LABELS = {
  'phishing': 'Phishing',
  'malware': 'Malware',
  'tracker': 'Trackers',
  'crypto-miner': 'Crypto Miner',
  'xss-attempt': 'XSS Attempt',
  'zero-trust-http': 'Zero Trust',
  'session-exposed': 'Session Leak',
  'hidden-iframe': 'Hidden Iframe',
  'malvertising': 'Malvertising',
  'credential-risk': 'Credential Risk',
  'dns-leak': 'Secure DNS Bypass',
};

const SEVERITY_COLORS = {
  critical: '#ff3b5c',
  high: '#ff6432',
  medium: '#ffa726',
  low: '#00e676',
};

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [release, setRelease] = useState(null);

  useEffect(() => {
    loadDashboard();
    fetch('/release.json', { cache: 'no-store' })
      .then((response) => response.ok ? response.json() : null)
      .then(setRelease)
      .catch(() => setRelease(null));
  }, []);

  const loadDashboard = async () => {
    try {
      const res = await api.get('/api/dashboard/overview');
      if (res.data.success) {
        setData(res.data.data);
      }
    } catch (err) {
      console.error('Dashboard load error:', err);
    } finally {
      setLoading(false);
    }
  };

  const copyProtectionCode = () => {
    if (data?.protectionCode) {
      navigator.clipboard.writeText(data.protectionCode);
      setCopied(true);
      toast.success('Protection code copied!');
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-primary"></div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="text-center text-gray-500 py-12">
        <AlertTriangle className="w-12 h-12 mx-auto mb-4 text-warning" />
        <p>Failed to load dashboard. Please try again.</p>
        <button onClick={loadDashboard} className="btn-primary mt-4">Retry</button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Security Dashboard</h1>
          <p className="text-gray-500 text-sm mt-1">Overview of your security posture and threat activity</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs bg-safe/20 text-safe px-3 py-1.5 rounded-full font-medium flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-safe animate-pulse"></span>
            Protection Active
          </span>
        </div>
      </div>

      {release?.latestVersion && (
        <div className="card border-warning/20 bg-warning/5 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <RefreshCw className="w-5 h-5 text-warning mt-0.5" />
            <div>
              <div className="text-sm font-semibold text-gray-200">Latest extension release: v{release.latestVersion}</div>
              <div className="text-xs text-gray-500 mt-1">The public release feed is available even when users are signed out.</div>
            </div>
          </div>
          <a href={release.downloadUrl} className="btn-ghost inline-flex items-center justify-center gap-2 text-sm" download>
            <Download className="w-4 h-4" /> Download latest
          </a>
        </div>
      )}

      {/* Protection Code Card */}
      {data.protectionCode && (
        <div className="card bg-gradient-to-r from-primary/5 to-secondary/5 border-primary/20">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-gray-400 mb-1">Your Protection Code</div>
              <div className="text-2xl font-mono font-bold text-primary tracking-wider">{data.protectionCode}</div>
              <div className="text-xs text-gray-500 mt-1">Use this code to protect your websites</div>
            </div>
            <button
              onClick={copyProtectionCode}
              className="flex items-center gap-2 bg-primary/10 hover:bg-primary/20 text-primary px-4 py-2.5 rounded-lg transition-all"
            >
              {copied ? <CheckCircle className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="stat-card border-l-4 border-l-danger">
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-500">Total Threats</span>
            <AlertTriangle className="w-5 h-5 text-danger" />
          </div>
          <div className="text-3xl font-bold text-gray-100">{data.totalThreats?.toLocaleString()}</div>
          <div className="text-xs text-gray-500">{data.threats24h || 0} in last 24h</div>
        </div>
        <div className="stat-card border-l-4 border-l-warning">
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-500">Trackers Detected</span>
            <Eye className="w-5 h-5 text-warning" />
          </div>
          <div className="text-3xl font-bold text-gray-100">{data.userStats?.trackersDetected?.toLocaleString()}</div>
          <div className="text-xs text-gray-500">{data.threats7d || 0} this week</div>
        </div>
        <div className="stat-card border-l-4 border-l-safe">
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-500">Safe Scans</span>
            <CheckCircle className="w-5 h-5 text-safe" />
          </div>
          <div className="text-3xl font-bold text-gray-100">{data.userStats?.safeScans?.toLocaleString()}</div>
          <div className="text-xs text-gray-500">URLs verified clean</div>
        </div>
        <div className="stat-card border-l-4 border-l-primary">
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-500">Protected Sites</span>
            <Globe className="w-5 h-5 text-primary" />
          </div>
          <div className="text-3xl font-bold text-gray-100">{data.protectedSites?.length || 0}</div>
          <div className="text-xs text-gray-500">Active protection</div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Trend Chart */}
        <div className="card lg:col-span-2">
          <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-primary" />
            Threat Activity – Last 7 Days
          </h3>
          {data.trendData?.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={data.trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2d3e" />
                <XAxis dataKey="_id" stroke="#5a7a99" fontSize={11} tickFormatter={(v) => v?.slice(5)} />
                <YAxis stroke="#5a7a99" fontSize={11} />
                <Tooltip
                  contentStyle={{ background: '#1e2130', border: '1px solid #2a2d3e', borderRadius: 8 }}
                  labelStyle={{ color: '#e2e8f0' }}
                />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Line type="monotone" dataKey="count" stroke="#ff3b5c" name="Total Threats" strokeWidth={2} dot={{ fill: '#ff3b5c' }} />
                <Line type="monotone" dataKey="blocked" stroke="#00e676" name="Blocked" strokeWidth={2} dot={{ fill: '#00e676' }} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-600 text-sm">
              No threat data available for the last 7 days.
            </div>
          )}
        </div>

        {/* Severity Pie Chart */}
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4 text-secondary" />
            Threat Severity
          </h3>
          {data.threatsBySeverity?.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={data.threatsBySeverity}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  dataKey="count"
                  nameKey="_id"
                  label={({ _id, count }) => `${_id}: ${count}`}
                  labelLine={false}
                >
                  {data.threatsBySeverity.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry._id] || '#4f8ef7'} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#1e2130', border: '1px solid #2a2d3e', borderRadius: 8 }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-600 text-sm">
              No severity data available.
            </div>
          )}
        </div>
      </div>

      {/* Category Breakdown + Recent Threats */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Category Bar Chart */}
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">Threat Categories</h3>
          {data.threatsByCategory?.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={data.threatsByCategory.slice(0, 6)} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2d3e" horizontal={false} />
                <XAxis type="number" stroke="#5a7a99" fontSize={11} />
                <YAxis
                  type="category"
                  dataKey="_id"
                  stroke="#5a7a99"
                  fontSize={10}
                  width={90}
                  tickFormatter={(v) => CATEGORY_LABELS[v] || v}
                />
                <Tooltip
                  contentStyle={{ background: '#1e2130', border: '1px solid #2a2d3e', borderRadius: 8 }}
                />
                <Bar dataKey="count" fill="#4f8ef7" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-600 text-sm">
              No category data available.
            </div>
          )}
        </div>

        {/* Recent Threats */}
        <div className="card lg:col-span-2">
          <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-danger" />
            Recent Threats
          </h3>
          {data.recentThreats?.length > 0 ? (
            <div className="space-y-2">
              {data.recentThreats.slice(0, 8).map((threat, i) => (
                <div key={i} className="flex items-center gap-3 p-3 rounded-lg bg-surface hover:bg-surface/80 transition-colors">
                  <span
                    className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                    style={{ backgroundColor: SEVERITY_COLORS[threat.severity] }}
                  ></span>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-gray-200 truncate">
                      {CATEGORY_LABELS[threat.category] || threat.category}
                    </div>
                    <div className="text-xs text-gray-500 truncate">{threat.detail}</div>
                  </div>
                  <span className="badge badge-danger flex-shrink-0">
                    {threat.severity?.toUpperCase()}
                  </span>
                  <span className="text-xs text-gray-600 flex-shrink-0 font-mono">
                    {new Date(threat.createdAt).toLocaleDateString()}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-600 text-sm">
              No recent threats. Your browsing is safe! 🛡️
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
