import { useEffect, useState } from 'react';
import { AlertTriangle, Filter, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import api from '../services/api';

const SEVERITY_COLORS = {
  critical: 'badge-danger',
  high: 'badge-warning',
  medium: 'badge-warning',
  low: 'badge-safe',
};

const CATEGORY_LABELS = {
  'phishing': 'Phishing',
  'malware': 'Malware',
  'tracker': 'Tracker',
  'crypto-miner': 'Crypto Miner',
  'xss-attempt': 'XSS Attempt',
  'zero-trust-http': 'Zero Trust HTTP',
  'session-exposed': 'Session Token Exposed',
  'hidden-iframe': 'Hidden Iframe',
  'malvertising': 'Malvertising',
  'credential-risk': 'Credential Risk',
  'suspicious-redirect': 'Suspicious Redirect',
  'phishing-pattern': 'Phishing Pattern',
  'high-risk-tld': 'High Risk TLD',
  'dns-leak': 'DNS Leak',
  'brand-spoofing': 'Brand Spoofing',
  'insecure-form': 'Insecure Form',
  'dynamic-miner-injection': 'Dynamic Miner',
  'suspicious-keyword': 'Suspicious Keyword',
};

const ACTIONS = {
  blocked: ' Blocked',
  warned: '⚠️ Warned',
  logged: '📝 Logged',
  monitored: '👁️ Monitored',
};

export default function Threats() {
  const [threats, setThreats] = useState([]);
  const [pagination, setPagination] = useState({});
  const [loading, setLoading] = useState(true);
  const [filterCategory, setFilterCategory] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    loadThreats();
  }, [currentPage, filterCategory, filterSeverity]);

  const loadThreats = async () => {
    setLoading(true);
    try {
      const params = { page: currentPage, limit: 15 };
      if (filterCategory) params.category = filterCategory;
      if (filterSeverity) params.severity = filterSeverity;

      const res = await api.get('/api/dashboard/threats', { params });
      if (res.data.success) {
        setThreats(res.data.data.threats);
        setPagination(res.data.data.pagination);
      }
    } catch (err) {
      console.error('Error loading threats:', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredThreats = threats.filter(t =>
    t.detail?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    t.url?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    t.domain?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Threat Log</h1>
        <p className="text-gray-500 text-sm mt-1">Detailed log of all detected security threats</p>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-wrap items-center gap-4">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search threats..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input-field pl-10 w-full"
            />
          </div>
          <select
            value={filterCategory}
            onChange={(e) => { setFilterCategory(e.target.value); setCurrentPage(1); }}
            className="input-field"
          >
            <option value="">All Categories</option>
            {Object.entries(CATEGORY_LABELS).map(([key, label]) => (
              <option key={key} value={key}>{label}</option>
            ))}
          </select>
          <select
            value={filterSeverity}
            onChange={(e) => { setFilterSeverity(e.target.value); setCurrentPage(1); }}
            className="input-field"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Threats List */}
      <div className="space-y-3">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-primary"></div>
          </div>
        ) : filteredThreats.length === 0 ? (
          <div className="card text-center py-12">
            <AlertTriangle className="w-12 h-12 mx-auto mb-4 text-safe" />
            <h3 className="text-lg font-semibold text-gray-200">No threats found</h3>
            <p className="text-gray-500 text-sm mt-1">
              {searchQuery || filterCategory || filterSeverity
                ? 'Try adjusting your filters'
                : 'Your browsing has been clean!'}
            </p>
          </div>
        ) : (
          filteredThreats.map((threat) => (
            <div
              key={threat._id}
              className="card hover:border-primary/20 transition-all group"
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-3 flex-1">
                  <span
                    className="w-3 h-3 rounded-full mt-1 flex-shrink-0"
                    style={{ backgroundColor:
                      threat.severity === 'critical' ? '#ff3b5c' :
                      threat.severity === 'high' ? '#ff6432' :
                      threat.severity === 'medium' ? '#ffa726' : '#00e676'
                    }}
                  ></span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-semibold text-gray-200 text-sm">
                        {CATEGORY_LABELS[threat.category] || threat.category}
                      </span>
                      <span className={`badge ${SEVERITY_COLORS[threat.severity]}`}>
                        {threat.severity?.toUpperCase()}
                      </span>
                      <span className="text-xs text-gray-600">
                        {threat.detectionLayer}
                      </span>
                    </div>
                    <p className="text-sm text-gray-400 mb-1">{threat.detail}</p>
                    <div className="flex items-center gap-4 text-xs text-gray-600">
                      <span className="truncate max-w-[300px]">🔗 {threat.url}</span>
                      {threat.domain && <span>🌐 {threat.domain}</span>}
                      <span>🕐 {new Date(threat.createdAt).toLocaleString()}</span>
                    </div>
                  </div>
                </div>
                <div className="text-right ml-4">
                  <span className="text-xs text-gray-500">
                    {ACTIONS[threat.action] || threat.action}
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Pagination */}
      {pagination.pages > 1 && (
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-500">
            Showing {(currentPage - 1) * pagination.limit + 1}–{Math.min(currentPage * pagination.limit, pagination.total)} of {pagination.total}
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-2 rounded-lg bg-surface border border-border disabled:opacity-30 hover:bg-white/5 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            {Array.from({ length: Math.min(5, pagination.pages) }, (_, i) => {
              const page = currentPage <= 3 ? i + 1 : pagination.pages - 4 + i;
              if (page < 1 || page > pagination.pages) return null;
              return (
                <button
                  key={page}
                  onClick={() => setCurrentPage(page)}
                  className={`w-9 h-9 rounded-lg text-sm font-medium transition-all ${
                    page === currentPage
                      ? 'bg-primary text-white'
                      : 'bg-surface border border-border text-gray-400 hover:bg-white/5'
                  }`}
                >
                  {page}
                </button>
              );
            })}
            <button
              onClick={() => setCurrentPage(p => Math.min(pagination.pages, p + 1))}
              disabled={currentPage === pagination.pages}
              className="p-2 rounded-lg bg-surface border border-border disabled:opacity-30 hover:bg-white/5 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
