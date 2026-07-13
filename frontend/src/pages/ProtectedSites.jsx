import { useEffect, useState } from 'react';
import { Globe, Plus, Shield, X, Copy, CheckCircle } from 'lucide-react';
import api from '../services/api';
import toast from 'react-hot-toast';

export default function ProtectedSites() {
  const [sites, setSites] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newSiteUrl, setNewSiteUrl] = useState('');
  const [newSiteName, setNewSiteName] = useState('');
  const [adding, setAdding] = useState(false);

  useEffect(() => {
    loadSites();
  }, []);

  const loadSites = async () => {
    try {
      const res = await api.get('/api/dashboard/sites');
      if (res.data.success) {
        setSites(res.data.data);
      }
    } catch (err) {
      console.error('Error loading sites:', err);
    } finally {
      setLoading(false);
    }
  };

  const addSite = async (e) => {
    e.preventDefault();
    if (!newSiteUrl) return;
    setAdding(true);
    try {
      const res = await api.post('/api/dashboard/sites', {
        siteUrl: newSiteUrl,
        siteName: newSiteName,
      });
      if (res.data.success) {
        setSites([res.data.data, ...sites]);
        setNewSiteUrl('');
        setNewSiteName('');
        setShowAddModal(false);
        toast.success('Site protected successfully!');
      }
    } catch (err) {
      toast.error('Failed to protect site');
    } finally {
      setAdding(false);
    }
  };

  const copyCode = (code) => {
    navigator.clipboard.writeText(code);
    toast.success('Code copied!');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Protected Sites</h1>
          <p className="text-gray-500 text-sm mt-1">Manage websites protected by NetGuard</p>
        </div>
        <button onClick={() => setShowAddModal(true)} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />
          Add Site
        </button>
      </div>

      {/* Sites Grid */}
      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-primary"></div>
        </div>
      ) : sites.length === 0 ? (
        <div className="card text-center py-16">
          <Globe className="w-16 h-16 mx-auto mb-4 text-gray-700" />
          <h3 className="text-lg font-semibold text-gray-300 mb-2">No protected sites yet</h3>
          <p className="text-gray-500 text-sm mb-6">
            Add your websites to protect them with NetGuard's security engine.
          </p>
          <button onClick={() => setShowAddModal(true)} className="btn-primary">
            Protect Your First Site
          </button>
        </div>
      ) : (
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {sites.map((site) => (
            <div key={site._id} className="card group hover:border-primary/30 transition-all">
              <div className="flex items-start justify-between mb-4">
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Globe className="w-5 h-5 text-primary" />
                </div>
                <span className={`badge ${site.isActive ? 'badge-safe' : 'badge-danger'}`}>
                  {site.isActive ? 'Active' : 'Inactive'}
                </span>
              </div>

              <h3 className="font-semibold text-gray-200 mb-1 truncate">
                {site.siteName || site.siteUrl}
              </h3>
              <p className="text-xs text-gray-500 truncate mb-4">{site.siteUrl}</p>

              {/* Protection Code */}
              <div className="bg-surface rounded-lg p-3 mb-4">
                <div className="text-xs text-gray-500 mb-1">Protection Code</div>
                <div className="flex items-center gap-2">
                  <code className="text-xs text-primary font-mono flex-1 truncate">
                    {site.protectionCode}
                  </code>
                  <button
                    onClick={() => copyCode(site.protectionCode)}
                    className="text-gray-500 hover:text-primary transition-colors"
                  >
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-2 gap-3">
                <div className="text-center p-2 bg-surface rounded-lg">
                  <div className="text-lg font-bold text-gray-200">{site.threatsDetected}</div>
                  <div className="text-xs text-gray-500">Threats</div>
                </div>
                <div className="text-center p-2 bg-surface rounded-lg">
                  <div className="text-lg font-bold text-safe">{site.securityScore}</div>
                  <div className="text-xs text-gray-500">Security</div>
                </div>
              </div>

              <div className="mt-3 pt-3 border-t border-border flex items-center justify-between text-xs text-gray-600">
                <span>{site.hasSSL ? ' SSL Enabled' : '⚠️ No SSL'}</span>
                <span>{new Date(site.createdAt).toLocaleDateString()}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add Site Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-6">
          <div className="card w-full max-w-md">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-bold text-gray-100">Protect a Website</h2>
              <button onClick={() => setShowAddModal(false)} className="text-gray-500 hover:text-gray-300">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={addSite} className="space-y-4">
              <div>
                <label className="text-sm text-gray-400 mb-1 block">Website URL *</label>
                <input
                  type="url"
                  value={newSiteUrl}
                  onChange={(e) => setNewSiteUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="input-field w-full"
                  required
                />
              </div>
              <div>
                <label className="text-sm text-gray-400 mb-1 block">Site Name (optional)</label>
                <input
                  type="text"
                  value={newSiteName}
                  onChange={(e) => setNewSiteName(e.target.value)}
                  placeholder="My Website"
                  className="input-field w-full"
                />
              </div>

              <div className="bg-surface rounded-lg p-4 text-sm text-gray-400">
                <Shield className="w-4 h-4 text-primary inline mr-2" />
                A unique protection code will be generated for your site. Add this code to your website to enable NetGuard protection.
              </div>

              <div className="flex gap-3 pt-2">
                <button type="button" onClick={() => setShowAddModal(false)} className="btn-ghost flex-1">
                  Cancel
                </button>
                <button type="submit" disabled={adding} className="btn-primary flex-1">
                  {adding ? 'Adding...' : 'Protect Site'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
