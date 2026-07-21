import { useEffect, useMemo, useState } from 'react';
import {
  Activity, Check, CheckCircle2, Clipboard, Code2, Copy, Gauge, Globe,
  Info, LockKeyhole, Plus, Power, RefreshCw, Settings2, Shield, ShieldCheck, X,
} from 'lucide-react';
import api, { API_BASE_URL } from '../services/api';
import toast from 'react-hot-toast';

const DEFAULT_SETTINGS = {
  telemetryEnabled: true,
  rateLimitEnabled: true,
  repeatProtectionEnabled: true,
  botDetectionEnabled: true,
  formShieldEnabled: true,
  recaptchaEnabled: true,
  clientErrorMonitoring: true,
  autoBlockEnabled: true,
  autoPostureScanEnabled: true,
  repeatWindowSeconds: 5,
  repeatMaxSubmissions: 2,
  burstWindowSeconds: 5,
  burstMaxRequests: 8,
  minuteMaxRequests: 60,
  blockMinutes: 15,
  autoScanIntervalHours: 24,
};

const PROFILE_SETTINGS = {
  balanced: DEFAULT_SETTINGS,
  strict: {
    ...DEFAULT_SETTINGS,
    burstMaxRequests: 5,
    minuteMaxRequests: 30,
    blockMinutes: 30,
    autoScanIntervalHours: 12,
  },
};

const TOGGLES = [
  ['telemetryEnabled', 'Network telemetry', 'Store privacy-safe events in MongoDB for real reports.'],
  ['rateLimitEnabled', 'Request rate detection', 'Detect bursts in the selected time window.'],
  ['repeatProtectionEnabled', 'Repeated message protection', 'Hash form content locally and detect identical submissions without storing the message.'],
  ['botDetectionEnabled', 'Bot signal detection', 'Challenge webdriver, headless, and automated request patterns.'],
  ['formShieldEnabled', 'Form shield', 'Pause suspicious form submissions before they reach the form action.'],
  ['recaptchaEnabled', 'reCAPTCHA challenge', 'Verify suspicious visitors when reCAPTCHA v3 keys are configured.'],
  ['clientErrorMonitoring', 'Client error monitoring', 'Record a one-way hash when the website reports a JavaScript error.'],
  ['autoBlockEnabled', 'Automatic temporary block', 'Block extreme repeat/rate patterns for the configured period.'],
  ['autoPostureScanEnabled', 'Automatic posture scans', 'Recheck TLS, certificate, and security headers automatically while the site is in use.'],
];

const RUNTIME_LAYER_KEYS = TOGGLES
  .map(([key]) => key)
  .filter((key) => key !== 'autoPostureScanEnabled');

function snippetFor(site) {
  const base = API_BASE_URL || window.location.origin;
  return `<script src="${base}/api/site/sdk.js" data-netguard-key="${site.protectionCode}" defer></script>`;
}

function connectionBadge(status) {
  if (status === 'connected') return 'badge-safe';
  if (status === 'offline') return 'badge-danger';
  return 'badge-warning';
}

export default function ProtectedSites() {
  const [sites, setSites] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [editing, setEditing] = useState(null);
  const [newSiteUrl, setNewSiteUrl] = useState('');
  const [newSiteName, setNewSiteName] = useState('');
  const [newSiteProfile, setNewSiteProfile] = useState('balanced');
  const [newSiteSettings, setNewSiteSettings] = useState({ ...DEFAULT_SETTINGS });
  const [adding, setAdding] = useState(false);
  const [saving, setSaving] = useState(false);
  const [scanning, setScanning] = useState(false);

  const loadSites = async (showToast = false) => {
    try {
      const response = await api.get('/api/dashboard/sites');
      setSites(response.data.data || []);
      if (showToast) toast.success('Website status refreshed');
    } catch (error) {
      toast.error(error.response?.data?.message || 'Could not load protected websites');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadSites(); }, []);

  const addSite = async (event) => {
    event.preventDefault();
    setAdding(true);
    try {
      const response = await api.post('/api/dashboard/sites', {
        siteUrl: newSiteUrl,
        siteName: newSiteName,
        protectionProfile: newSiteProfile,
        protectionSettings: newSiteSettings,
        isActive: true,
      });
      const site = response.data.data;
      setSites((current) => [site, ...current]);
      setNewSiteUrl('');
      setNewSiteName('');
      setNewSiteProfile('balanced');
      setNewSiteSettings({ ...DEFAULT_SETTINGS });
      setShowAddModal(false);
      setEditing({ ...site, protectionSettings: { ...DEFAULT_SETTINGS, ...site.protectionSettings } });
      const scanText = response.data.automation?.initialScanCompleted
        ? ' Initial security scan completed.'
        : response.data.automation?.initialScanFailed
          ? ' The site was registered, but the first scan needs a retry.'
          : '';
      toast.success(`Website registered.${scanText} Install the one-time script to activate live protection.`);
    } catch (error) {
      toast.error(error.response?.data?.message || 'Could not register website');
    } finally {
      setAdding(false);
    }
  };

  const copyText = async (value, message) => {
    await navigator.clipboard.writeText(value);
    toast.success(message);
  };

  const openSettings = (site) => {
    setEditing({ ...site, protectionSettings: { ...DEFAULT_SETTINGS, ...site.protectionSettings } });
  };

  const updateSetting = (key, value) => {
    setEditing((current) => ({
      ...current,
      protectionProfile: 'custom',
      protectionSettings: { ...current.protectionSettings, [key]: value },
    }));
  };

  const chooseNewProfile = (profile) => {
    setNewSiteProfile(profile);
    setNewSiteSettings({ ...PROFILE_SETTINGS[profile] });
  };

  const updateNewSetting = (key, value) => {
    setNewSiteProfile('custom');
    setNewSiteSettings((current) => ({ ...current, [key]: value }));
  };

  const chooseEditingProfile = (profile) => {
    setEditing((current) => ({
      ...current,
      protectionProfile: profile,
      protectionSettings: { ...PROFILE_SETTINGS[profile] },
    }));
  };

  const toggleSite = async (site) => {
    try {
      const response = await api.patch(`/api/dashboard/sites/${site._id}`, { isActive: !site.isActive });
      const updated = response.data.data;
      setSites((current) => current.map((item) => item._id === updated._id ? updated : item));
      if (editing?._id === updated._id) openSettings(updated);
      toast.success(updated.isActive ? 'Website protection enabled' : 'Website protection paused');
    } catch (error) {
      toast.error(error.response?.data?.message || 'Could not change website protection');
    }
  };

  const saveSettings = async () => {
    setSaving(true);
    try {
      const response = await api.patch(`/api/dashboard/sites/${editing._id}`, {
        isActive: editing.isActive,
        protectionProfile: editing.protectionProfile || 'custom',
        protectionSettings: editing.protectionSettings,
      });
      const updated = response.data.data;
      setSites((current) => current.map((site) => site._id === updated._id ? updated : site));
      setEditing({ ...updated, protectionSettings: { ...DEFAULT_SETTINGS, ...updated.protectionSettings } });
      toast.success('Website protection settings saved');
    } catch (error) {
      toast.error(error.response?.data?.message || 'Could not save protection settings');
    } finally {
      setSaving(false);
    }
  };

  const runNetworkScan = async () => {
    setScanning(true);
    try {
      const response = await api.post(`/api/dashboard/sites/${editing._id}/network-scan`);
      const updated = response.data.data;
      setSites((current) => current.map((site) => site._id === updated._id ? updated : site));
      setEditing({ ...updated, protectionSettings: { ...DEFAULT_SETTINGS, ...updated.protectionSettings } });
      toast.success('Real TLS and security-header scan completed');
    } catch (error) {
      toast.error(error.response?.data?.message || 'Network posture scan failed');
    } finally {
      setScanning(false);
    }
  };

  const connectedCount = useMemo(() => sites.filter((site) => site.integrationStatus === 'connected').length, [sites]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Protected Sites</h1>
          <p className="text-gray-500 text-sm mt-1">Add your own website, choose its protection layers, and let NetGuard monitor it automatically after one verified connection.</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => loadSites(true)} className="btn-ghost flex items-center gap-2"><RefreshCw className="w-4 h-4" /> Refresh</button>
          <button onClick={() => setShowAddModal(true)} className="btn-primary flex items-center gap-2"><Plus className="w-4 h-4" /> Add Site</button>
        </div>
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        {[
          [Code2, '1. Add & configure', 'Enter the user-owned HTTPS site and turn each protection layer ON or OFF.'],
          [Activity, '2. Automatic scan', 'NetGuard immediately checks TLS, the certificate, and public security headers.'],
          [ShieldCheck, '3. Connect once', 'Install one site script; live monitoring, decisions, reports, and repeat scans then run automatically.'],
        ].map(([Icon, title, description]) => (
          <div key={title} className="card py-5 flex gap-3 items-start">
            <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center shrink-0"><Icon className="w-5 h-5 text-primary" /></div>
            <div><h2 className="text-sm font-semibold text-gray-200">{title}</h2><p className="text-xs text-gray-500 mt-1 leading-5">{description}</p></div>
          </div>
        ))}
      </div>

      <div className="card border-primary/20 bg-primary/5 flex flex-col md:flex-row md:items-center gap-3 justify-between">
        <div className="flex gap-3"><Info className="w-5 h-5 text-primary shrink-0 mt-0.5" /><div><p className="text-sm font-semibold text-gray-200">Each user protects their own site</p><p className="text-xs text-gray-500 mt-1">The dashboard stores settings and reports; the generated script connects NetGuard to the user&apos;s registered origin. NetGuard hashes the server-observed IP and never collects MAC addresses or raw form values.</p></div></div>
        <span className="badge badge-info whitespace-nowrap">{connectedCount}/{sites.length} connected</span>
      </div>

      {loading ? (
        <div className="h-64 flex items-center justify-center"><div className="animate-spin rounded-full h-10 w-10 border-t-2 border-primary" /></div>
      ) : sites.length === 0 ? (
        <div className="card text-center py-16">
          <Globe className="w-14 h-14 mx-auto mb-4 text-gray-700" />
          <h3 className="text-lg font-semibold text-gray-300">No protected websites yet</h3>
          <p className="text-gray-500 text-sm mt-2 mb-6">Register your first website, paste the integration script, and generate evidence-backed reports.</p>
          <button onClick={() => setShowAddModal(true)} className="btn-primary">Protect Your First Site</button>
        </div>
      ) : (
        <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
          {sites.map((site) => (
            <article key={site._id} className="card group hover:border-primary/30 transition-all">
              <div className="flex items-start justify-between gap-3 mb-4">
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center"><Globe className="w-5 h-5 text-primary" /></div>
                <div className="flex gap-2 items-center">
                  <button type="button" onClick={() => toggleSite(site)} title={site.isActive ? 'Pause protection' : 'Enable protection'} className={`w-8 h-8 rounded-lg inline-flex items-center justify-center border transition ${site.isActive ? 'text-safe border-safe/30 bg-safe/10' : 'text-gray-500 border-border bg-surface'}`}><Power className="w-4 h-4" /></button>
                  <span className={`badge ${site.isActive ? 'badge-info' : 'badge-danger'}`}>{site.isActive ? 'Enabled' : 'Disabled'}</span>
                  <span className={`badge ${connectionBadge(site.integrationStatus)}`}>{site.integrationStatus}</span>
                </div>
              </div>
              <h3 className="font-semibold text-gray-200 truncate">{site.siteName || site.siteUrl}</h3>
              <p className="text-xs text-gray-500 truncate mt-1">{site.siteUrl}</p>

              <div className="grid grid-cols-3 gap-2 my-4">
                <div className="bg-surface rounded-lg p-3 text-center"><strong className="block text-lg text-gray-200">{site.lastNetworkScan?.scannedAt && !site.lastNetworkScan?.error ? site.securityScore : '—'}</strong><span className="text-[11px] text-gray-600">Posture</span></div>
                <div className="bg-surface rounded-lg p-3 text-center"><strong className="block text-lg text-warning">{site.counters?.challenged || 0}</strong><span className="text-[11px] text-gray-600">Challenges</span></div>
                <div className="bg-surface rounded-lg p-3 text-center"><strong className="block text-lg text-primary">{site.enabledLayerCount ?? RUNTIME_LAYER_KEYS.filter((key) => site.protectionSettings?.[key]).length}/{RUNTIME_LAYER_KEYS.length}</strong><span className="text-[11px] text-gray-600">Layers ON</span></div>
              </div>

              <div className="bg-surface rounded-lg p-3 mb-4">
                <div className="text-[11px] text-gray-600 mb-1">Protection code</div>
                <div className="flex items-center gap-2"><code className="text-xs text-primary truncate flex-1">{site.protectionCode}</code><button onClick={() => copyText(site.protectionCode, 'Protection code copied')} className="text-gray-500 hover:text-primary"><Copy className="w-4 h-4" /></button></div>
              </div>

              <div className="flex gap-2">
                <button onClick={() => copyText(snippetFor(site), 'Integration script copied')} className="btn-ghost flex-1 px-3 text-sm inline-flex items-center justify-center gap-2"><Code2 className="w-4 h-4" /> Copy script</button>
                <button onClick={() => openSettings(site)} className="btn-primary flex-1 px-3 text-sm inline-flex items-center justify-center gap-2"><Settings2 className="w-4 h-4" /> Configure</button>
              </div>
              <div className="mt-3 pt-3 border-t border-border flex items-center justify-between text-[11px] text-gray-600"><span>{site.protectionRunning ? 'Live protection running' : site.lastNetworkScan?.scannedAt ? 'Scan ready · connection required' : 'Preparing first scan'}</span><span>{site.lastHeartbeat ? `Seen ${new Date(site.lastHeartbeat).toLocaleString()}` : 'Awaiting install'}</span></div>
            </article>
          ))}
        </div>
      )}

      {showAddModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-5">
          <div className="card w-full max-w-3xl max-h-[92vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6"><div><h2 className="text-lg font-bold text-gray-100">Protect a user-owned website</h2><p className="text-xs text-gray-500 mt-1">The URL, profile, and ON/OFF choices below belong only to this website.</p></div><button onClick={() => setShowAddModal(false)} className="text-gray-500 hover:text-gray-300"><X className="w-5 h-5" /></button></div>
            <form onSubmit={addSite} className="space-y-4">
              <label className="block"><span className="text-sm text-gray-400 mb-1 block">Website URL *</span><input type="url" value={newSiteUrl} onChange={(event) => setNewSiteUrl(event.target.value)} placeholder="https://example.com" className="input-field w-full" required /></label>
              <label className="block"><span className="text-sm text-gray-400 mb-1 block">Site name</span><input value={newSiteName} onChange={(event) => setNewSiteName(event.target.value)} placeholder="Customer Portal" maxLength={120} className="input-field w-full" /></label>
              <div>
                <div className="flex items-center justify-between mb-2"><span className="text-sm text-gray-400">Protection profile</span>{newSiteProfile === 'custom' && <span className="badge badge-info">Custom</span>}</div>
                <div className="grid sm:grid-cols-2 gap-3">
                  {[
                    ['balanced', 'Balanced · recommended', 'Strong protection with practical limits for normal websites.'],
                    ['strict', 'Strict', 'Lower request limits, 30-minute blocks, and scans every 12 hours.'],
                  ].map(([profile, title, description]) => (
                    <button type="button" key={profile} onClick={() => chooseNewProfile(profile)} className={`text-left rounded-xl border p-4 ${newSiteProfile === profile ? 'border-primary bg-primary/5' : 'border-border bg-surface'}`}>
                      <span className="text-sm font-semibold text-gray-200 block">{title}</span><span className="text-[11px] text-gray-500 mt-1 block">{description}</span>
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <div className="flex items-center justify-between mb-2"><span className="text-sm text-gray-400">Protection layers</span><span className="text-[11px] text-primary">{TOGGLES.filter(([key]) => newSiteSettings[key]).length}/{TOGGLES.length} ON</span></div>
                <div className="grid sm:grid-cols-2 gap-2">
                  {TOGGLES.map(([key, label]) => (
                    <button type="button" key={key} onClick={() => updateNewSetting(key, !newSiteSettings[key])} className={`rounded-lg border p-3 flex items-center justify-between gap-3 text-left ${newSiteSettings[key] ? 'border-primary/30 bg-primary/5' : 'border-border bg-surface'}`}>
                      <span className="text-xs text-gray-300">{label}</span><span className={`w-5 h-5 rounded flex items-center justify-center shrink-0 ${newSiteSettings[key] ? 'bg-primary text-white' : 'border border-gray-600'}`}>{newSiteSettings[key] && <Check className="w-3.5 h-3.5" />}</span>
                    </button>
                  ))}
                </div>
              </div>
              <div className="rounded-lg bg-safe/5 border border-safe/15 p-4 flex gap-3"><LockKeyhole className="w-5 h-5 text-safe shrink-0" /><p className="text-xs text-gray-400 leading-5">Adding the URL starts the public posture scan automatically. Live form/rate/bot protection starts after the site owner installs the generated script once; NetGuard cannot edit a remote website without that owner-authorized connection.</p></div>
              <div className="flex gap-3 pt-2"><button type="button" onClick={() => setShowAddModal(false)} className="btn-ghost flex-1">Cancel</button><button type="submit" disabled={adding} className="btn-primary flex-1">{adding ? 'Adding & scanning…' : 'Add Site & Auto-Scan'}</button></div>
            </form>
          </div>
        </div>
      )}

      {editing && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-card border border-border rounded-2xl w-full max-w-3xl max-h-[92vh] overflow-y-auto">
            <header className="sticky top-0 bg-card/95 backdrop-blur border-b border-border p-5 flex items-center justify-between z-10"><div><h2 className="font-bold text-gray-100">{editing.siteName}</h2><p className="text-xs text-gray-500 mt-1">Integration and website protection controls</p></div><button onClick={() => setEditing(null)} className="text-gray-500 hover:text-gray-200"><X className="w-5 h-5" /></button></header>
            <div className="p-5 space-y-6">
              <section className="grid sm:grid-cols-3 gap-3">
                {[
                  ['Public scan', editing.automationScan?.status === 'complete' ? 'Complete' : editing.automationScan?.status || 'Pending', Boolean(editing.lastNetworkScan?.scannedAt && !editing.lastNetworkScan?.error)],
                  ['Site connection', editing.integrationStatus === 'connected' ? 'Verified' : editing.integrationStatus, editing.integrationStatus === 'connected'],
                  ['Live protection', editing.isActive && editing.integrationStatus === 'connected' ? 'Running' : editing.isActive ? 'Waiting for connection' : 'Paused', editing.isActive && editing.integrationStatus === 'connected'],
                ].map(([label, value, good]) => (
                  <div key={label} className="bg-surface rounded-xl p-4"><span className="text-[11px] text-gray-600 block">{label}</span><strong className={`text-sm mt-1 block capitalize ${good ? 'text-safe' : 'text-warning'}`}>{value}</strong></div>
                ))}
              </section>

              <section>
                <div className="flex items-center justify-between mb-3"><h3 className="font-semibold text-gray-200 flex items-center gap-2"><Code2 className="w-4 h-4 text-primary" /> Integration code</h3><span className={`badge ${connectionBadge(editing.integrationStatus)}`}>{editing.integrationStatus}</span></div>
                <p className="text-xs text-gray-500 mb-3">Paste this once before the closing <code>&lt;/body&gt;</code> tag, deploy the site, open it, then refresh this page.</p>
                <div className="bg-dark border border-border rounded-lg p-4 flex gap-3 items-start"><code className="text-xs text-primary break-all flex-1">{snippetFor(editing)}</code><button onClick={() => copyText(snippetFor(editing), 'Integration script copied')} className="text-gray-500 hover:text-primary"><Copy className="w-4 h-4" /></button></div>
                {editing.integrationStatus === 'connected' && <div className="mt-3 text-xs text-safe flex items-center gap-2"><CheckCircle2 className="w-4 h-4" /> Integration verified from the registered origin.</div>}
              </section>

              <section className="border-t border-border pt-5">
                <div className="flex items-center justify-between gap-4"><div><h3 className="font-semibold text-gray-200">Master protection</h3><p className="text-xs text-gray-500 mt-1">Disable this to keep the site registered without applying NetGuard decisions.</p></div><button onClick={() => setEditing((current) => ({ ...current, isActive: !current.isActive }))} className={`w-12 h-7 rounded-full p-1 transition ${editing.isActive ? 'bg-safe' : 'bg-gray-700'}`}><span className={`block w-5 h-5 bg-white rounded-full transition-transform ${editing.isActive ? 'translate-x-5' : ''}`} /></button></div>
              </section>

              <section className="border-t border-border pt-5">
                <div className="flex items-center justify-between mb-3"><div><h3 className="font-semibold text-gray-200">Protection profile</h3><p className="text-xs text-gray-500 mt-1">Start with a safe profile, then change any layer to create a custom profile.</p></div><span className="badge badge-info capitalize">{editing.protectionProfile || 'balanced'}</span></div>
                <div className="grid sm:grid-cols-2 gap-3">
                  {[
                    ['balanced', 'Balanced · recommended', '8 requests / 5 seconds · 15-minute block · 24-hour scan'],
                    ['strict', 'Strict', '5 requests / 5 seconds · 30-minute block · 12-hour scan'],
                  ].map(([profile, title, description]) => (
                    <button type="button" key={profile} onClick={() => chooseEditingProfile(profile)} className={`text-left rounded-xl border p-4 ${editing.protectionProfile === profile ? 'border-primary bg-primary/5' : 'border-border bg-surface'}`}><span className="text-sm font-semibold text-gray-200 block">{title}</span><span className="text-[11px] text-gray-500 mt-1 block">{description}</span></button>
                  ))}
                </div>
              </section>

              <section className="border-t border-border pt-5">
                <div className="flex items-start justify-between gap-4 mb-4"><div><h3 className="font-semibold text-gray-200 flex items-center gap-2"><Activity className="w-4 h-4 text-primary" /> Real network posture scan</h3><p className="text-xs text-gray-500 mt-1">Inspect TLS, certificate expiry, HSTS, CSP, clickjacking, MIME, referrer, and permissions headers from the Render backend.</p></div><button onClick={runNetworkScan} disabled={scanning} className="btn-ghost text-sm whitespace-nowrap">{scanning ? 'Scanning…' : 'Run scan'}</button></div>
                {editing.lastNetworkScan?.scannedAt ? (
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    {[
                      ['Posture score', editing.lastNetworkScan.securityHeaderScore ?? 'N/A'],
                      ['TLS', editing.lastNetworkScan.tlsAuthorized ? editing.lastNetworkScan.tlsProtocol : 'Failed'],
                      ['Certificate days', editing.lastNetworkScan.certificateDaysRemaining ?? 'N/A'],
                      ['HSTS', editing.lastNetworkScan.hsts ? 'Enabled' : 'Missing'],
                      ['CSP', editing.lastNetworkScan.contentSecurityPolicy ? 'Enabled' : 'Missing'],
                      ['Frame protection', editing.lastNetworkScan.frameProtection ? 'Enabled' : 'Missing'],
                    ].map(([label, value]) => <div key={label} className="bg-surface rounded-lg p-3"><span className="text-[11px] text-gray-600 block">{label}</span><strong className="text-sm text-gray-200 mt-1 block">{value}</strong></div>)}
                  </div>
                ) : <div className="bg-surface rounded-lg p-4 text-xs text-gray-600">No stored network scan yet. Run the scan to include real posture evidence in the protected-website report.</div>}
              </section>

              <section className="grid md:grid-cols-2 gap-3">
                {TOGGLES.map(([key, label, description]) => (
                  <button key={key} onClick={() => updateSetting(key, !editing.protectionSettings[key])} className={`text-left rounded-xl border p-4 transition ${editing.protectionSettings[key] ? 'border-primary/30 bg-primary/5' : 'border-border bg-surface'}`}>
                    <div className="flex items-center justify-between gap-3"><span className="text-sm font-medium text-gray-200">{label}</span><span className={`w-5 h-5 rounded flex items-center justify-center ${editing.protectionSettings[key] ? 'bg-primary text-white' : 'border border-gray-600'}`}>{editing.protectionSettings[key] && <Check className="w-3.5 h-3.5" />}</span></div>
                    <p className="text-[11px] text-gray-500 mt-2 leading-4">{description}</p>
                  </button>
                ))}
              </section>

              {!editing.recaptchaAvailable && editing.protectionSettings.recaptchaEnabled && (
                <div className="rounded-lg bg-warning/5 border border-warning/20 p-4 text-xs text-warning">reCAPTCHA toggle is saved, but challenges remain in safe throttle mode until the Render keys are configured and this website hostname is authorized in the same Google reCAPTCHA key.</div>
              )}

              <section className="border-t border-border pt-5">
                <h3 className="font-semibold text-gray-200 flex items-center gap-2 mb-4"><Gauge className="w-4 h-4 text-primary" /> Detection thresholds</h3>
                <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
                  {[
                    ['repeatWindowSeconds', 'Repeat window (seconds)', 1, 30],
                    ['repeatMaxSubmissions', 'Same submissions allowed', 1, 20],
                    ['burstWindowSeconds', 'Burst window (seconds)', 1, 60],
                    ['burstMaxRequests', 'Events per burst', 2, 200],
                    ['minuteMaxRequests', 'Events per minute', 10, 2000],
                    ['blockMinutes', 'Temporary block (minutes)', 1, 1440],
                    ['autoScanIntervalHours', 'Automatic scan interval (hours)', 1, 168],
                  ].map(([key, label, min, max]) => (
                    <label key={key}><span className="text-xs text-gray-500 block mb-1">{label}</span><input type="number" min={min} max={max} value={editing.protectionSettings[key]} onChange={(event) => updateSetting(key, Number(event.target.value))} className="input-field w-full" /></label>
                  ))}
                </div>
                <p className="text-[11px] text-gray-600 mt-3">Balanced default: two identical submissions or eight monitored events inside five seconds trigger reCAPTCHA/throttling; an extreme pattern can be blocked for 15 minutes.</p>
              </section>
            </div>
            <footer className="sticky bottom-0 bg-card/95 backdrop-blur border-t border-border p-4 flex gap-3 justify-end"><button onClick={() => setEditing(null)} className="btn-ghost">Close</button><button onClick={saveSettings} disabled={saving} className="btn-primary flex items-center gap-2"><Shield className="w-4 h-4" />{saving ? 'Saving…' : 'Save Protection'}</button></footer>
          </div>
        </div>
      )}
    </div>
  );
}
