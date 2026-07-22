import { useEffect, useState } from 'react';
import { Shield, Eye, Brain, Lock, Bell, Save } from 'lucide-react';
import api, { notifyApiError } from '../services/api';
import toast from 'react-hot-toast';
import { useAuth } from '../context/AuthContext';

export default function Settings() {
  const { user } = useAuth();
  const [settings, setSettings] = useState({
    zeroTrustMode: true,
    behavioralDetection: true,
    threatIntelEnabled: true,
    sessionMonitoring: true,
    notifications: true,
    autoBlock: true,
  });
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (user?.settings) {
      setSettings({ ...user.settings });
    }
  }, [user]);

  const saveSettings = async () => {
    setSaving(true);
    try {
      const res = await api.put('/api/dashboard/settings', settings);
      if (res.data.success) {
        setSettings(res.data.settings);
        toast.success('Settings saved successfully!');
      }
    } catch (err) {
      notifyApiError(err, 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const toggleSetting = (key) => {
    setSettings(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const SettingRow = ({ icon: Icon, label, desc, value, onChange }) => (
    <div className="flex items-center justify-between p-4 bg-surface rounded-lg">
      <div className="flex items-center gap-3">
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${
          value ? 'bg-primary/10' : 'bg-gray-800'
        }`}>
          <Icon className={`w-4 h-4 ${value ? 'text-primary' : 'text-gray-600'}`} />
        </div>
        <div>
          <div className="text-sm font-medium text-gray-200">{label}</div>
          <div className="text-xs text-gray-500">{desc}</div>
        </div>
      </div>
      <label className="relative inline-flex items-center cursor-pointer">
        <input
          type="checkbox"
          checked={value}
          onChange={onChange}
          className="sr-only peer"
        />
        <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
      </label>
    </div>
  );

  return (
    <div className="space-y-6 max-w-3xl">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Settings</h1>
        <p className="text-gray-500 text-sm mt-1">Configure your NetGuard security settings</p>
      </div>

      {/* Zero Trust */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Lock className="w-4 h-4 text-primary" />
          Zero Trust
        </h3>
        <div className="space-y-3">
          <SettingRow
            icon={Shield}
            label="Zero Trust Mode"
            desc="Flag all unencrypted HTTP connections"
            value={settings.zeroTrustMode}
            onChange={() => toggleSetting('zeroTrustMode')}
          />
          <SettingRow
            icon={Lock}
            label="Session Monitoring"
            desc="Detect long-lived cloud session cookies"
            value={settings.sessionMonitoring}
            onChange={() => toggleSetting('sessionMonitoring')}
          />
        </div>
      </div>

      {/* Detection */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Brain className="w-4 h-4 text-secondary" />
          Detection Layers
        </h3>
        <div className="space-y-3">
          <SettingRow
            icon={Eye}
            label="Behavioral Detection"
            desc="Track third-party domains across sites"
            value={settings.behavioralDetection}
            onChange={() => toggleSetting('behavioralDetection')}
          />
          <SettingRow
            icon={Shield}
            label="Threat Intelligence"
            desc="IoC pattern matching and phishing heuristics"
            value={settings.threatIntelEnabled}
            onChange={() => toggleSetting('threatIntelEnabled')}
          />
          <SettingRow
            icon={Bell}
            label="Notifications"
            desc="Show browser notifications for threats"
            value={settings.notifications}
            onChange={() => toggleSetting('notifications')}
          />
          <SettingRow
            icon={Shield}
            label="Auto-Block Threats"
            desc="Automatically block detected threats"
            value={settings.autoBlock}
            onChange={() => toggleSetting('autoBlock')}
          />
        </div>
      </div>

      {/* Extension Info */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Shield className="w-4 h-4 text-safe" />
          Extension Info
        </h3>
        <div className="space-y-3 text-sm">
          <div className="flex justify-between py-2 border-b border-border">
            <span className="text-gray-500">Version</span>
            <span className="text-gray-200 font-mono">2.0.0</span>
          </div>
          <div className="flex justify-between py-2 border-b border-border">
            <span className="text-gray-500">Protection Code</span>
            <span className="text-primary font-mono">{user?.protectionCode || 'Not generated'}</span>
          </div>
          <div className="flex justify-between py-2 border-b border-border">
            <span className="text-gray-500">Member Since</span>
            <span className="text-gray-200">{user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A'}</span>
          </div>
          <div className="flex justify-between py-2">
            <span className="text-gray-500">Account Type</span>
            <span className={`font-medium ${user?.role === 'admin' ? 'text-warning' : 'text-primary'}`}>
              {user?.role === 'admin' ? 'Administrator' : 'Standard User'}
            </span>
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <button onClick={saveSettings} disabled={saving} className="btn-primary flex items-center gap-2">
          <Save className="w-4 h-4" />
          {saving ? 'Saving...' : 'Save Settings'}
        </button>
      </div>
    </div>
  );
}
