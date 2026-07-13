// NetGuard popup.js v3.1

const API_BASE = NETGUARD_CONFIG.API_BASE.replace(/\/$/, '');
const DASHBOARD_URL = NETGUARD_CONFIG.DASHBOARD_URL.replace(/\/$/, '');

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

const PHISHING_DOMAINS = [
  'paypa1.com','amazon-secure-login.com','g00gle.com','faceb00k.com',
  'netflix-billing-update.com','apple-id-verify.net','secure-bankofamerica.com',
  'microsoft-support-alert.com','login-instagram.xyz','verify-paypal.info',
  'account-google-verify.com','icloud-locked.net','ebay-account-verify.org',
  'dropbox-shared-files.com','linkedin-premium-free.com',
  'signin-paypal-account.com','update-amazon-account.net','google-security-alert.xyz',
];

const MALWARE_DOMAINS = [
  'malware-download.ru','virus-host.cn','exploit-kit.io','botnet-c2.xyz',
  'ransomware-spread.tk','trojan-dropper.ml','keylogger-host.pw',
  'cryptominer-pool.ru','adware-injector.cn','spyware-collect.xyz',
];

const TRACKER_DOMAINS = [
  'doubleclick.net','googletagmanager.com','facebook.com/tr',
  'analytics.twitter.com','hotjar.com','mixpanel.com','segment.io',
  'amplitude.com','heap.io','fullstory.com','criteo.com','taboola.com',
];

function extractDomain(url) {
  try {
    return new URL(url.startsWith('http') ? url : 'https://' + url).hostname.toLowerCase();
  } catch { return url.toLowerCase(); }
}

function timeAgo(ms) {
  const diff = Date.now() - ms;
  if (diff < 60000) return Math.floor(diff/1000) + 's ago';
  if (diff < 3600000) return Math.floor(diff/60000) + 'm ago';
  return Math.floor(diff/3600000) + 'h ago';
}

function formatDomain(url) {
  const d = extractDomain(url);
  return d.length > 32 ? d.substring(0, 30) + '…' : d;
}

function scanURL(url) {
  const domain = extractDomain(url);

  for (const ph of PHISHING_DOMAINS) {
    if (domain === ph || domain.endsWith(`.${ph}`)) {
      return { status: 'danger', label: 'PHISHING DETECTED', desc: `Matches known phishing domain: ${ph}`, icon: '🎣', severity: 'CRITICAL', layer: 'Threat Intelligence' };
    }
  }
  for (const mal of MALWARE_DOMAINS) {
    if (domain === mal || domain.endsWith(`.${mal}`)) {
      return { status: 'danger', label: 'MALWARE HOST', desc: 'Known malware distribution point', icon: '☣️', severity: 'CRITICAL', layer: 'Threat Intelligence' };
    }
  }
  for (const tr of TRACKER_DOMAINS) {
    if (domain === tr || domain.endsWith(`.${tr}`)) {
      return { status: 'warning', label: 'TRACKER DETECTED', desc: 'Cross-site tracking domain', icon: '👁️', severity: 'MEDIUM', layer: 'Behavioral Analysis' };
    }
  }

  const realDomains = ['paypal.com','amazon.com','google.com','apple.com','microsoft.com','netflix.com','facebook.com','instagram.com'];
  const brandPattern = /paypal|amazon|google|apple|microsoft|netflix|facebook|instagram/i;
  const isMimicking = brandPattern.test(domain) && !realDomains.some(r => domain === r || domain.endsWith(`.${r}`));
  if (isMimicking) {
    return { status: 'danger', label: 'BRAND SPOOFING', desc: 'Domain mimics a legitimate brand — likely phishing', icon: '', severity: 'HIGH', layer: 'Heuristic Analysis' };
  }

  if (/\.(tk|ml|pw|xyz|ru|cn|top|gq|cf|ga)$/.test(domain)) {
    return { status: 'warning', label: 'SUSPICIOUS TLD', desc: 'High-risk top-level domain', icon: '⚠️', severity: 'MEDIUM', layer: 'Heuristic Analysis' };
  }

  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain)) {
    return { status: 'warning', label: 'DIRECT IP ACCESS', desc: 'Possible DNS leak — bypasses hostname resolution', icon: '🔍', severity: 'MEDIUM', layer: 'DNS Monitor' };
  }

  if (/^http:\/\//i.test(url)) {
    return { status: 'warning', label: 'UNENCRYPTED (HTTP)', desc: 'Zero Trust violation — no TLS encryption', icon: '🔓', severity: 'HIGH', layer: 'Zero Trust' };
  }

  return { status: 'safe', label: 'URL IS SAFE', desc: 'No threats detected. HTTPS encrypted.', icon: '✅', severity: 'NONE', layer: 'All Layers' };
}

function showScanResult(result) {
  const box = document.getElementById('scanResult');
  const icon = document.getElementById('resultIcon');
  const title = document.getElementById('resultTitle');
  const desc = document.getElementById('resultDesc');
  const sev = document.getElementById('resultSeverity');
  const layer = document.getElementById('resultLayer');

  box.className = `scan-result ${result.status}`;
  icon.textContent = result.icon;
  title.className = `result-title ${result.status}`;
  title.textContent = result.label;
  desc.textContent = result.desc;
  if (sev) { sev.textContent = `Severity: ${result.severity}`; sev.className = `sev-badge sev-${result.severity.toLowerCase()}`; }
  if (layer) { layer.textContent = `Layer: ${result.layer}`; }
  box.style.display = 'block';
}

function addFeedItem(type, title, meta, severity = '') {
  const list = document.getElementById('feedList');
  const empty = list.querySelector('.empty-feed');
  if (empty) empty.remove();

  const safeSeverity = String(severity || '').toLowerCase();
  const sevBadge = severity ? `<span class="sev-mini sev-${escapeHtml(safeSeverity)}">${escapeHtml(severity)}</span>` : '';
  const item = document.createElement('div');
  item.className = 'feed-item';
  item.innerHTML = `
    <div class="feed-dot ${type}"></div>
    <div class="feed-info">
      <div class="feed-title">${escapeHtml(title)} ${sevBadge}</div>
      <div class="feed-meta">${escapeHtml(meta)}</div>
    </div>
    <div class="feed-time">${timeAgo(Date.now())}</div>
  `;
  list.insertBefore(item, list.firstChild);
  while (list.children.length > 10) list.removeChild(list.lastChild);
}

function loadStoredFeed(feed) {
  if (!feed || feed.length === 0) return;
  const list = document.getElementById('feedList');
  const empty = list.querySelector('.empty-feed');
  if (empty) empty.remove();

  feed.slice(0, 10).forEach(item => {
    const el = document.createElement('div');
    el.className = 'feed-item';
    const severity = escapeHtml(item.severity || '');
    const sevBadge = item.severity ? `<span class="sev-mini sev-${severity}">${severity.toUpperCase()}</span>` : '';
    el.innerHTML = `
      <div class="feed-dot ${item.type}"></div>
      <div class="feed-info">
        <div class="feed-title">${escapeHtml(item.title)} ${sevBadge}</div>
        <div class="feed-meta">${escapeHtml(item.meta)}</div>
      </div>
      <div class="feed-time">${timeAgo(item.time)}</div>
    `;
    list.appendChild(el);
  });
}

function loadThreatLog(log) {
  const container = document.getElementById('threatLogList');
  if (!container) return;
  container.innerHTML = '';
  if (!log || log.length === 0) {
    container.innerHTML = '<div class="empty-feed">No threats recorded this session.</div>';
    return;
  }
  log.slice(0, 15).forEach(entry => {
    const el = document.createElement('div');
    el.className = 'threat-log-item';
    el.innerHTML = `
      <div class="log-header">
        <span class="log-category">${escapeHtml(entry.category)}</span>
        <span class="sev-mini sev-${escapeHtml(entry.severity || 'low')}">${escapeHtml(entry.severity || 'low').toUpperCase()}</span>
        <span class="feed-time">${timeAgo(entry.time)}</span>
      </div>
      <div class="log-detail">${escapeHtml(entry.detail)}</div>
    `;
    container.appendChild(el);
  });
}

function updateStats(blocked, trackers, safe) {
  document.getElementById('statBlocked').textContent = blocked;
  document.getElementById('statTrackers').textContent = trackers;
  document.getElementById('statSafe').textContent = safe;
}

function animateStat(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.transform = 'scale(1.3)';
  setTimeout(() => el.style.transform = 'scale(1)', 200);
}

function getStats(cb) {
  chrome.storage.local.get(['blocked','trackers','safe','feed','threatLog'], (data) => {
    cb(data.blocked||0, data.trackers||0, data.safe||0, data.feed||[], data.threatLog||[]);
  });
}

function incrementStat(key) {
  chrome.storage.local.get([key], (data) => {
    chrome.storage.local.set({ [key]: (data[key]||0) + 1 });
  });
}

function saveFeedItem(type, title, meta, severity) {
  chrome.storage.local.get(['feed'], (data) => {
    const feed = data.feed || [];
    feed.unshift({ type, title, meta, severity, time: Date.now() });
    if (feed.length > 50) feed.pop();
    chrome.storage.local.set({ feed });
  });
}

function loadCurrentTab() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.url) return;
    const urlText = document.getElementById('currentUrlText');
    const statusIcon = document.getElementById('currentUrlStatusIcon');
    urlText.textContent = formatDomain(tab.url);
    const result = scanURL(tab.url);
    const icons = { safe: '✅', danger: '🚫', warning: '⚠️' };
    statusIcon.textContent = icons[result.status];
    const tlsInput = document.getElementById('tlsHostInput');
    if (tlsInput && /^https?:/i.test(tab.url)) tlsInput.value = extractDomain(tab.url);

    if (result.status === 'danger') addFeedItem('blocked', `Threat: ${formatDomain(tab.url)}`, result.label, 'HIGH');
    else if (result.status === 'warning') addFeedItem('tracked', `Warning: ${formatDomain(tab.url)}`, result.label, 'MEDIUM');
    else addFeedItem('safe', `Safe: ${formatDomain(tab.url)}`, 'No threats detected');
  });
}

function updateLayerStatus(settings) {
  const layers = [
    { id: 'layerZeroTrust', key: 'zeroTrustMode', label: 'Zero Trust' },
    { id: 'layerBehavioral', key: 'behavioralDetection', label: 'Behavioral' },
    { id: 'layerThreatIntel', key: 'threatIntelEnabled', label: 'Threat Intel' },
    { id: 'layerSession', key: 'sessionMonitoring', label: 'Session' },
  ];
  layers.forEach(l => {
    const el = document.getElementById(l.id);
    if (!el) return;
    const on = settings[l.key] !== false;
    el.className = `layer-dot ${on ? 'layer-on' : 'layer-off'}`;
    el.title = `${l.label}: ${on ? 'Active' : 'Off'}`;
  });
}

function setupTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  const panes = document.querySelectorAll('.tab-pane');
  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      panes.forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const target = document.getElementById('pane-' + btn.dataset.tab);
      if (target) target.classList.add('active');
    });
  });
}

// Cloud Status Check
function updateCloudStatus() {
  chrome.storage.local.get(['cloudToken'], (data) => {
    const cloudIndicator = document.getElementById('cloudStatus');
    if (cloudIndicator) {
      if (data.cloudToken) {
        cloudIndicator.innerHTML = '<span class="cloud-dot cloud-on"></span> Cloud Synced';
      } else {
        cloudIndicator.innerHTML = '<span class="cloud-dot cloud-off"></span> Offline Mode';
      }
    }
  });
}

function updateUpdateBanner() {
  chrome.storage.local.get('updateInfo', ({ updateInfo }) => {
    const banner = document.getElementById('updateBanner');
    const text = document.getElementById('updateText');
    const button = document.getElementById('updateButton');
    if (!banner || !updateInfo?.available || !updateInfo.downloadUrl) return;
    text.textContent = `Update available: v${updateInfo.latestVersion}`;
    banner.classList.add('show');
    button.onclick = () => chrome.tabs.create({ url: updateInfo.downloadUrl });
  });
}

function scorePassword(password) {
  const checks = [
    password.length >= 8,
    password.length >= 12,
    /[a-z]/.test(password),
    /[A-Z]/.test(password),
    /\d/.test(password),
    /[^A-Za-z0-9]/.test(password),
  ];
  return checks.filter(Boolean).length;
}

function updateStrengthMeter(password) {
  const score = scorePassword(password);
  const percent = password ? Math.round((score / 6) * 100) : 0;
  const fill = document.getElementById('strengthFill');
  const label = document.getElementById('strengthLabel');
  const names = ['Very weak', 'Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong'];
  const colors = ['#ff3b5c', '#ff3b5c', '#ff6432', '#ffa726', '#4f8ef7', '#00c853', '#00e676'];
  fill.style.width = `${percent}%`;
  fill.style.background = colors[score];
  label.textContent = password
    ? `${names[score]} (${score}/6 checks). The full password never leaves this device.`
    : 'Nothing is sent while you type. Only the first 5 SHA-1 characters are used for the breach check.';
}

async function sha1Hex(value) {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function checkPasswordBreach() {
  const input = document.getElementById('passwordInput');
  const result = document.getElementById('passwordResult');
  const button = document.getElementById('passwordCheckBtn');
  const password = input.value;
  if (!password) return;

  button.disabled = true;
  button.textContent = 'Checking...';
  result.className = 'tool-result show';
  result.textContent = 'Creating a local SHA-1 hash and sending only its 5-character prefix...';

  try {
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' },
      cache: 'no-store',
    });
    if (!response.ok) throw new Error(`HIBP returned ${response.status}`);
    const body = await response.text();
    const match = body.split('\n').find((line) => line.slice(0, 35).toUpperCase() === suffix);
    const count = match ? Number.parseInt(match.split(':')[1], 10) || 0 : 0;
    const strength = scorePassword(password);
    result.className = `tool-result show ${count > 0 ? 'danger' : strength >= 5 ? 'safe' : 'warning'}`;
    result.innerHTML = `
      <div class="tool-result-title">${count > 0 ? 'Compromised password' : 'No breach match found'}</div>
      <div class="tool-result-line"><span class="tool-result-key">Breach occurrences</span><span class="tool-result-value">${count.toLocaleString()}</span></div>
      <div class="tool-result-line"><span class="tool-result-key">Strength checks</span><span class="tool-result-value">${strength}/6</span></div>
      <div class="privacy-note">${count > 0 ? 'Do not use this password. Change it anywhere it is currently used.' : 'No match is not a guarantee of safety; always use a unique password and MFA.'}</div>`;
  } catch (error) {
    result.className = 'tool-result show warning';
    result.textContent = `Breach check unavailable: ${error.message}`;
  } finally {
    input.value = '';
    updateStrengthMeter('');
    button.disabled = false;
    button.textContent = 'Check';
  }
}

async function inspectTls() {
  const input = document.getElementById('tlsHostInput');
  const result = document.getElementById('tlsResult');
  const button = document.getElementById('tlsCheckBtn');
  const host = extractDomain(input.value.trim());
  if (!host) return;

  button.disabled = true;
  button.textContent = 'Inspecting...';
  result.className = 'tool-result show';
  result.textContent = 'Connecting to the certificate endpoint...';

  try {
    const response = await fetch(`${API_BASE}/api/public/tls-inspect?host=${encodeURIComponent(host)}`, { cache: 'no-store' });
    const payload = await response.json();
    if (!response.ok || !payload.success) throw new Error(payload.message || `API returned ${response.status}`);
    const data = payload.data;
    const healthy = data.authorized && data.daysRemaining > 14 && /^TLSv1\.[23]$/.test(data.protocol);
    result.className = `tool-result show ${healthy ? 'safe' : 'warning'}`;
    result.innerHTML = `
      <div class="tool-result-title">${healthy ? 'Valid TLS configuration' : 'TLS needs attention'}</div>
      <div class="tool-result-line"><span class="tool-result-key">Protocol</span><span class="tool-result-value">${escapeHtml(data.protocol)}</span></div>
      <div class="tool-result-line"><span class="tool-result-key">Cipher</span><span class="tool-result-value">${escapeHtml(data.cipher)}</span></div>
      <div class="tool-result-line"><span class="tool-result-key">Certificate</span><span class="tool-result-value">${escapeHtml(data.subject)}</span></div>
      <div class="tool-result-line"><span class="tool-result-key">Issuer</span><span class="tool-result-value">${escapeHtml(data.issuer)}</span></div>
      <div class="tool-result-line"><span class="tool-result-key">Expires in</span><span class="tool-result-value">${escapeHtml(data.daysRemaining)} days</span></div>
      <div class="tool-result-line"><span class="tool-result-key">HSTS</span><span class="tool-result-value">${data.hsts?.enabled ? 'Enabled' : 'Not detected'}</span></div>`;
  } catch (error) {
    result.className = 'tool-result show danger';
    result.textContent = `TLS inspection failed: ${error.message}`;
  } finally {
    button.disabled = false;
    button.textContent = 'Inspect';
  }
}

// Scan Button
document.getElementById('scanBtn').addEventListener('click', () => {
  const input = document.getElementById('scanInput').value.trim();
  if (!input) return;

  const result = scanURL(input);
  showScanResult(result);

  if (result.status === 'safe') {
    incrementStat('safe');
    addFeedItem('safe', `Scan passed: ${formatDomain(input)}`, 'No threats detected');
    saveFeedItem('safe', `Scan passed: ${formatDomain(input)}`, 'No threats detected', 'none');
    animateStat('statSafe');
  } else if (result.status === 'danger') {
    incrementStat('blocked');
    addFeedItem('blocked', `Threat: ${formatDomain(input)}`, result.label, result.severity);
    saveFeedItem('blocked', `Threat: ${formatDomain(input)}`, result.label, result.severity.toLowerCase());
    animateStat('statBlocked');
  } else {
    incrementStat('trackers');
    addFeedItem('tracked', `Warning: ${formatDomain(input)}`, result.label, result.severity);
    saveFeedItem('tracked', `Warning: ${formatDomain(input)}`, result.label, result.severity.toLowerCase());
    animateStat('statTrackers');
  }
  getStats((b, t, s) => updateStats(b, t, s));
});

document.getElementById('scanInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('scanBtn').click();
});

document.getElementById('passwordInput').addEventListener('input', (event) => updateStrengthMeter(event.target.value));
document.getElementById('passwordInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') checkPasswordBreach();
});
document.getElementById('passwordCheckBtn').addEventListener('click', checkPasswordBreach);
document.getElementById('tlsHostInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') inspectTls();
});
document.getElementById('tlsCheckBtn').addEventListener('click', inspectTls);

// Protection Toggle
document.getElementById('protectionToggle').addEventListener('change', (e) => {
  const enabled = e.target.checked;
  chrome.runtime.sendMessage({ type: 'PROTECTION_TOGGLE', enabled });
  const badge = document.querySelector('.status-badge');
  if (enabled) {
    badge.style.background = 'rgba(0,230,118,0.1)';
    badge.style.borderColor = 'rgba(0,230,118,0.3)';
    badge.style.color = 'var(--safe)';
    badge.innerHTML = '<div class="status-dot"></div> ACTIVE';
  } else {
    badge.style.background = 'rgba(255,59,92,0.1)';
    badge.style.borderColor = 'rgba(255,59,92,0.3)';
    badge.style.color = 'var(--danger)';
    badge.innerHTML = '<div class="status-dot" style="background:var(--danger)"></div> PAUSED';
  }
});

// Feature Toggles
function setupFeatureToggles() {
  const toggles = [
    { id: 'zeroTrustToggle', key: 'zeroTrustMode' },
    { id: 'behavioralToggle', key: 'behavioralDetection' },
    { id: 'sessionToggle', key: 'sessionMonitoring' },
    { id: 'threatIntelToggle', key: 'threatIntelEnabled' },
  ];
  chrome.storage.local.get(toggles.map(t => t.key), (data) => {
    toggles.forEach(t => {
      const el = document.getElementById(t.id);
      if (!el) return;
      el.checked = data[t.key] !== false;
      el.addEventListener('change', () => {
        chrome.storage.local.set({ [t.key]: el.checked });
        chrome.storage.local.get(toggles.map(x => x.key), (d) => updateLayerStatus(d));
      });
    });
    updateLayerStatus(data);
  });
}

// Clear Data
const clearBtn = document.getElementById('clearDataBtn');
if (clearBtn) {
  clearBtn.addEventListener('click', () => {
    chrome.storage.local.set({ blocked: 0, trackers: 0, safe: 0, feed: [], threatLog: [] }, () => {
      updateStats(0, 0, 0);
      document.getElementById('feedList').innerHTML = '<div class="empty-feed">No activity yet.</div>';
      const logList = document.getElementById('threatLogList');
      if (logList) logList.innerHTML = '<div class="empty-feed">No threats recorded this session.</div>';
    });
  });
}

document.getElementById('exportDataBtn').addEventListener('click', () => {
  chrome.storage.local.get([
    'blocked', 'trackers', 'safe', 'feed', 'threatLog',
    'zeroTrustMode', 'behavioralDetection', 'sessionMonitoring', 'threatIntelEnabled',
  ], (data) => {
    const payload = {
      exportedAt: new Date().toISOString(),
      extensionVersion: chrome.runtime.getManifest().version,
      ...data,
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `netguard-threat-log-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
});

document.getElementById('dashboardLink').addEventListener('click', () => {
  chrome.tabs.create({ url: `${DASHBOARD_URL}/dashboard` });
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (changes.updateInfo) updateUpdateBanner();
  if (changes.cloudToken) updateCloudStatus();
});

// Init
document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  setupFeatureToggles();
  document.getElementById('extensionVersion').textContent = `v${chrome.runtime.getManifest().version}`;

  getStats((blocked, trackers, safe, feed, threatLog) => {
    updateStats(blocked, trackers, safe);
    loadStoredFeed(feed);
    loadThreatLog(threatLog);
  });

  loadCurrentTab();
  updateCloudStatus();
  updateUpdateBanner();
  chrome.runtime.sendMessage({ type: 'CHECK_FOR_UPDATES' });

  chrome.storage.local.get(['protectionEnabled'], (data) => {
    const toggle = document.getElementById('protectionToggle');
    if (data.protectionEnabled === false) {
      toggle.checked = false;
      toggle.dispatchEvent(new Event('change'));
    }
  });
});
