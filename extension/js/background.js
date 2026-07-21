// ──────────────────────────────────────────────────────────
//  NetGuard – background.js v3.4
// ───────────────────────────────────────────────────────────

importScripts('config.js');

const API_BASE = NETGUARD_CONFIG.API_BASE.replace(/\/$/, '');
const RELEASE_URL = NETGUARD_CONFIG.RELEASE_URL;
const EXTENSION_VERSION = chrome.runtime.getManifest().version;

function versionParts(value) {
  return String(value || '').split('.').map((part) => Number.parseInt(part, 10) || 0);
}

function isNewerVersion(candidate, current) {
  const left = versionParts(candidate);
  const right = versionParts(current);
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    if ((left[index] || 0) > (right[index] || 0)) return true;
    if ((left[index] || 0) < (right[index] || 0)) return false;
  }
  return false;
}

async function checkForUpdates() {
  try {
    const response = await fetch(`${RELEASE_URL}${RELEASE_URL.includes('?') ? '&' : '?'}t=${Date.now()}`, { cache: 'no-store' });
    if (!response.ok) throw new Error(`Release feed returned ${response.status}`);
    const release = await response.json();
    const currentVersion = chrome.runtime.getManifest().version;
    const available = isNewerVersion(release.latestVersion, currentVersion);
    const downloadUrl = release.downloadUrl ? new URL(release.downloadUrl, RELEASE_URL).href : null;
    await chrome.storage.local.set({
      updateInfo: {
        available,
        currentVersion,
        latestVersion: release.latestVersion || currentVersion,
        downloadUrl,
        changelog: Array.isArray(release.changelog) ? release.changelog.slice(0, 5) : [],
        checkedAt: Date.now(),
      },
    });
    if (available) await chrome.action.setBadgeText({ text: 'UP' });
    else await chrome.action.setBadgeText({ text: '' });
    await chrome.action.setBadgeBackgroundColor({ color: '#ffa726' });
  } catch (error) {
    console.log('[NetGuard] Update check failed:', error.message);
  }
}

async function protectionIsEnabled() {
  const data = await chrome.storage.local.get('protectionEnabled');
  return data.protectionEnabled !== false;
}

async function settingIsEnabled(name) {
  const data = await chrome.storage.local.get(name);
  return data[name] !== false;
}

const TRACKER_DOMAINS = [
  'doubleclick.net','googletagmanager.com','hotjar.com','mixpanel.com',
  'segment.io','amplitude.com','heap.io','fullstory.com','quantserve.com',
  'scorecardresearch.com','zedo.com','adnxs.com','taboola.com','outbrain.com',
  'facebook.com','analytics.twitter.com','linkedin.com','tiktok.com',
  'pubmatic.com','rubiconproject.com','openx.net','criteo.com',
];

// FIXED: Use single backslash in regex patterns
const PHISHING_PATTERNS = [
  /paypa1\./i, /amaz0n\./i, /g00gle\./i, /faceb00k\./i,
  /login[-.]secure/i, /secure[-.]login/i, /account[-.]verify/i,
  /verify[-.]account/i, /apple[-.]id[-.]verify/i, /microsoft[-.]support[-.]alert/i,
  /netflix[-.]billing/i, /bank[-.]of[-.]america.*secure/i,
];

const MALWARE_TLDS = /\.(tk|ml|pw|xyz|ru|cn|top|club|gq|cf|ga)$/i;
const SUSPICIOUS_KEYWORDS = /\b(exploit|botnet|c2|ransom|trojan|keylog|cryptominer|spyware|adware)\b/i;

const thirdPartyTracker = {};

function getDomain(url) {
  try { return new URL(url).hostname.toLowerCase(); }
  catch { return ''; }
}

async function reportThreatToCloud(category, detail, url, severity, detectionLayer, action) {
  const token = await getToken();
  if (!token) return;

  try {
    const response = await fetch(`${API_BASE}/api/extension/threats`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        category, detail, url: url || 'browser-session://local', severity, detectionLayer, action,
        domain: getDomain(url || ''),
        extensionVersion: EXTENSION_VERSION,
      }),
    });
    if (response.status === 401) await chrome.storage.local.remove('cloudToken');
  } catch (err) {
    console.log('[NetGuard] Cloud sync failed (offline mode):', err.message);
  }
}

async function reportBrowsingActivity(url) {
  const token = await getToken();
  if (!token) return;
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) return;
    await fetch(`${API_BASE}/api/extension/activity`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      // Deliberately send no path, query string, page title, or hash.
      body: JSON.stringify({
        domain: parsed.hostname.toLowerCase(),
        protocol: parsed.protocol,
        visitedAt: new Date().toISOString(),
        extensionVersion: EXTENSION_VERSION,
      }),
    });
  } catch (error) {
    console.log('[NetGuard] Activity sync skipped:', error.message);
  }
}

async function batchReportThreats(threats) {
  const token = await getToken();
  if (!token) return;

  try {
    const response = await fetch(`${API_BASE}/api/extension/threats/batch`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ threats }),
    });
    if (response.status === 401) await chrome.storage.local.remove('cloudToken');
  } catch (err) {
    console.log('[NetGuard] Batch sync failed:', err.message);
  }
}

function getToken() {
  return new Promise(resolve => {
    chrome.storage.local.get(['cloudToken'], (data) => {
      resolve(data.cloudToken || null);
    });
  });
}

function setToken(token) {
  chrome.storage.local.set({ cloudToken: token });
}

async function syncSettingsFromCloud() {
  const token = await getToken();
  if (!token) return;

  try {
    const res = await fetch(`${API_BASE}/api/extension/settings`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    if (res.status === 401) {
      await chrome.storage.local.remove('cloudToken');
      return;
    }
    const data = await res.json();
    if (data.success) {
      chrome.storage.local.set({
        zeroTrustMode: data.settings.zeroTrustMode,
        behavioralDetection: data.settings.behavioralDetection,
        threatIntelEnabled: data.settings.threatIntelEnabled,
        sessionMonitoring: data.settings.sessionMonitoring,
      });
      console.log('[NetGuard] Settings synced from cloud');
    }
  } catch (err) {
    console.log('[NetGuard] Settings sync failed:', err.message);
  }
}

async function incrementStat(key, amount = 1) {
  return new Promise(resolve => {
    chrome.storage.local.get([key], (data) => {
      chrome.storage.local.set({ [key]: (data[key] || 0) + amount }, resolve);
    });
  });
}

async function addFeedEntry(type, title, meta, severity = 'low') {
  return new Promise(resolve => {
    chrome.storage.local.get(['feed'], (data) => {
      const feed = data.feed || [];
      feed.unshift({ type, title, meta, severity, time: Date.now() });
      if (feed.length > 100) feed.pop();
      chrome.storage.local.set({ feed }, resolve);
    });
  });
}

async function addThreatLog(category, detail, url, severity) {
  return new Promise(resolve => {
    chrome.storage.local.get(['threatLog'], (data) => {
      const log = data.threatLog || [];
      log.unshift({ category, detail, url, severity, time: Date.now() });
      if (log.length > 200) log.pop();
      chrome.storage.local.set({ threatLog: log }, resolve);
    });
  });
}

chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (!(await protectionIsEnabled())) return;
    const reqDomain = getDomain(details.url);
    const initiator = details.initiator ? getDomain(details.initiator) : '';
    if (!reqDomain || !initiator || reqDomain === initiator) return;

    if (!(await settingIsEnabled('behavioralDetection'))) return;
    if (!thirdPartyTracker[reqDomain]) thirdPartyTracker[reqDomain] = new Set();
    thirdPartyTracker[reqDomain].add(initiator);

    if (thirdPartyTracker[reqDomain].size >= 3) {
      const isKnown = TRACKER_DOMAINS.some(t => reqDomain === t || reqDomain.endsWith('.' + t));
      if (!isKnown) {
        await addFeedEntry('tracked', `Behavioral tracker: ${reqDomain}`,
          `Observed across ${thirdPartyTracker[reqDomain].size} sites`, 'medium');
        await incrementStat('trackers');
        await reportThreatToCloud('tracker', `Behavioral tracker: ${reqDomain}`, details.url, 'medium', 'behavioral', 'logged');
      }
    }
  },
  { urls: ['<all_urls>'] }
);

chrome.webRequest.onCompleted.addListener(
  async (details) => {
    if (!(await protectionIsEnabled())) return;
    const domain = getDomain(details.url);
    if (!domain) return;

    if (!(await settingIsEnabled('threatIntelEnabled'))) return;
    for (const tracker of TRACKER_DOMAINS) {
      if (domain === tracker || domain.endsWith('.' + tracker)) {
        await incrementStat('trackers');
        await addFeedEntry('tracked', `Tracker: ${domain}`, 'Cross-site tracker detected', 'low');
        await reportThreatToCloud('tracker', `Known tracker: ${domain}`, details.url, 'low', 'threat-intel', 'monitored');
        return;
      }
    }

    for (const pattern of PHISHING_PATTERNS) {
      if (pattern.test(domain)) {
        await incrementStat('blocked');
        await addFeedEntry('blocked', `Phishing pattern: ${domain}`,
          'Domain matches known phishing IoC', 'high');
        await addThreatLog('phishing-pattern', `Matched pattern: ${pattern}`, details.url, 'high');
        await reportThreatToCloud('phishing-pattern', `Phishing pattern matched: ${domain}`, details.url, 'high', 'threat-intel', 'blocked');
        return;
      }
    }

    if (MALWARE_TLDS.test(domain)) {
      await incrementStat('trackers');
      await addFeedEntry('tracked', `High-risk TLD: ${domain}`, 'Suspicious domain extension', 'medium');
      await reportThreatToCloud('high-risk-tld', `High-risk TLD: ${domain}`, details.url, 'medium', 'heuristic', 'warned');
    }

    if (SUSPICIOUS_KEYWORDS.test(domain)) {
      await incrementStat('blocked');
      await addFeedEntry('blocked', `Suspicious domain: ${domain}`,
        'Domain contains malware-related keyword', 'high');
      await addThreatLog('suspicious-keyword', domain, details.url, 'high');
      await reportThreatToCloud('malware', `Suspicious keyword in domain: ${domain}`, details.url, 'high', 'threat-intel', 'blocked');
    }
  },
  { urls: ['<all_urls>'] }
);

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (!(await protectionIsEnabled())) return;
  if (changeInfo.status !== 'complete' || !tab.url) return;
  if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) return;

  const domain = getDomain(tab.url);
  await reportBrowsingActivity(tab.url);

  if (await settingIsEnabled('zeroTrustMode') && tab.url.startsWith('http://') && domain !== 'localhost' && domain !== '127.0.0.1') {
    await addFeedEntry('tracked', `Unencrypted: ${domain}`,
      'HTTP — Zero Trust violation, no TLS encryption', 'high');
    await addThreatLog('zero-trust-http', 'Unencrypted HTTP connection', tab.url, 'high');
    await incrementStat('trackers');
    await reportThreatToCloud('zero-trust-http', `Unencrypted HTTP: ${domain}`, tab.url, 'high', 'zero-trust', 'warned');

    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'NetGuard: Unencrypted Connection',
      message: `⚠️ ${domain} uses HTTP. Your data is not encrypted.`
    });
  }

  if (/^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(tab.url)) {
    await addFeedEntry('tracked', `Direct IP access: ${domain}`,
      'Possible DNS leak — bypasses hostname resolution', 'medium');
    await incrementStat('trackers');
    await reportThreatToCloud('dns-leak', `Direct IP access: ${domain}`, tab.url, 'medium', 'heuristic', 'logged');
  }
});

if (chrome.cookies && chrome.cookies.onChanged) {
  chrome.cookies.onChanged.addListener(async (changeInfo) => {
    if (!(await protectionIsEnabled())) return;
    if (!(await settingIsEnabled('sessionMonitoring'))) return;
    const { cookie, removed } = changeInfo;
    const cloudConsoleDomains = ['.aws.amazon.com', '.console.cloud.google.com',
      '.portal.azure.com', '.cloud.google.com'];
    const isCloudConsole = cloudConsoleDomains.some(d => cookie.domain.endsWith(d));
    if (!removed && isCloudConsole && !cookie.session && cookie.expirationDate) {
      const daysLeft = (cookie.expirationDate - Date.now() / 1000) / 86400;
      if (daysLeft > 7) {
        await addFeedEntry('tracked', `Long-lived cloud session: ${cookie.domain}`,
          `Cookie expires in ${Math.round(daysLeft)} days — session hijacking risk`, 'medium');
        await reportThreatToCloud('session-exposed', `Long-lived session: ${cookie.domain}`, '', 'medium', 'session-monitor', 'warned');
      }
    }
  });
}

chrome.alarms.create('security-heartbeat', { periodInMinutes: 5 });
chrome.alarms.create('threat-intel-refresh', { periodInMinutes: 30 });
chrome.alarms.create('cloud-sync', { periodInMinutes: 2 });
chrome.alarms.create('release-check', { periodInMinutes: 360 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'security-heartbeat') {
    const domains = Object.keys(thirdPartyTracker);
    if (domains.length > 500) {
      const oldest = domains.slice(0, 100);
      oldest.forEach(d => delete thirdPartyTracker[d]);
    }
  }
  if (alarm.name === 'threat-intel-refresh') {
    await addFeedEntry('safe', 'Threat Intel Refreshed',
      'IoC database and behavioral patterns updated', 'low');
  }
  if (alarm.name === 'cloud-sync') {
    await syncSettingsFromCloud();
  }
  if (alarm.name === 'release-check') await checkForUpdates();
});

chrome.runtime.onMessage.addListener(async (msg, sender) => {
  if (msg.type === 'THREAT') {
    if (!(await protectionIsEnabled())) return;
    await incrementStat('blocked');
    await addFeedEntry('blocked', msg.category, msg.detail, 'high');
    await addThreatLog(msg.category, msg.detail, msg.url || sender.url, 'high');
    await reportThreatToCloud(msg.category, msg.detail, msg.url || sender.url, 'high', 'content-script', 'blocked');

    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: `NetGuard: ${msg.category}`,
      message: msg.detail.substring(0, 100)
    });
  }

  if (msg.type === 'CREDENTIAL_WARNING') {
    await addFeedEntry('tracked', 'Credential Risk', msg.detail, 'high');
    await addThreatLog('credential-risk', msg.detail, msg.url, 'high');
    await reportThreatToCloud('credential-risk', msg.detail, msg.url, 'high', 'content-script', 'warned');
  }

  if (msg.type === 'SESSION_TOKEN_EXPOSED') {
    await addFeedEntry('blocked', 'Session Token Exposed', msg.detail, 'high');
    await incrementStat('blocked');
    await reportThreatToCloud('session-exposed', msg.detail, msg.url, 'high', 'content-script', 'blocked');
  }

  if (msg.type === 'SET_CLOUD_TOKEN') {
    setToken(msg.token);
    console.log('[NetGuard] Cloud token saved');
  }

  if (msg.type === 'CLEAR_CLOUD_TOKEN') {
    await chrome.storage.local.remove('cloudToken');
  }

  if (msg.type === 'PROTECTION_TOGGLE') {
    await chrome.storage.local.set({ protectionEnabled: Boolean(msg.enabled) });
    await chrome.declarativeNetRequest.updateEnabledRulesets(
      msg.enabled ? { enableRulesetIds: ['ruleset_1'] } : { disableRulesetIds: ['ruleset_1'] }
    );
  }

  if (msg.type === 'CHECK_FOR_UPDATES') await checkForUpdates();

  if (msg.type === 'GET_CLOUD_TOKEN') {
    const token = await getToken();
    chrome.runtime.sendMessage({ type: 'CLOUD_TOKEN_RESPONSE', token });
  }
});

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.storage.local.set({
      protectionEnabled: true,
      blocked: 0, trackers: 0, safe: 0, feed: [], threatLog: [],
      zeroTrustMode: true,
      behavioralDetection: true,
      sessionMonitoring: true,
      threatIntelEnabled: true,
      installedAt: Date.now(),
    });
    chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds: ['ruleset_1'] });
  }
  checkForUpdates();
});

checkForUpdates();
console.log('[NetGuard] v3.4 service worker running.');
