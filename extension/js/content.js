// ──────────────────────────────────────────────────────────
//  NetGuard – content.js v3.1
// ──────────────────────────────────────────────────────────

(function () {
  'use strict';

  const CRYPTO_MINER_SCRIPTS = [
    'coinhive','cryptoloot','minero','webminepool',
    'coin-hive','jsecoin','monerominer','deepminer','coinimp',
  ];

  const KNOWN_TRACKER_SCRIPTS = [
    'doubleclick.net','googletagmanager.com','hotjar.com',
    'mixpanel.com','segment.io','amplitude.com','fullstory.com',
    'facebook.com/tr','analytics.twitter.com',
  ];

  // Fixed regex patterns
  const XSS_PATTERNS = [
    /<script[\s>]/i, /javascript:/i, /on\w+\s*=/i,
    /eval\s*\(/i, /document\.cookie/i, /window\.location/i,
  ];

  let threatCount = 0;
  let observerStarted = false;
  let protectionEnabled = true;
  const sentThreats = new Set();

  function sendThreat(category, detail) {
    const key = `${category}:${detail}`;
    if (sentThreats.has(key)) return;
    sentThreats.add(key);
    threatCount++;
    chrome.runtime.sendMessage({ type: 'THREAT', category, detail, url: window.location.href });
  }

  function sendCredentialWarning(detail) {
    const key = `credential:${detail}`;
    if (sentThreats.has(key)) return;
    sentThreats.add(key);
    chrome.runtime.sendMessage({ type: 'CREDENTIAL_WARNING', detail, url: window.location.href });
  }

  function sendSessionWarning(detail) {
    const key = `session:${detail}`;
    if (sentThreats.has(key)) return;
    sentThreats.add(key);
    chrome.runtime.sendMessage({ type: 'SESSION_TOKEN_EXPOSED', detail, url: window.location.href });
  }

  // Check 1: Insecure Forms (Zero Trust)
  function checkInsecureForms() {
    if (!window.location.protocol.startsWith('https')) {
      const inputs = document.querySelectorAll('input[type="password"]');
      if (inputs.length > 0) {
        sendThreat('insecure-form',
          `Zero Trust violation: Password field on HTTP page at ${window.location.hostname}`);
      }
    }
  }

  // Check 2: IAM / Credential Security
  function checkCredentialSecurity() {
    const pwFields = document.querySelectorAll('input[type="password"]');
    pwFields.forEach(field => {
      if (field.autocomplete === 'off' || field.getAttribute('autocomplete') === 'off') {
        sendCredentialWarning(
          `Autocomplete disabled on password field at ${window.location.hostname}`);
      }
    });

    const hasMFAField = document.querySelector(
      'input[name*="otp"], input[name*="mfa"], input[name*="2fa"], ' +
      'input[placeholder*="code"], input[placeholder*="authenticator"]'
    );
    const hasLoginForm = document.querySelector('form input[type="password"]');
    if (hasLoginForm && !hasMFAField) {
      const cloudDomains = ['aws.amazon.com','console.cloud.google.com','portal.azure.com'];
      if (cloudDomains.some(d => window.location.hostname.includes(d))) {
        sendCredentialWarning(
          `Cloud console login at ${window.location.hostname} — no MFA field detected. IAM risk.`);
      }
    }
  }

  // Check 3: Crypto Miners
  function checkCryptoMiners() {
    const scripts = document.querySelectorAll('script[src]');
    scripts.forEach(script => {
      const src = (script.src || '').toLowerCase();
      for (const miner of CRYPTO_MINER_SCRIPTS) {
        if (src.includes(miner)) {
          script.remove();
          sendThreat('crypto-miner', `Crypto mining script detected: ${src}`);
        }
      }
    });
  }

  // Check 4: Hidden Iframes
  function checkHiddenIframes() {
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(frame => {
      const style = window.getComputedStyle(frame);
      const width = parseInt(style.width, 10);
      const height = parseInt(style.height, 10);
      const hidden = style.display === 'none' || style.visibility === 'hidden'
                  || (width < 5 && height < 5);
      if (hidden && frame.src && !frame.src.startsWith('about:')) {
        sendThreat('hidden-iframe',
          `Clickjacking/phishing: hidden iframe from ${frame.src}`);
      }
    });
  }

  // Check 5: Session Token Exposure
  function checkSessionTokenExposure() {
    const url = window.location.href;
    const tokenPatterns = [
      /[?&](token|session|sid|auth|jwt|access_token|id_token)=[^&]+/i,
      /[?&](PHPSESSID|JSESSIONID|ASP\.NET_SessionId)=[^&]+/i,
    ];
    for (const pattern of tokenPatterns) {
      if (pattern.test(url)) {
        sendSessionWarning(
          `Session token exposed in URL at ${window.location.hostname}`);
        break;
      }
    }
  }

  // Check 6: XSS Detection
  function checkXSSAttempts() {
    const params = new URLSearchParams(window.location.search);
    for (const [key, value] of params) {
      for (const pattern of XSS_PATTERNS) {
        if (pattern.test(value)) {
          sendThreat('xss-attempt',
            `XSS payload detected in URL parameter '${key}' at ${window.location.hostname}`);
          break;
        }
      }
    }
  }

  // Check 7: Tracker Visualization Data
  function collectTrackerData() {
    const thirdPartyDomains = new Set();
    const currentDomain = window.location.hostname;

    document.querySelectorAll('script[src], img[src], link[href], iframe[src]').forEach(el => {
      const src = el.src || el.href || '';
      try {
        const srcDomain = new URL(src).hostname;
        if (srcDomain && srcDomain !== currentDomain && !srcDomain.endsWith('.' + currentDomain)) {
          thirdPartyDomains.add(srcDomain);
        }
      } catch { /* skip */ }
    });

    if (thirdPartyDomains.size > 0) {
      chrome.runtime.sendMessage({
        type: 'TRACKER_MAP',
        domain: currentDomain,
        thirdParties: Array.from(thirdPartyDomains),
        url: window.location.href
      });
    }
  }

  // Check 8: Meta Refresh Redirect
  function checkRedirects() {
    const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
    if (metaRefresh) {
      const content = metaRefresh.getAttribute('content') || '';
      const urlMatch = content.match(/url=(.+)/i);
      if (urlMatch) {
        sendThreat('suspicious-redirect',
          `Meta-refresh redirect detected at ${window.location.hostname} → ${urlMatch[1]}`);
      }
    }
  }

  // Check 9: Dynamic Script Injection Monitor
  function watchDynamicScripts() {
    if (observerStarted) return;
    observerStarted = true;
    const observer = new MutationObserver((mutations) => {
      if (!protectionEnabled) return;
      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.tagName === 'SCRIPT' && node.src) {
            const src = node.src.toLowerCase();
            for (const miner of CRYPTO_MINER_SCRIPTS) {
              if (src.includes(miner)) {
                node.remove();
                sendThreat('dynamic-miner-injection', `Dynamic crypto miner removed: ${src}`);
              }
            }
          }
        });
      });
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  // Check 10: Malvertising Detection
  function checkMalvertising() {
    const adScriptPatterns = [
      /popunder/i, /popcash/i, /popads/i, /revcontent/i, /mgid\.com/i,
      /propeller-ads/i, /clickadu/i, /hilltopads/i,
    ];
    document.querySelectorAll('script[src]').forEach(script => {
      const src = (script.src || '').toLowerCase();
      for (const pattern of adScriptPatterns) {
        if (pattern.test(src)) {
          sendThreat('malvertising', `Malvertising network script detected: ${src}`);
        }
      }
    });
  }

  // Run all checks
  function runChecks(settings) {
    try {
      if (settings.zeroTrustMode !== false) checkInsecureForms();
      if (settings.sessionMonitoring !== false) {
        checkCredentialSecurity();
        checkSessionTokenExposure();
      }
      if (settings.threatIntelEnabled !== false) {
        checkCryptoMiners();
        checkHiddenIframes();
        checkXSSAttempts();
        checkRedirects();
        checkMalvertising();
        watchDynamicScripts();
      }
      if (settings.behavioralDetection !== false) {
        collectTrackerData();
      }
    } catch (e) { /* Silent fail */ }
  }

  const configuredOrigins = new Set([
    new URL(NETGUARD_CONFIG.DASHBOARD_URL).origin,
    ...(NETGUARD_CONFIG.ALLOWED_DASHBOARD_ORIGINS || []),
  ]);

  // The signed-in dashboard posts its JWT to its own page. The isolated content
  // script forwards it to extension storage without reading page localStorage.
  window.addEventListener('message', (event) => {
    if (event.source !== window || event.origin !== window.location.origin || !configuredOrigins.has(event.origin)) return;
    if (event.data?.source !== 'NETGUARD_WEB') return;
    if (event.data.type === 'NETGUARD_AUTH' && typeof event.data.token === 'string') {
      chrome.runtime.sendMessage({ type: 'SET_CLOUD_TOKEN', token: event.data.token });
    }
    if (event.data.type === 'NETGUARD_LOGOUT') {
      chrome.runtime.sendMessage({ type: 'CLEAR_CLOUD_TOKEN' });
    }
  });

  function runWhenEnabled() {
    chrome.storage.local.get([
      'protectionEnabled', 'zeroTrustMode', 'behavioralDetection',
      'sessionMonitoring', 'threatIntelEnabled',
    ], (data) => {
      protectionEnabled = data.protectionEnabled !== false;
      if (data.protectionEnabled !== false) runChecks(data);
    });
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.protectionEnabled) {
      protectionEnabled = changes.protectionEnabled.newValue !== false;
    }
  });

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', runWhenEnabled, { once: true });
  else runWhenEnabled();

  setTimeout(runWhenEnabled, 2000);
  setTimeout(runWhenEnabled, 5000);

})();
