// ──────────────────────────────────────────────────────────
//  NetGuard – content.js v3.5
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
  let warningShown = false;
  let warningDismissedForPage = false;
  let warningTimer = null;
  let dismissActiveWarning = null;

  const USER_WARNING_CATEGORIES = new Set([
    'insecure-form', 'crypto-miner', 'dynamic-miner-injection',
    'xss-attempt', 'suspicious-redirect', 'malvertising',
  ]);

  function contentThreatFinding(category, detail) {
    const labels = {
      'insecure-form': 'UNENCRYPTED PASSWORD FORM',
      'crypto-miner': 'CRYPTO MINER DETECTED',
      'dynamic-miner-injection': 'CRYPTO MINER BLOCKED',
      'xss-attempt': 'XSS ATTACK PATTERN',
      'suspicious-redirect': 'SUSPICIOUS REDIRECT',
      'malvertising': 'MALICIOUS AD SCRIPT',
    };
    return {
      status: 'danger',
      category,
      severity: category === 'xss-attempt' || category.includes('miner') ? 'critical' : 'high',
      score: category === 'xss-attempt' || category.includes('miner') ? 96 : 88,
      label: labels[category] || 'UNSAFE WEBSITE DETECTED',
      reason: detail,
      layer: 'Live Page Analysis',
    };
  }

  function showUnsafeWarning(finding, source = 'content') {
    if (window !== window.top || warningShown || warningDismissedForPage || !document.documentElement) return;
    warningShown = true;

    const pageStyle = document.createElement('style');
    pageStyle.id = 'netguard-warning-page-style';
    pageStyle.textContent = `
      html[data-netguard-warning-active] { overflow: hidden !important; }
      html[data-netguard-warning-active] body > :not(#netguard-unsafe-warning) {
        filter: blur(8px) saturate(.55) brightness(.45) !important;
        pointer-events: none !important;
        user-select: none !important;
        transition: filter .18s ease !important;
      }
    `;

    const host = document.createElement('div');
    host.id = 'netguard-unsafe-warning';
    host.setAttribute('role', 'presentation');
    host.style.cssText = 'position:fixed!important;inset:0!important;z-index:2147483647!important;display:block!important;';
    const shadow = host.attachShadow({ mode: 'closed' });
    shadow.innerHTML = `
      <style>
        :host { all: initial; }
        * { box-sizing: border-box; }
        .screen {
          position: fixed; inset: 0; z-index: 2147483647;
          display: grid; place-items: center; padding: 24px;
          background: rgba(2, 6, 15, .74);
          -webkit-backdrop-filter: blur(12px); backdrop-filter: blur(12px);
          font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          color: #f8fafc;
        }
        .scanline { position:absolute; inset:0; pointer-events:none; opacity:.18; background:repeating-linear-gradient(0deg,transparent 0 3px,rgba(255,255,255,.025) 3px 4px); }
        .card {
          position: relative; width: min(620px, 100%); overflow: hidden;
          border: 1px solid rgba(255, 62, 92, .5); border-radius: 24px;
          background: linear-gradient(155deg, rgba(17, 24, 39, .98), rgba(4, 9, 20, .98));
          box-shadow: 0 32px 100px rgba(0,0,0,.65), 0 0 60px rgba(255,59,92,.16);
          animation: ng-enter .22s ease-out;
        }
        @keyframes ng-enter { from { opacity:0; transform:translateY(12px) scale(.985); } }
        .topbar { height:5px; background:linear-gradient(90deg,#ff3155,#ff7832,#ff3155); }
        .inner { padding: 34px 38px 32px; }
        .header { display:flex; gap:18px; align-items:center; }
        .shield {
          width:72px; height:72px; flex:0 0 72px; display:grid; place-items:center;
          border-radius:20px; color:#fff; background:rgba(255,49,85,.14);
          border:1px solid rgba(255,49,85,.42); box-shadow:inset 0 0 24px rgba(255,49,85,.08);
        }
        .shield svg { width:38px; height:38px; }
        .eyebrow { color:#ff5c76; font:700 11px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing:.18em; }
        h1 { margin:7px 0 0; color:#fff; font-size:clamp(25px,5vw,36px); line-height:1.08; letter-spacing:-.025em; }
        .domain { margin-top:22px; padding:13px 15px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; border-radius:11px; background:#060b15; border:1px solid #263247; color:#fca5a5; font:600 13px/1.3 ui-monospace, SFMono-Regular, Menlo, monospace; }
        .ai { margin-top:14px; padding:16px; border-radius:13px; background:rgba(79,142,247,.08); border:1px solid rgba(79,142,247,.25); }
        .ai-title { color:#7db2ff; font-size:12px; font-weight:800; letter-spacing:.08em; }
        .ai p { margin:7px 0 0; color:#cbd5e1; font-size:14px; line-height:1.6; }
        .facts { display:flex; flex-wrap:wrap; gap:8px; margin-top:15px; }
        .pill { padding:7px 10px; border:1px solid #2b374b; border-radius:999px; color:#94a3b8; background:rgba(255,255,255,.025); font-size:11px; font-weight:700; }
        .pill.danger { color:#fecdd3; border-color:rgba(255,49,85,.35); background:rgba(255,49,85,.08); }
        .timerbox { display:flex; align-items:center; gap:13px; margin-top:19px; padding:14px 16px; border-radius:13px; background:rgba(255,255,255,.035); border:1px solid #263247; }
        .timer { width:45px; height:45px; flex:0 0 45px; border-radius:50%; display:grid; place-items:center; border:3px solid #ff3155; color:#fff; font:800 18px/1 ui-monospace,monospace; box-shadow:0 0 20px rgba(255,49,85,.18); }
        .timer-title { color:#f1f5f9; font-size:13px; font-weight:800; }
        .timer-note { color:#7f8da3; font-size:12px; margin-top:3px; }
        .actions { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:20px; }
        button { min-height:48px; border-radius:12px; font:800 13px/1 ui-sans-serif,system-ui,sans-serif; cursor:pointer; transition:transform .15s,filter .15s,border-color .15s; }
        button:hover { transform:translateY(-1px); filter:brightness(1.08); }
        button:focus-visible { outline:3px solid rgba(125,178,255,.8); outline-offset:2px; }
        button:disabled { cursor:wait; opacity:.65; transform:none; }
        .back { color:#fff; border:0; background:linear-gradient(135deg,#ff3155,#c5123b); box-shadow:0 8px 24px rgba(255,49,85,.2); }
        .continue { color:#aab7ca; border:1px solid #344156; background:#101827; }
        .foot { margin-top:17px; text-align:center; color:#526079; font-size:10px; letter-spacing:.08em; }
        @media (max-width:560px) { .inner{padding:26px 22px 24px}.header{align-items:flex-start}.shield{width:58px;height:58px;flex-basis:58px}.actions{grid-template-columns:1fr}.continue{order:2} }
        @media (prefers-reduced-motion:reduce) { .card, button { animation:none; transition:none; } }
      </style>
      <section class="screen" role="alertdialog" aria-modal="true" aria-labelledby="ng-warning-title" aria-describedby="ng-warning-reason">
        <div class="scanline"></div>
        <div class="card">
          <div class="topbar"></div>
          <div class="inner">
            <div class="header">
              <div class="shield" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3 5 6v5c0 4.7 2.8 8.2 7 10 4.2-1.8 7-5.3 7-10V6l-7-3Z"/><path d="m9.4 9.4 5.2 5.2m0-5.2-5.2 5.2"/></svg>
              </div>
              <div><div class="eyebrow">NETGUARD ACTIVE PROTECTION</div><h1 id="ng-warning-title">Unsafe website detected</h1></div>
            </div>
            <div class="domain" id="ng-domain"></div>
            <div class="ai"><div class="ai-title">NETGUARD AI RISK RECOMMENDATION</div><p id="ng-warning-reason"></p></div>
            <div class="facts"><span class="pill danger" id="ng-severity"></span><span class="pill" id="ng-layer"></span><span class="pill" id="ng-score"></span></div>
            <div class="timerbox"><div class="timer" id="ng-countdown">10</div><div><div class="timer-title">Returning you to safety in <span id="ng-seconds">10 seconds</span></div><div class="timer-note">Choose Continue Anyway only if you fully trust this website.</div></div></div>
            <div class="actions"><button class="back" id="ng-back" type="button">← Go Back to Safety</button><button class="continue" id="ng-continue" type="button">Continue Anyway</button></div>
            <div class="foot">NETGUARD PRO v3.5 · NETWORK &amp; CLOUD SECURITY</div>
          </div>
        </div>
      </section>`;

    document.documentElement.setAttribute('data-netguard-warning-active', 'true');
    document.documentElement.append(pageStyle, host);

    let hostname = 'Unknown website';
    try { hostname = new URL(window.location.href).hostname || window.location.href; } catch { /* keep fallback */ }
    shadow.getElementById('ng-domain').textContent = hostname;
    shadow.getElementById('ng-warning-title').textContent = finding.label || 'Unsafe website detected';
    shadow.getElementById('ng-warning-reason').textContent =
      `NetGuard recommends that you do not continue. ${finding.reason || 'High-risk security signals were detected on this page.'}`;
    shadow.getElementById('ng-severity').textContent = `RISK: ${String(finding.severity || 'high').toUpperCase()}`;
    shadow.getElementById('ng-layer').textContent = finding.layer || 'Security Analysis';
    shadow.getElementById('ng-score').textContent = `RISK SCORE: ${Number(finding.score) || 85}/100`;

    const countdown = shadow.getElementById('ng-countdown');
    const seconds = shadow.getElementById('ng-seconds');
    const backButton = shadow.getElementById('ng-back');
    const continueButton = shadow.getElementById('ng-continue');
    const deadline = Date.now() + 10000;
    let returning = false;

    function decisionPayload(action) {
      return {
        type: 'UNSAFE_WARNING_DECISION',
        action,
        url: window.location.href,
        finding: {
          category: finding.category,
          severity: finding.severity,
          label: finding.label,
          reason: finding.reason,
          layer: finding.layer,
        },
      };
    }

    function cleanup() {
      if (warningTimer) clearInterval(warningTimer);
      warningTimer = null;
      document.removeEventListener('keydown', onKeydown, true);
      document.documentElement.removeAttribute('data-netguard-warning-active');
      pageStyle.remove();
      host.remove();
      warningShown = false;
      warningDismissedForPage = true;
      dismissActiveWarning = null;
    }

    dismissActiveWarning = cleanup;

    function returnToSafety(action) {
      if (returning) return;
      returning = true;
      if (warningTimer) clearInterval(warningTimer);
      warningTimer = null;
      backButton.disabled = true;
      continueButton.disabled = true;
      backButton.textContent = 'Returning to safety…';
      chrome.runtime.sendMessage(decisionPayload(action));
    }

    function onKeydown(event) {
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopImmediatePropagation();
        returnToSafety('back');
      }
    }

    continueButton.addEventListener('click', () => {
      chrome.runtime.sendMessage(decisionPayload('continue'));
      cleanup();
    });
    backButton.addEventListener('click', () => returnToSafety('back'));
    document.addEventListener('keydown', onKeydown, true);
    backButton.focus();

    warningTimer = setInterval(() => {
      const remaining = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
      countdown.textContent = String(remaining);
      seconds.textContent = `${remaining} second${remaining === 1 ? '' : 's'}`;
      if (remaining === 0) returnToSafety('auto-back');
    }, 200);

    if (source === 'url') {
      chrome.runtime.sendMessage({
        type: 'UNSAFE_PAGE_WARNING',
        url: window.location.href,
        finding,
      });
    }
  }

  function inspectCurrentUrl() {
    const finding = NETGUARD_RISK_ENGINE.analyzeUrl(window.location.href);
    if (finding.status === 'danger') showUnsafeWarning(finding, 'url');
  }

  function sendThreat(category, detail) {
    const key = `${category}:${detail}`;
    if (sentThreats.has(key)) return;
    sentThreats.add(key);
    threatCount++;
    chrome.runtime.sendMessage({ type: 'THREAT', category, detail, url: window.location.href });
    if (USER_WARNING_CATEGORIES.has(category)) {
      showUnsafeWarning(contentThreatFinding(category, detail), 'content');
    }
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
        try {
          const delay = Number.parseInt(content.split(';')[0], 10) || 0;
          const target = new URL(urlMatch[1].trim().replace(/^['"]|['"]$/g, ''), window.location.href);
          if (target.origin !== window.location.origin && delay <= 5) {
            sendThreat('suspicious-redirect',
              `Fast cross-origin redirect detected at ${window.location.hostname} → ${target.hostname}`);
          }
        } catch { /* malformed redirect is ignored */ }
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
      if (!protectionEnabled && dismissActiveWarning) dismissActiveWarning();
    }
  });

  chrome.storage.local.get('protectionEnabled', (data) => {
    protectionEnabled = data.protectionEnabled !== false;
    if (protectionEnabled) inspectCurrentUrl();
  });

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', runWhenEnabled, { once: true });
  else runWhenEnabled();

  setTimeout(runWhenEnabled, 2000);
  setTimeout(runWhenEnabled, 5000);

})();
