(function netGuardSiteSdk() {
  'use strict';

  var script = document.currentScript || Array.from(document.scripts).find(function (item) {
    return item.src && item.src.indexOf('/api/site/sdk.js') !== -1;
  });
  if (!script || !script.dataset.netguardKey || window.__NETGUARD_SITE_SDK__) return;
  window.__NETGUARD_SITE_SDK__ = true;

  var key = script.dataset.netguardKey;
  var apiBase = new URL(script.src, window.location.href).origin;
  var approvedForms = new WeakSet();
  var config = null;
  var visitorId = getVisitorId();

  function getVisitorId() {
    var storageKey = 'netguard_visitor_id';
    try {
      var existing = sessionStorage.getItem(storageKey);
      if (existing) return existing;
      var value = crypto.randomUUID ? crypto.randomUUID() : Array.from(crypto.getRandomValues(new Uint8Array(16))).map(function (byte) {
        return byte.toString(16).padStart(2, '0');
      }).join('');
      sessionStorage.setItem(storageKey, value);
      return value;
    } catch (_) {
      return 'session-' + Math.random().toString(36).slice(2);
    }
  }

  function routeOnly() {
    return String(window.location.pathname || '/').slice(0, 300);
  }

  function botSignals() {
    return {
      webdriver: navigator.webdriver === true,
      hidden: document.visibilityState === 'hidden',
    };
  }

  async function sha256(value) {
    var bytes = new TextEncoder().encode(value);
    var digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest)).map(function (byte) {
      return byte.toString(16).padStart(2, '0');
    }).join('');
  }

  async function formDigest(form) {
    var values = [];
    new FormData(form).forEach(function (value, name) {
      var lower = String(name).toLowerCase();
      if (typeof value !== 'string' || /pass|token|secret|key|auth|cookie|session/.test(lower)) return;
      values.push(lower + '=' + value.trim().replace(/\s+/g, ' ').slice(0, 200));
    });
    values.sort();
    return values.length ? sha256(values.join('&')) : '';
  }

  async function requestJson(path, body) {
    var response = await fetch(apiBase + path, {
      method: body ? 'POST' : 'GET',
      mode: 'cors',
      credentials: 'omit',
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    var payload = await response.json().catch(function () { return {}; });
    if (!response.ok && !payload.action) throw new Error(payload.message || 'NetGuard request failed');
    return payload;
  }

  function sendEvent(eventType, extra) {
    if (!config || !config.protectionEnabled) return Promise.resolve({ action: 'allowed' });
    return requestJson('/api/site/event/' + encodeURIComponent(key), Object.assign({
      eventType: eventType,
      visitorId: visitorId,
      route: routeOnly(),
      signals: botSignals(),
    }, extra || {}));
  }

  function notice(message, danger) {
    var old = document.getElementById('netguard-security-notice');
    if (old) old.remove();
    var box = document.createElement('div');
    box.id = 'netguard-security-notice';
    box.setAttribute('role', 'alert');
    box.style.cssText = 'position:fixed;right:20px;bottom:20px;z-index:2147483647;max-width:360px;padding:14px 16px;border-radius:10px;color:#fff;font:14px/1.45 system-ui,sans-serif;box-shadow:0 12px 40px rgba(0,0,0,.35);background:' + (danger ? '#9f1239' : '#1e3a8a');
    box.textContent = message;
    document.body.appendChild(box);
    setTimeout(function () { box.remove(); }, 7000);
  }

  function resumeForm(form, submitter) {
    approvedForms.add(form);
    if (typeof form.requestSubmit === 'function') form.requestSubmit(submitter || undefined);
    else HTMLFormElement.prototype.submit.call(form);
  }

  function loadRecaptcha(siteKey) {
    if (window.grecaptcha) return Promise.resolve(window.grecaptcha);
    return new Promise(function (resolve, reject) {
      var loader = document.createElement('script');
      loader.src = 'https://www.google.com/recaptcha/api.js?render=' + encodeURIComponent(siteKey);
      loader.async = true;
      loader.onload = function () { resolve(window.grecaptcha); };
      loader.onerror = function () { reject(new Error('reCAPTCHA could not load')); };
      document.head.appendChild(loader);
    });
  }

  async function solveChallenge(form, submitter) {
    if (!config.recaptcha.enabled || !config.recaptcha.siteKey) {
      notice('NetGuard blocked a suspicious repeated request. Please wait and try again.', true);
      return;
    }
    try {
      var recaptcha = await loadRecaptcha(config.recaptcha.siteKey);
      var token = await new Promise(function (resolve, reject) {
        recaptcha.ready(function () {
          recaptcha.execute(config.recaptcha.siteKey, { action: 'netguard_form' }).then(resolve).catch(reject);
        });
      });
      var result = await requestJson('/api/site/challenge/' + encodeURIComponent(key), {
        token: token,
        visitorId: visitorId,
        route: routeOnly(),
      });
      if (result.success) {
        notice('NetGuard verification passed. Your request can continue.', false);
        resumeForm(form, submitter);
      } else {
        notice('NetGuard verification failed. The request was not sent.', true);
      }
    } catch (_) {
      notice('NetGuard could not verify this request. Please wait and try again.', true);
    }
  }

  async function protectForm(event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement) || form.hasAttribute('data-netguard-ignore')) return;
    if (approvedForms.has(form)) {
      approvedForms.delete(form);
      return;
    }
    if (!config || !config.protectionEnabled || (!config.settings.formShieldEnabled && !config.settings.rateLimitEnabled)) return;

    event.preventDefault();
    var submitter = event.submitter;
    try {
      var messageHash = await formDigest(form);
      var result = await sendEvent('form-submit', { messageHash: messageHash });
      if (result.action === 'allowed') return resumeForm(form, submitter);
      if (result.action === 'challenged') return solveChallenge(form, submitter);
      if (result.action === 'throttled') {
        notice('NetGuard detected repeated requests. Please wait ' + (result.retryAfterSeconds || 5) + ' seconds and try again.', true);
        return;
      }
      notice('NetGuard temporarily blocked this request pattern to protect the website.', true);
    } catch (_) {
      // Fail open for availability; the protected site's own backend/WAF remains authoritative.
      resumeForm(form, submitter);
    }
  }

  async function start() {
    try {
      var response = await requestJson('/api/site/config/' + encodeURIComponent(key));
      config = response.data;
      if (!config.protectionEnabled) return;
      var navigation = performance.getEntriesByType && performance.getEntriesByType('navigation')[0];
      if (config.settings.telemetryEnabled) {
        sendEvent('page-view', { loadMs: navigation ? Math.round(navigation.duration) : null }).catch(function () {});
      }
      document.addEventListener('submit', protectForm, true);

      if (config.settings.clientErrorMonitoring) {
        window.addEventListener('error', function (event) {
          sha256(String(event.message || 'client-error').slice(0, 300)).then(function (messageHash) {
            sendEvent('client-error', { messageHash: messageHash }).catch(function () {});
          });
        });
      }
      setInterval(function () { sendEvent('heartbeat').catch(function () {}); }, 5 * 60 * 1000);
    } catch (error) {
      console.warn('[NetGuard] Site protection could not connect:', error.message);
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
}());
