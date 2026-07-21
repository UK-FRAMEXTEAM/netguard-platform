const crypto = require('crypto');

function normalizeSiteUrl(value) {
  let parsed;
  try {
    parsed = new URL(String(value || '').trim());
  } catch {
    throw new Error('Enter a valid website URL');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Only HTTP and HTTPS websites are supported');
  }
  if (process.env.NODE_ENV === 'production' && parsed.protocol !== 'https:') {
    throw new Error('Production protected sites must use HTTPS');
  }
  parsed.username = '';
  parsed.password = '';
  parsed.pathname = '/';
  parsed.search = '';
  parsed.hash = '';
  return { siteUrl: parsed.href, normalizedOrigin: parsed.origin };
}

function requestOrigin(req) {
  const direct = String(req.get('origin') || '').trim();
  if (direct) return direct.replace(/\/$/, '');
  const referer = String(req.get('referer') || '').trim();
  if (!referer) return '';
  try { return new URL(referer).origin; } catch { return ''; }
}

function originMatchesSite(origin, site) {
  if (!origin) return false;
  let expected = site.normalizedOrigin;
  if (!expected) {
    try { expected = new URL(site.siteUrl).origin; } catch { return false; }
  }
  return origin.replace(/\/$/, '') === expected.replace(/\/$/, '');
}

function hashIdentifier(namespace, value) {
  return crypto
    .createHmac('sha256', process.env.JWT_SECRET)
    .update(`${namespace}:${String(value || '')}`)
    .digest('hex');
}

function safeDeviceFamily(userAgent) {
  const ua = String(userAgent || '').toLowerCase();
  if (/bot|crawler|spider|headless/.test(ua)) return 'Bot';
  if (/edg\//.test(ua)) return 'Edge';
  if (/firefox\//.test(ua)) return 'Firefox';
  if (/chrome\//.test(ua)) return 'Chrome';
  if (/safari\//.test(ua)) return 'Safari';
  return 'Other';
}

function protectionDecision({ settings, counts, state, event, recaptchaAvailable, now = new Date() }) {
  if (state?.blockedUntil && new Date(state.blockedUntil) > now) {
    return { action: 'blocked', category: 'request-burst', severity: 'critical', reason: 'Temporary network block is active' };
  }

  const minuteExtreme = settings.rateLimitEnabled && counts.minute >= settings.minuteMaxRequests * 2;
  const burstExtreme = settings.rateLimitEnabled && counts.burst >= settings.burstMaxRequests * 2;
  const repeatExtreme = settings.repeatProtectionEnabled && event.messageHash && counts.repeat >= settings.repeatMaxSubmissions + 2;
  const automation = settings.botDetectionEnabled && Boolean(event.botSignal);
  const extreme = minuteExtreme || burstExtreme || repeatExtreme;

  if (extreme && settings.autoBlockEnabled) {
    const category = repeatExtreme ? 'repeat-submission' : minuteExtreme ? 'minute-rate' : 'request-burst';
    return { action: 'blocked', category, severity: 'critical', reason: 'Automatic temporary block threshold reached' };
  }

  const verified = state?.verifiedUntil && new Date(state.verifiedUntil) > now;
  if (verified && !extreme) {
    return { action: 'allowed', category: 'normal', severity: 'info', reason: 'Recently verified visitor' };
  }

  const repeat = settings.repeatProtectionEnabled && event.messageHash && counts.repeat >= settings.repeatMaxSubmissions;
  const burst = settings.rateLimitEnabled && counts.burst >= settings.burstMaxRequests;
  const minute = settings.rateLimitEnabled && counts.minute >= settings.minuteMaxRequests;
  const suspicious = repeat || burst || minute || automation;
  const category = repeat ? 'repeat-submission' : burst ? 'request-burst' : minute ? 'minute-rate' : automation ? 'automation' : 'normal';

  if (suspicious && settings.recaptchaEnabled && recaptchaAvailable) {
    return { action: 'challenged', category, severity: 'high', reason: 'Suspicious request pattern requires reCAPTCHA verification' };
  }
  if (suspicious) {
    return { action: 'throttled', category, severity: 'medium', reason: 'Suspicious request pattern was throttled' };
  }
  return { action: 'allowed', category: 'normal', severity: 'info', reason: 'Request pattern is within configured limits' };
}

module.exports = {
  normalizeSiteUrl,
  requestOrigin,
  originMatchesSite,
  hashIdentifier,
  safeDeviceFamily,
  protectionDecision,
};
