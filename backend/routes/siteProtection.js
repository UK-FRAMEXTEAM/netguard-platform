const path = require('path');
const express = require('express');
const rateLimit = require('express-rate-limit');
const ProtectedSite = require('../models/ProtectedSite');
const SiteSecurityEvent = require('../models/SiteSecurityEvent');
const SiteVisitorState = require('../models/SiteVisitorState');
const {
  requestOrigin,
  originMatchesSite,
  hashIdentifier,
  safeDeviceFamily,
  protectionDecision,
} = require('../lib/siteProtection');
const { settingsForProfile } = require('../lib/siteProfiles');
const { queueAutomaticScan } = require('../lib/siteAutomation');

const router = express.Router();
const EVENT_TYPES = new Set(['page-view', 'heartbeat', 'form-submit', 'client-error', 'bot-signal']);
const RATE_EVENT_TYPES = ['page-view', 'form-submit', 'client-error', 'bot-signal'];

router.use((req, res, next) => {
  const origin = String(req.get('origin') || '').trim();
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '600');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const ingressLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: process.env.NODE_ENV === 'production' ? 240 : 1000,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { success: false, action: 'throttled', message: 'NetGuard telemetry rate limit reached.' },
});
router.use(ingressLimiter);

function publicSettings(site) {
  const raw = site.protectionSettings?.toObject?.() || site.protectionSettings || {};
  const settings = settingsForProfile(site.protectionProfile, raw);
  return {
    telemetryEnabled: settings.telemetryEnabled,
    rateLimitEnabled: settings.rateLimitEnabled,
    repeatProtectionEnabled: settings.repeatProtectionEnabled,
    botDetectionEnabled: settings.botDetectionEnabled,
    formShieldEnabled: settings.formShieldEnabled,
    recaptchaEnabled: settings.recaptchaEnabled,
    clientErrorMonitoring: settings.clientErrorMonitoring,
    autoBlockEnabled: settings.autoBlockEnabled,
    repeatWindowSeconds: settings.repeatWindowSeconds,
    repeatMaxSubmissions: settings.repeatMaxSubmissions,
    burstWindowSeconds: settings.burstWindowSeconds,
    burstMaxRequests: settings.burstMaxRequests,
    minuteMaxRequests: settings.minuteMaxRequests,
    blockMinutes: settings.blockMinutes,
  };
}

async function loadSite(req, res, next) {
  try {
    const code = String(req.params.code || '').trim();
    if (!/^netguard_[a-z0-9_-]{12,80}$/i.test(code)) {
      return res.status(404).json({ success: false, message: 'Protected site was not found.' });
    }
    const site = await ProtectedSite.findOne({ protectionCode: code });
    if (!site) return res.status(404).json({ success: false, message: 'Protected site was not found.' });
    const origin = requestOrigin(req);
    if (!originMatchesSite(origin, site)) {
      return res.status(403).json({ success: false, message: 'This protection code is not valid for the requesting origin.' });
    }
    req.protectedSite = site;
    req.siteOrigin = origin;
    next();
  } catch (error) {
    console.error('[site-protection] Site lookup failed:', error.message);
    res.status(500).json({ success: false, message: 'Could not validate protected site.' });
  }
}

function cleanRoute(value) {
  const route = String(value || '/').trim().slice(0, 300);
  return route.startsWith('/') && !route.includes('?') && !route.includes('#') ? route : '/';
}

function eventExpiry() {
  const days = Math.min(730, Math.max(7, Number(process.env.SITE_EVENT_RETENTION_DAYS) || 180));
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
}

function stateExpiry() {
  return new Date(Date.now() + 24 * 60 * 60 * 1000);
}

async function updateVisitorState(filter, update) {
  try {
    return await SiteVisitorState.findOneAndUpdate(filter, update, { upsert: true, setDefaultsOnInsert: true });
  } catch (error) {
    // Two simultaneous first requests can race on the unique visitor-state key.
    if (error.code !== 11000) throw error;
    return SiteVisitorState.findOneAndUpdate(filter, update, { upsert: false });
  }
}

async function refreshScore(siteId) {
  const site = await ProtectedSite.findById(siteId).select('counters threatsDetected integrationStatus');
  if (!site) return;
  const counters = site.counters || {};
  const penalty = Math.min(70,
    (Number(counters.blocked) || 0) * 3 +
    (Number(counters.challenged) || 0) +
    (Number(counters.recaptchaFailed) || 0) * 2
  );
  site.securityScore = Math.max(0, 100 - penalty);
  await site.save();
}

router.get('/sdk.js', (_req, res) => {
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.sendFile(path.join(__dirname, '..', 'public', 'netguard-site-sdk.js'));
});

router.get('/config/:code', loadSite, async (req, res) => {
  const site = req.protectedSite;
  site.normalizedOrigin = site.normalizedOrigin || req.siteOrigin;
  site.integrationStatus = 'connected';
  site.lastHeartbeat = new Date();
  await site.save();
  queueAutomaticScan(site);

  const settings = publicSettings(site);
  const recaptchaAvailable = Boolean(process.env.RECAPTCHA_SITE_KEY && process.env.RECAPTCHA_SECRET_KEY);
  res.json({
    success: true,
    data: {
      siteName: site.siteName,
      protectionEnabled: site.isActive,
      settings,
      recaptcha: {
        enabled: Boolean(settings.recaptchaEnabled && recaptchaAvailable),
        siteKey: settings.recaptchaEnabled && recaptchaAvailable ? process.env.RECAPTCHA_SITE_KEY : '',
      },
      privacy: 'Raw IP addresses, MAC addresses, form values, paths with queries, and screenshot data are not stored.',
    },
  });
});

router.post('/event/:code', loadSite, async (req, res) => {
  try {
    const site = req.protectedSite;
    const settings = publicSettings(site);
    if (!site.isActive) {
      return res.json({ success: true, action: 'allowed', protectionEnabled: false });
    }
    queueAutomaticScan(site);

    const eventType = EVENT_TYPES.has(req.body.eventType) ? req.body.eventType : 'page-view';
    if (!settings.telemetryEnabled && ['page-view', 'heartbeat', 'client-error'].includes(eventType)) {
      await ProtectedSite.findByIdAndUpdate(site._id, {
        $set: { integrationStatus: 'connected', lastHeartbeat: new Date() },
      });
      return res.json({ success: true, action: 'allowed', protectionEnabled: true, telemetryStored: false });
    }
    const visitorId = String(req.body.visitorId || '').replace(/[^a-z0-9_-]/gi, '').slice(0, 80);
    const clientMessageHash = /^[a-f0-9]{64}$/i.test(String(req.body.messageHash || ''))
      ? String(req.body.messageHash).toLowerCase()
      : '';
    const ipHash = hashIdentifier(`site:${site._id}:ip`, req.ip);
    const visitorHash = hashIdentifier(`site:${site._id}:visitor`, `${visitorId}:${req.get('user-agent') || ''}`);
    const messageHash = clientMessageHash
      ? hashIdentifier(`site:${site._id}:message`, clientMessageHash)
      : '';
    const botSignal = Boolean(req.body.signals?.webdriver) || safeDeviceFamily(req.get('user-agent')) === 'Bot';
    const now = new Date();
    const repeatStart = new Date(now.getTime() - settings.repeatWindowSeconds * 1000);
    const burstStart = new Date(now.getTime() - settings.burstWindowSeconds * 1000);
    const minuteStart = new Date(now.getTime() - 60 * 1000);

    const stateFilter = { siteId: site._id, ipHash, visitorHash };
    const [state, burstPrevious, minutePrevious, repeatPrevious] = await Promise.all([
      SiteVisitorState.findOne(stateFilter).lean(),
      SiteSecurityEvent.countDocuments({ siteId: site._id, ipHash, eventType: { $in: RATE_EVENT_TYPES }, createdAt: { $gte: burstStart } }),
      SiteSecurityEvent.countDocuments({ siteId: site._id, ipHash, eventType: { $in: RATE_EVENT_TYPES }, createdAt: { $gte: minuteStart } }),
      messageHash ? SiteSecurityEvent.countDocuments({ siteId: site._id, ipHash, messageHash, eventType: 'form-submit', createdAt: { $gte: repeatStart } }) : 0,
    ]);

    const counts = {
      burst: burstPrevious + (RATE_EVENT_TYPES.includes(eventType) ? 1 : 0),
      minute: minutePrevious + (RATE_EVENT_TYPES.includes(eventType) ? 1 : 0),
      repeat: repeatPrevious + (eventType === 'form-submit' && messageHash ? 1 : 0),
    };
    const recaptchaAvailable = Boolean(process.env.RECAPTCHA_SITE_KEY && process.env.RECAPTCHA_SECRET_KEY);
    const decision = protectionDecision({
      settings,
      counts,
      state,
      event: { messageHash, botSignal },
      recaptchaAvailable,
      now,
    });

    const severity = eventType === 'client-error' && decision.action === 'allowed' ? 'low' : decision.severity;
    const category = eventType === 'client-error' && decision.category === 'normal' ? 'client-error' : decision.category;
    await SiteSecurityEvent.create({
      userId: site.userId,
      siteId: site._id,
      eventType,
      category,
      severity,
      action: decision.action,
      ipHash,
      visitorHash,
      messageHash,
      route: cleanRoute(req.body.route),
      deviceFamily: safeDeviceFamily(req.get('user-agent')),
      loadMs: Number.isFinite(Number(req.body.loadMs)) ? Math.min(300000, Math.max(0, Number(req.body.loadMs))) : null,
      repeatCount: counts.repeat,
      burstCount: counts.burst,
      minuteCount: counts.minute,
      expireAt: eventExpiry(),
    });

    const stateUpdate = {
      $set: {
        lastSeenAt: now,
        expireAt: stateExpiry(),
        challengeRequired: decision.action === 'challenged',
      },
    };
    if (decision.action === 'blocked') {
      stateUpdate.$set.blockedUntil = new Date(now.getTime() + settings.blockMinutes * 60 * 1000);
    }
    await updateVisitorState(stateFilter, stateUpdate);

    const counterKey = decision.action === 'allowed' ? 'allowed' : decision.action;
    const increments = {
      'counters.monitoredEvents': 1,
      [`counters.${counterKey}`]: 1,
    };
    if (decision.action !== 'allowed' || eventType === 'client-error' || botSignal) increments.threatsDetected = 1;
    await ProtectedSite.findByIdAndUpdate(site._id, {
      $inc: increments,
      $set: {
        integrationStatus: 'connected',
        lastHeartbeat: now,
        lastEventAt: now,
        lastScanned: now,
        hasSSL: req.siteOrigin.startsWith('https://'),
      },
    });
    if (decision.action !== 'allowed') refreshScore(site._id).catch(() => {});

    res.status(decision.action === 'blocked' ? 429 : 200).json({
      success: decision.action !== 'blocked',
      action: decision.action,
      reason: decision.reason,
      retryAfterSeconds: decision.action === 'throttled' ? settings.burstWindowSeconds : 0,
      challenge: decision.action === 'challenged',
    });
  } catch (error) {
    console.error('[site-protection] Event failed:', error.message);
    res.status(500).json({ success: false, action: 'throttled', message: 'Protection check could not be completed.' });
  }
});

router.post('/challenge/:code', loadSite, async (req, res) => {
  try {
    if (!process.env.RECAPTCHA_SITE_KEY || !process.env.RECAPTCHA_SECRET_KEY) {
      return res.status(503).json({ success: false, message: 'reCAPTCHA is not configured on the NetGuard backend.' });
    }
    const site = req.protectedSite;
    const token = String(req.body.token || '').slice(0, 5000);
    const visitorId = String(req.body.visitorId || '').replace(/[^a-z0-9_-]/gi, '').slice(0, 80);
    if (!token) return res.status(400).json({ success: false, message: 'A reCAPTCHA token is required.' });

    const verification = new URLSearchParams({
      secret: process.env.RECAPTCHA_SECRET_KEY,
      response: token,
    });
    const upstream = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: verification,
      signal: AbortSignal.timeout(10000),
    });
    const result = await upstream.json();
    const expectedHostname = new URL(site.siteUrl).hostname;
    const hostnameMatches = !result.hostname || result.hostname === expectedHostname;
    const scorePasses = result.score === undefined || Number(result.score) >= 0.5;
    const actionMatches = !result.action || result.action === 'netguard_form';
    const passed = Boolean(result.success && hostnameMatches && scorePasses && actionMatches);

    const ipHash = hashIdentifier(`site:${site._id}:ip`, req.ip);
    const visitorHash = hashIdentifier(`site:${site._id}:visitor`, `${visitorId}:${req.get('user-agent') || ''}`);
    const stateFilter = { siteId: site._id, ipHash, visitorHash };
    const now = new Date();
    const state = await SiteVisitorState.findOne(stateFilter).lean();
    const failures = passed ? 0 : (state?.challengeFailures || 0) + 1;
    const activeExistingBlock = state?.blockedUntil && new Date(state.blockedUntil) > now
      ? state.blockedUntil
      : null;
    const blockedUntil = !passed && failures >= 3
      ? new Date(now.getTime() + publicSettings(site).blockMinutes * 60 * 1000)
      : activeExistingBlock;

    await updateVisitorState(stateFilter, {
      $set: {
        challengeRequired: !passed,
        challengeFailures: failures,
        verifiedUntil: passed ? new Date(now.getTime() + 10 * 60 * 1000) : null,
        blockedUntil,
        lastSeenAt: now,
        expireAt: stateExpiry(),
      },
    });

    await SiteSecurityEvent.create({
      userId: site.userId,
      siteId: site._id,
      eventType: 'recaptcha',
      category: 'challenge',
      severity: passed ? 'info' : 'high',
      action: passed ? 'passed' : 'failed',
      ipHash,
      visitorHash,
      route: cleanRoute(req.body.route),
      deviceFamily: safeDeviceFamily(req.get('user-agent')),
      expireAt: eventExpiry(),
    });
    await ProtectedSite.findByIdAndUpdate(site._id, {
      $inc: { [`counters.${passed ? 'recaptchaPassed' : 'recaptchaFailed'}`]: 1 },
      $set: { lastEventAt: now, lastHeartbeat: now, integrationStatus: 'connected' },
    });
    if (!passed) refreshScore(site._id).catch(() => {});

    res.status(passed ? 200 : 403).json({
      success: passed,
      action: passed ? 'allowed' : blockedUntil ? 'blocked' : 'challenged',
      message: passed ? 'Visitor verification passed.' : 'Visitor verification failed.',
    });
  } catch (error) {
    console.error('[site-protection] reCAPTCHA verification failed:', error.message);
    res.status(502).json({ success: false, message: 'reCAPTCHA verification service is unavailable.' });
  }
});

module.exports = router;
