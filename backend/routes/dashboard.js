// ───────────────────────────────────────────────────────────
//  NetGuard Cloud Platform – Dashboard Routes
// ───────────────────────────────────────────────────────────
const express = require('express');
const router = express.Router();
const Threat = require('../models/Threat');
const ProtectedSite = require('../models/ProtectedSite');
const BrowsingActivity = require('../models/BrowsingActivity');
const SiteSecurityEvent = require('../models/SiteSecurityEvent');
const { authenticate, isAdmin } = require('../middleware/auth');
const { normalizeSiteUrl } = require('../lib/siteProtection');
const {
  SITE_BOOLEAN_SETTINGS,
  normalizeProfile,
  sanitizeSiteSettings,
  settingsForProfile,
} = require('../lib/siteProfiles');
const { runStoredWebsiteScan } = require('../lib/siteAutomation');
const crypto = require('crypto');

function siteConnectionStatus(site) {
  if (!site.lastHeartbeat) return 'pending';
  return Date.now() - new Date(site.lastHeartbeat).getTime() <= 15 * 60 * 1000 ? 'connected' : 'offline';
}

function siteView(site) {
  const value = site.toObject ? site.toObject() : site;
  const integrationStatus = siteConnectionStatus(value);
  const protectionSettings = settingsForProfile(value.protectionProfile, value.protectionSettings);
  const enabledLayerCount = SITE_BOOLEAN_SETTINGS
    .filter((key) => key !== 'autoPostureScanEnabled' && protectionSettings[key])
    .length;
  return {
    ...value,
    protectionSettings,
    integrationStatus,
    setupStatus: integrationStatus === 'connected' && value.isActive
      ? 'protected'
      : integrationStatus === 'offline'
        ? 'offline'
        : 'integration-required',
    protectionRunning: Boolean(value.isActive && integrationStatus === 'connected'),
    enabledLayerCount,
    recaptchaAvailable: Boolean(process.env.RECAPTCHA_SITE_KEY && process.env.RECAPTCHA_SECRET_KEY),
  };
}

// Get dashboard overview stats
router.get('/overview', authenticate, async (req, res) => {
  try {
    const userId = req.user._id;
    const now = new Date();
    const last24h = new Date(now - 24 * 60 * 60 * 1000);
    const last7d = new Date(now - 7 * 24 * 60 * 60 * 1000);
    const last30d = new Date(now - 30 * 24 * 60 * 60 * 1000);

    // Threat counts
    const [totalThreats, threats24h, threats7d, threatsByCategory, threatsBySeverity] = await Promise.all([
      Threat.countDocuments({ userId }),
      Threat.countDocuments({ userId, createdAt: { $gte: last24h } }),
      Threat.countDocuments({ userId, createdAt: { $gte: last7d } }),
      Threat.aggregate([
        { $match: { userId: userId } },
        { $group: { _id: '$category', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
      Threat.aggregate([
        { $match: { userId: userId } },
        { $group: { _id: '$severity', count: { $sum: 1 } } },
      ]),
    ]);

    // Recent threats (last 10)
    const recentThreats = await Threat.find({ userId })
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();

    // Protected sites
    const connectedSince = new Date(now - 15 * 60 * 1000);
    const protectedSites = await ProtectedSite.find({ userId, isActive: true, lastHeartbeat: { $gte: connectedSince } })
      .sort({ createdAt: -1 })
      .lean();

    // Threat trend (daily for last 7 days)
    const trendData = await Threat.aggregate([
      {
        $match: {
          userId,
          createdAt: { $gte: last7d },
        },
      },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          count: { $sum: 1 },
          blocked: { $sum: { $cond: [{ $in: ['$action', ['blocked', 'auto-returned']] }, 1, 0] } },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    res.json({
      success: true,
      data: {
        totalThreats,
        threats24h,
        threats7d,
        threatsByCategory,
        threatsBySeverity,
        recentThreats,
        protectedSites,
        trendData,
        userStats: req.user.stats,
        protectionCode: req.user.protectionCode,
        settings: req.user.settings,
      },
    });
  } catch (error) {
    console.error('Dashboard overview error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get threats list (paginated)
router.get('/threats', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const category = req.query.category;
    const severity = req.query.severity;

    const filter = { userId: req.user._id };
    if (category) filter.category = category;
    if (severity) filter.severity = severity;

    const [threats, total] = await Promise.all([
      Threat.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Threat.countDocuments(filter),
    ]);

    res.json({
      success: true,
      data: {
        threats,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
        },
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get protected sites
router.get('/sites', authenticate, async (req, res) => {
  try {
    const sites = await ProtectedSite.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .lean();
    res.json({ success: true, data: sites.map(siteView) });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Add a protected site
router.post('/sites', authenticate, async (req, res) => {
  try {
    const { siteUrl, siteName, protectionSettings: incomingSettings } = req.body;
    if (!siteUrl) {
      return res.status(400).json({ success: false, message: 'Site URL required' });
    }

    const normalized = normalizeSiteUrl(siteUrl);
    const existing = await ProtectedSite.findOne({
      userId: req.user._id,
      normalizedOrigin: normalized.normalizedOrigin,
    });
    if (existing) {
      return res.status(409).json({ success: false, message: 'This website is already registered.' });
    }
    const code = `netguard_${crypto.randomBytes(18).toString('base64url').toLowerCase()}`;
    const protectionProfile = normalizeProfile(req.body.protectionProfile);
    const protectionSettings = settingsForProfile(protectionProfile, incomingSettings);

    let site = await ProtectedSite.create({
      userId: req.user._id,
      siteUrl: normalized.siteUrl,
      normalizedOrigin: normalized.normalizedOrigin,
      siteName: String(siteName || normalized.normalizedOrigin).trim().slice(0, 120),
      protectionCode: code,
      protectionProfile,
      protectionSettings,
      isActive: req.body.isActive !== false,
      hasSSL: normalized.siteUrl.startsWith('https'),
      integrationStatus: 'pending',
    });

    // Add to user's protected sites
    req.user.protectedSites.push({
      url: normalized.siteUrl,
      code,
      isActive: site.isActive,
    });
    await req.user.save();

    let initialScan = { ok: true, skipped: true };
    if (site.protectionSettings.autoPostureScanEnabled !== false) {
      initialScan = await runStoredWebsiteScan(site, { force: true, source: 'registration' });
      site = initialScan.site || site;
    }

    res.json({
      success: true,
      data: siteView(site),
      automation: {
        initialScanCompleted: Boolean(initialScan.ok && !initialScan.skipped),
        initialScanFailed: !initialScan.ok,
        message: initialScan.message || '',
      },
    });
  } catch (error) {
    const status = /valid website|supported|must use HTTPS/i.test(error.message) ? 400 : 500;
    res.status(status).json({ success: false, message: status === 400 ? error.message : 'Server error' });
  }
});

// Enable/disable a site and configure real protection thresholds.
router.patch('/sites/:siteId', authenticate, async (req, res) => {
  try {
    const site = await ProtectedSite.findOne({ _id: req.params.siteId, userId: req.user._id });
    if (!site) return res.status(404).json({ success: false, message: 'Protected site was not found.' });

    if (typeof req.body.isActive === 'boolean') site.isActive = req.body.isActive;
    if (typeof req.body.siteName === 'string' && req.body.siteName.trim()) {
      site.siteName = req.body.siteName.trim().slice(0, 120);
    }
    const requestedProfile = req.body.protectionProfile === undefined
      ? site.protectionProfile
      : normalizeProfile(req.body.protectionProfile);
    if (req.body.protectionProfile !== undefined) site.protectionProfile = requestedProfile;
    const incoming = req.body.protectionSettings;
    if (incoming && typeof incoming === 'object') {
      const current = site.protectionSettings?.toObject?.() || site.protectionSettings || {};
      const base = req.body.protectionProfile && requestedProfile !== 'custom'
        ? settingsForProfile(requestedProfile)
        : sanitizeSiteSettings(current);
      site.protectionSettings = sanitizeSiteSettings(incoming, base);
    }
    site.updatedAt = new Date();
    await site.save();
    if (typeof req.body.isActive === 'boolean') {
      const legacySite = req.user.protectedSites?.find((entry) => entry.code === site.protectionCode);
      if (legacySite) {
        legacySite.isActive = site.isActive;
        await req.user.save();
      }
    }
    res.json({ success: true, data: siteView(site) });
  } catch (error) {
    console.error('Protected site settings error:', error.message);
    res.status(500).json({ success: false, message: 'Could not update website protection.' });
  }
});

// Run a server-side, SSRF-safe public TLS and response-header posture scan.
router.post('/sites/:siteId/network-scan', authenticate, async (req, res) => {
  const site = await ProtectedSite.findOne({ _id: req.params.siteId, userId: req.user._id });
  if (!site) return res.status(404).json({ success: false, message: 'Protected site was not found.' });
  const result = await runStoredWebsiteScan(site, { force: true, source: 'manual' });
  if (!result.ok) return res.status(400).json({ success: false, message: result.message, data: siteView(result.site || site) });
  res.json({ success: true, data: siteView(result.site), scan: result.scan });
});

// Update user settings
router.put('/settings', authenticate, async (req, res) => {
  try {
    const { zeroTrustMode, behavioralDetection, threatIntelEnabled,
            sessionMonitoring, notifications, autoBlock } = req.body;

    req.user.settings = {
      zeroTrustMode: zeroTrustMode ?? req.user.settings.zeroTrustMode,
      behavioralDetection: behavioralDetection ?? req.user.settings.behavioralDetection,
      threatIntelEnabled: threatIntelEnabled ?? req.user.settings.threatIntelEnabled,
      sessionMonitoring: sessionMonitoring ?? req.user.settings.sessionMonitoring,
      notifications: notifications ?? req.user.settings.notifications,
      autoBlock: autoBlock ?? req.user.settings.autoBlock,
    };
    await req.user.save();

    res.json({ success: true, settings: req.user.settings });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Privacy-preserving browsing analytics and security report data.
router.get('/analytics', authenticate, async (req, res) => {
  try {
    const requestedDays = Number.parseInt(req.query.days, 10) || 30;
    const days = Math.min(90, Math.max(7, requestedDays));
    const startDate = new Date();
    startDate.setUTCHours(0, 0, 0, 0);
    startDate.setUTCDate(startDate.getUTCDate() - (days - 1));
    const startDay = startDate.toISOString().slice(0, 10);
    const userId = req.user._id;

    const activityMatch = { userId, day: { $gte: startDay } };
    const threatMatch = { userId, createdAt: { $gte: startDate } };

    const [
      activityTotalsResult,
      dailyActivity,
      topDomains,
      threatTotalsResult,
      threatCategories,
      threatDomains,
      dailyThreats,
      recentThreats,
    ] = await Promise.all([
      BrowsingActivity.aggregate([
        { $match: activityMatch },
        { $group: {
          _id: null,
          totalVisits: { $sum: '$visits' },
          secureVisits: { $sum: '$secureVisits' },
          insecureVisits: { $sum: '$insecureVisits' },
          domains: { $addToSet: '$domain' },
        } },
      ]),
      BrowsingActivity.aggregate([
        { $match: activityMatch },
        { $group: {
          _id: '$day',
          visits: { $sum: '$visits' },
          secure: { $sum: '$secureVisits' },
          insecure: { $sum: '$insecureVisits' },
        } },
        { $sort: { _id: 1 } },
      ]),
      BrowsingActivity.aggregate([
        { $match: activityMatch },
        { $group: {
          _id: '$domain',
          visits: { $sum: '$visits' },
          secure: { $sum: '$secureVisits' },
          insecure: { $sum: '$insecureVisits' },
          lastVisitedAt: { $max: '$lastVisitedAt' },
        } },
        { $sort: { visits: -1 } },
        { $limit: 25 },
      ]),
      Threat.aggregate([
        { $match: threatMatch },
        { $group: {
          _id: null,
          total: { $sum: 1 },
          blocked: { $sum: { $cond: [{ $in: ['$action', ['blocked', 'auto-returned']] }, 1, 0] } },
          highRisk: { $sum: { $cond: [{ $in: ['$severity', ['high', 'critical']] }, 1, 0] } },
          trackers: { $sum: { $cond: [{ $eq: ['$category', 'tracker'] }, 1, 0] } },
        } },
      ]),
      Threat.aggregate([
        { $match: threatMatch },
        { $group: { _id: '$category', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
      Threat.aggregate([
        { $match: { ...threatMatch, domain: { $ne: '' } } },
        { $group: {
          _id: '$domain',
          threats: { $sum: 1 },
          highRisk: { $sum: { $cond: [{ $in: ['$severity', ['high', 'critical']] }, 1, 0] } },
        } },
      ]),
      Threat.aggregate([
        { $match: threatMatch },
        { $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          threats: { $sum: 1 },
          blocked: { $sum: { $cond: [{ $in: ['$action', ['blocked', 'auto-returned']] }, 1, 0] } },
        } },
        { $sort: { _id: 1 } },
      ]),
      Threat.find(threatMatch).sort({ createdAt: -1 }).limit(10).lean(),
    ]);

    const activityTotals = activityTotalsResult[0] || {
      totalVisits: 0, secureVisits: 0, insecureVisits: 0, domains: [],
    };
    const threatTotals = threatTotalsResult[0] || {
      total: 0, blocked: 0, highRisk: 0, trackers: 0,
    };
    const domainThreatMap = new Map(threatDomains.map((entry) => [entry._id, entry]));
    const domains = topDomains.map((entry) => ({
      domain: entry._id,
      visits: entry.visits,
      secureVisits: entry.secure,
      insecureVisits: entry.insecure,
      threats: domainThreatMap.get(entry._id)?.threats || 0,
      highRiskThreats: domainThreatMap.get(entry._id)?.highRisk || 0,
      lastVisitedAt: entry.lastVisitedAt,
    }));

    const secureRate = activityTotals.totalVisits
      ? (activityTotals.secureVisits / activityTotals.totalVisits) * 100
      : 0;
    const riskPenalty = Math.min(60, (threatTotals.highRisk * 5) + (activityTotals.insecureVisits * 2));
    const securityScore = activityTotals.totalVisits
      ? Math.max(0, Math.min(100, Math.round(secureRate - riskPenalty)))
      : null;

    const recommendations = [];
    if (!activityTotals.totalVisits) recommendations.push('Connect the NetGuard extension and browse normally to build a private domain-level report.');
    if (activityTotals.insecureVisits) recommendations.push(`Avoid or upgrade ${activityTotals.insecureVisits} unencrypted HTTP visit(s) recorded in this period.`);
    if (threatTotals.highRisk) recommendations.push(`Review ${threatTotals.highRisk} high or critical finding(s) and follow the assistant remediation steps.`);
    if (threatTotals.trackers) recommendations.push(`Review tracker-heavy domains and tighten behavioral detection or browser privacy controls.`);
    if (activityTotals.totalVisits && !threatTotals.highRisk && !activityTotals.insecureVisits) recommendations.push('No urgent transport or high-severity issues were found. Keep protection and update checks enabled.');

    res.json({
      success: true,
      data: {
        periodDays: days,
        generatedAt: new Date().toISOString(),
        privacyMode: 'domain-only',
        securityScore,
        totals: {
          visits: activityTotals.totalVisits,
          uniqueDomains: activityTotals.domains.length,
          secureVisits: activityTotals.secureVisits,
          insecureVisits: activityTotals.insecureVisits,
          threats: threatTotals.total,
          blocked: threatTotals.blocked,
          highRisk: threatTotals.highRisk,
          trackers: threatTotals.trackers,
        },
        dailyActivity,
        dailyThreats,
        domains,
        threatCategories,
        recentThreats,
        recommendations,
      },
    });
  } catch (error) {
    console.error('Analytics report error:', error.message);
    res.status(500).json({ success: false, message: 'Could not build the analytics report' });
  }
});

// MongoDB-backed protected website report. IP values are only returned as short,
// non-reversible HMAC labels so the report can show network sources without
// storing or exposing a visitor's raw address.
router.get('/website-report', authenticate, async (req, res) => {
  try {
    const requestedDays = Number.parseInt(req.query.days, 10) || 30;
    const days = Math.min(90, Math.max(7, requestedDays));
    const startDate = new Date();
    startDate.setUTCHours(0, 0, 0, 0);
    startDate.setUTCDate(startDate.getUTCDate() - (days - 1));

    const site = await ProtectedSite.findOne({
      _id: req.query.siteId,
      userId: req.user._id,
    }).lean();
    if (!site) return res.status(404).json({ success: false, message: 'Select a valid protected website.' });

    const match = {
      userId: req.user._id,
      siteId: site._id,
      createdAt: { $gte: startDate },
      eventType: { $ne: 'heartbeat' },
    };
    const [totalsResult, daily, categories, networkSources, recentEvents] = await Promise.all([
      SiteSecurityEvent.aggregate([
        { $match: match },
        { $group: {
          _id: null,
          monitoredEvents: { $sum: 1 },
          visitors: { $addToSet: '$ipHash' },
          allowed: { $sum: { $cond: [{ $eq: ['$action', 'allowed'] }, 1, 0] } },
          challenged: { $sum: { $cond: [{ $eq: ['$action', 'challenged'] }, 1, 0] } },
          throttled: { $sum: { $cond: [{ $eq: ['$action', 'throttled'] }, 1, 0] } },
          blocked: { $sum: { $cond: [{ $eq: ['$action', 'blocked'] }, 1, 0] } },
          recaptchaPassed: { $sum: { $cond: [{ $eq: ['$action', 'passed'] }, 1, 0] } },
          recaptchaFailed: { $sum: { $cond: [{ $eq: ['$action', 'failed'] }, 1, 0] } },
          repeatSubmissions: { $sum: { $cond: [{ $eq: ['$category', 'repeat-submission'] }, 1, 0] } },
          botSignals: { $sum: { $cond: [{ $eq: ['$category', 'automation'] }, 1, 0] } },
          clientErrors: { $sum: { $cond: [{ $eq: ['$eventType', 'client-error'] }, 1, 0] } },
          averageLoadMs: { $avg: '$loadMs' },
        } },
      ]),
      SiteSecurityEvent.aggregate([
        { $match: match },
        { $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          events: { $sum: 1 },
          challenged: { $sum: { $cond: [{ $eq: ['$action', 'challenged'] }, 1, 0] } },
          throttled: { $sum: { $cond: [{ $eq: ['$action', 'throttled'] }, 1, 0] } },
          blocked: { $sum: { $cond: [{ $eq: ['$action', 'blocked'] }, 1, 0] } },
        } },
        { $sort: { _id: 1 } },
      ]),
      SiteSecurityEvent.aggregate([
        { $match: { ...match, category: { $ne: 'normal' } } },
        { $group: { _id: '$category', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
      SiteSecurityEvent.aggregate([
        { $match: match },
        { $group: {
          _id: '$ipHash',
          events: { $sum: 1 },
          challenged: { $sum: { $cond: [{ $eq: ['$action', 'challenged'] }, 1, 0] } },
          blocked: { $sum: { $cond: [{ $eq: ['$action', 'blocked'] }, 1, 0] } },
          lastSeenAt: { $max: '$createdAt' },
        } },
        { $sort: { events: -1 } },
        { $limit: 10 },
      ]),
      SiteSecurityEvent.find(match)
        .sort({ createdAt: -1 })
        .limit(30)
        .select('eventType category severity action ipHash route deviceFamily repeatCount burstCount minuteCount createdAt')
        .lean(),
    ]);

    const totalsRaw = totalsResult[0] || {};
    const total = totalsRaw.monitoredEvents || 0;
    const unsafe = (totalsRaw.blocked || 0) + (totalsRaw.throttled || 0) +
      (totalsRaw.recaptchaFailed || 0) + (totalsRaw.clientErrors || 0);
    const trafficScore = total
      ? Math.max(0, Math.min(100, Math.round(100 - (unsafe / total) * 100 - (totalsRaw.botSignals || 0) * 2)))
      : null;
    const postureScore = site.lastNetworkScan?.securityHeaderScore ?? null;
    const securityScore = trafficScore === null
      ? postureScore
      : postureScore === null
        ? trafficScore
        : Math.round((trafficScore + postureScore) / 2);
    const recommendations = [];
    const connectionStatus = siteConnectionStatus(site);
    if (connectionStatus === 'pending') recommendations.push('Install the NetGuard website script and load the registered website once to verify the integration.');
    if (connectionStatus === 'offline') recommendations.push('The website has not sent a heartbeat in 15 minutes. Check the integration script, CSP, and backend availability.');
    if (!total && connectionStatus === 'connected') recommendations.push('The integration is connected but this period has no reportable events. Open the site and submit a safe test form.');
    if (totalsRaw.repeatSubmissions) recommendations.push(`Review ${totalsRaw.repeatSubmissions} repeated form submission event(s) and keep repeat protection enabled.`);
    if (totalsRaw.blocked) recommendations.push(`Review ${totalsRaw.blocked} temporary network block(s) and confirm the threshold is not blocking legitimate users.`);
    if (totalsRaw.recaptchaFailed) recommendations.push(`Investigate ${totalsRaw.recaptchaFailed} failed reCAPTCHA verification(s) and verify the registered reCAPTCHA domains.`);
    if (totalsRaw.clientErrors) recommendations.push(`Fix ${totalsRaw.clientErrors} client-side error event(s); use the assistant with a redacted screenshot if needed.`);
    if (!site.lastNetworkScan?.scannedAt) recommendations.push('Run the server-side network posture scan to add TLS, certificate, HSTS, CSP, and security-header evidence.');
    if (site.lastNetworkScan?.scannedAt && !site.lastNetworkScan?.hsts) recommendations.push('Enable HTTP Strict Transport Security (HSTS) after confirming the entire site and subdomain plan supports HTTPS.');
    if (site.lastNetworkScan?.scannedAt && !site.lastNetworkScan?.contentSecurityPolicy) recommendations.push('Add and test a Content Security Policy to reduce script-injection risk.');
    if (site.lastNetworkScan?.scannedAt && !site.lastNetworkScan?.frameProtection) recommendations.push('Add CSP frame-ancestors or X-Frame-Options to reduce clickjacking risk.');
    if (site.lastNetworkScan?.certificateDaysRemaining !== undefined && site.lastNetworkScan?.certificateDaysRemaining !== null && site.lastNetworkScan.certificateDaysRemaining <= 14) recommendations.push(`Renew the TLS certificate soon; ${site.lastNetworkScan.certificateDaysRemaining} day(s) remain.`);
    if (total && !unsafe) recommendations.push('No urgent protected-website issues were found. Keep edge DDoS protection, server-side rate limiting, and NetGuard monitoring enabled.');

    res.json({
      success: true,
      data: {
        reportType: 'website',
        periodDays: days,
        generatedAt: new Date().toISOString(),
        privacyMode: 'HMAC-hashed network identifiers; no raw IP, MAC, form values, or query strings',
        securityScore,
        site: {
          _id: site._id,
          siteName: site.siteName,
          siteUrl: site.siteUrl,
          hasSSL: site.hasSSL,
          isActive: site.isActive,
          integrationStatus: connectionStatus,
          lastHeartbeat: site.lastHeartbeat,
          protectionSettings: site.protectionSettings,
          lastNetworkScan: site.lastNetworkScan || null,
        },
        totals: {
          monitoredEvents: total,
          uniqueNetworkSources: totalsRaw.visitors?.length || 0,
          allowed: totalsRaw.allowed || 0,
          challenged: totalsRaw.challenged || 0,
          throttled: totalsRaw.throttled || 0,
          blocked: totalsRaw.blocked || 0,
          recaptchaPassed: totalsRaw.recaptchaPassed || 0,
          recaptchaFailed: totalsRaw.recaptchaFailed || 0,
          repeatSubmissions: totalsRaw.repeatSubmissions || 0,
          botSignals: totalsRaw.botSignals || 0,
          clientErrors: totalsRaw.clientErrors || 0,
          averageLoadMs: totalsRaw.averageLoadMs ? Math.round(totalsRaw.averageLoadMs) : null,
        },
        daily,
        categories,
        networkSources: networkSources.map((source) => ({
          source: `source-${String(source._id).slice(0, 10)}`,
          events: source.events,
          challenged: source.challenged,
          blocked: source.blocked,
          lastSeenAt: source.lastSeenAt,
        })),
        recentEvents: recentEvents.map((event) => ({
          ...event,
          ipHash: undefined,
          source: `source-${String(event.ipHash).slice(0, 10)}`,
        })),
        recommendations,
        limitations: [
          'Browsers cannot expose a visitor MAC address; NetGuard uses a keyed hash of the server-observed IP and an ephemeral session ID.',
          'The website script reduces application-layer form abuse but cannot stop volumetric DDoS traffic before it reaches the origin. Use an edge WAF/CDN as well.',
        ],
      },
    });
  } catch (error) {
    console.error('Website report error:', error.message);
    res.status(500).json({ success: false, message: 'Could not build the protected website report.' });
  }
});

module.exports = router;
