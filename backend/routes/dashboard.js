// ───────────────────────────────────────────────────────────
//  NetGuard Cloud Platform – Dashboard Routes
// ───────────────────────────────────────────────────────────
const express = require('express');
const router = express.Router();
const Threat = require('../models/Threat');
const ProtectedSite = require('../models/ProtectedSite');
const BrowsingActivity = require('../models/BrowsingActivity');
const { authenticate, isAdmin } = require('../middleware/auth');

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
    const protectedSites = await ProtectedSite.find({ userId, isActive: true })
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
          blocked: { $sum: { $cond: [{ $eq: ['$action', 'blocked'] }, 1, 0] } },
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
    res.json({ success: true, data: sites });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Add a protected site
router.post('/sites', authenticate, async (req, res) => {
  try {
    const { siteUrl, siteName } = req.body;
    if (!siteUrl) {
      return res.status(400).json({ success: false, message: 'Site URL required' });
    }

    const code = req.user.generateSiteCode(siteUrl);

    const site = await ProtectedSite.create({
      userId: req.user._id,
      siteUrl,
      siteName: siteName || siteUrl,
      protectionCode: code,
      hasSSL: siteUrl.startsWith('https'),
    });

    // Add to user's protected sites
    req.user.protectedSites.push({
      url: siteUrl,
      code,
      isActive: true,
    });
    await req.user.save();

    res.json({ success: true, data: site });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
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
          blocked: { $sum: { $cond: [{ $eq: ['$action', 'blocked'] }, 1, 0] } },
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
          blocked: { $sum: { $cond: [{ $eq: ['$action', 'blocked'] }, 1, 0] } },
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

module.exports = router;
