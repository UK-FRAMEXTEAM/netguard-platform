// ───────────────────────────────────────────────────────────
//  NetGuard Cloud Platform – Dashboard Routes
// ───────────────────────────────────────────────────────────
const express = require('express');
const router = express.Router();
const Threat = require('../models/Threat');
const ProtectedSite = require('../models/ProtectedSite');
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

module.exports = router;
