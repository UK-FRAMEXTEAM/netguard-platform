// ───────────────────────────────────────────────────────────
//  NetGuard Cloud Platform – Admin Routes
// ───────────────────────────────────────────────────────────
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Threat = require('../models/Threat');
const ProtectedSite = require('../models/ProtectedSite');
const { authenticate, isAdmin } = require('../middleware/auth');

// Get all users
router.get('/users', authenticate, isAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const [users, total] = await Promise.all([
      User.find()
        .select('-googleId')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      User.countDocuments(),
    ]);

    res.json({
      success: true,
      data: {
        users,
        pagination: { page, limit, total, pages: Math.ceil(total / limit) },
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get platform-wide stats
router.get('/stats', authenticate, isAdmin, async (req, res) => {
  try {
    const [totalUsers, totalThreats, totalSites, threatBreakdown,
           severityBreakdown, categoryBreakdown, recentThreats, activeUsers] = await Promise.all([
      User.countDocuments(),
      Threat.countDocuments(),
      ProtectedSite.countDocuments(),
      Threat.aggregate([
        { $group: { _id: '$category', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
      Threat.aggregate([
        { $group: { _id: '$severity', count: { $sum: 1 } } },
      ]),
      Threat.aggregate([
        { $group: { _id: '$category', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
      Threat.find().sort({ createdAt: -1 }).limit(20).lean(),
      User.countDocuments({ lastLogin: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } }),
    ]);

    res.json({
      success: true,
      data: {
        totalUsers,
        activeUsers,
        totalThreats,
        totalSites,
        threatBreakdown,
        severityBreakdown,
        categoryBreakdown,
        recentThreats,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get user details
router.get('/users/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-googleId').lean();
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const [threats, sites] = await Promise.all([
      Threat.find({ userId: req.params.id }).sort({ createdAt: -1 }).limit(50).lean(),
      ProtectedSite.find({ userId: req.params.id }).lean(),
    ]);

    res.json({ success: true, data: { ...user, threats, sites } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Update user role
router.put('/users/:id/role', authenticate, isAdmin, async (req, res) => {
  try {
    const { role } = req.body;
    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ success: false, message: 'Invalid role' });
    }

    const target = await User.findById(req.params.id);
    if (!target) return res.status(404).json({ success: false, message: 'User not found' });
    const ownerEmail = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
    const targetEmail = String(target.email || '').trim().toLowerCase();
    if (role === 'admin' && targetEmail !== ownerEmail) {
      return res.status(403).json({ success: false, message: 'Only ADMIN_EMAIL can receive the admin role' });
    }
    if (targetEmail === ownerEmail && role !== 'admin') {
      return res.status(403).json({ success: false, message: 'The owner admin role cannot be removed here' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true }
    ).select('-googleId');

    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Platform threat trend (last 30 days)
router.get('/threat-trend', authenticate, isAdmin, async (req, res) => {
  try {
    const last30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const trend = await Threat.aggregate([
      { $match: { createdAt: { $gte: last30d } } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          count: { $sum: 1 },
          blocked: { $sum: { $cond: [{ $eq: ['$action', 'blocked'] }, 1, 0] } },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    res.json({ success: true, data: trend });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;
