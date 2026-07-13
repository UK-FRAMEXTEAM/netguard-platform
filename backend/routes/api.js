// ───────────────────────────────────────────────────────────
//  NetGuard Cloud Platform – Extension Sync API Routes
// ───────────────────────────────────────────────────────────
const express = require('express');
const router = express.Router();
const Threat = require('../models/Threat');
const ProtectedSite = require('../models/ProtectedSite');
const { extensionAuth } = require('../middleware/auth');

// Report a threat from extension
router.post('/threats', extensionAuth, async (req, res) => {
  try {
    const { category, severity, detail, url, domain, detectionLayer, action } = req.body;

    if (!category || !detail || !url) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const threat = await Threat.create({
      userId: req.extensionUser.id,
      category,
      severity: severity || 'medium',
      detail,
      url,
      domain: domain || '',
      detectionLayer: detectionLayer || 'content-script',
      action: action || 'logged',
    });

    // Update only the counters represented by this event.
    const User = require('../models/User');
    const increments = {};
    if (action === 'blocked') increments['stats.threatsBlocked'] = 1;
    if (category === 'tracker') increments['stats.trackersDetected'] = 1;
    if (Object.keys(increments).length) {
      await User.findByIdAndUpdate(req.extensionUser.id, { $inc: increments });
    }

    res.json({ success: true, threat });
  } catch (error) {
    console.error('Threat sync error:', error);
    res.status(500).json({ success: false, message: 'Sync error' });
  }
});

// Batch threat sync (for multiple threats at once)
router.post('/threats/batch', extensionAuth, async (req, res) => {
  try {
    const { threats } = req.body;
    if (!Array.isArray(threats) || threats.length === 0) {
      return res.status(400).json({ success: false, message: 'No threats provided' });
    }

    const created = await Threat.insertMany(
      threats.map(t => ({
        userId: req.extensionUser.id,
        category: t.category || 'unknown',
        severity: t.severity || 'medium',
        detail: t.detail || '',
        url: t.url || '',
        domain: t.domain || '',
        detectionLayer: t.detectionLayer || 'content-script',
        action: t.action || 'logged',
      }))
    );

    // Update stats
    const blocked = threats.filter(t => t.action === 'blocked').length;
    const trackers = threats.filter(t => t.category === 'tracker').length;

    const User = require('../models/User');
    await User.findByIdAndUpdate(req.extensionUser.id, {
      $inc: {
        'stats.threatsBlocked': blocked,
        'stats.trackersDetected': trackers,
      },
    });

    res.json({ success: true, count: created.length });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Sync error' });
  }
});

// Verify protection code (for website integration)
router.get('/verify/:code', async (req, res) => {
  try {
    const site = await ProtectedSite.findOne({
      protectionCode: req.params.code,
      isActive: true,
    }).populate('userId', 'name email');

    if (!site) {
      return res.json({ success: false, message: 'Invalid or inactive protection code' });
    }

    res.json({
      success: true,
      site: {
        url: site.siteUrl,
        name: site.siteName,
        protectionCode: site.protectionCode,
        owner: site.userId.name,
        securityScore: site.securityScore,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Verification error' });
  }
});

// Get user's protection code
router.get('/protection-code', extensionAuth, async (req, res) => {
  try {
    const User = require('../models/User');
    const user = await User.findById(req.extensionUser.id);

    if (!user.protectionCode) {
      user.generateProtectionCode();
      await user.save();
    }

    res.json({ success: true, protectionCode: user.protectionCode });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Sync extension settings from cloud
router.get('/settings', extensionAuth, async (req, res) => {
  try {
    const User = require('../models/User');
    const user = await User.findById(req.extensionUser.id);
    res.json({ success: true, settings: user.settings });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;
