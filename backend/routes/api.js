// ───────────────────────────────────────────────────────────
//  NetGuard Cloud Platform – Extension Sync API Routes
// ───────────────────────────────────────────────────────────
const express = require('express');
const router = express.Router();
const Threat = require('../models/Threat');
const ProtectedSite = require('../models/ProtectedSite');
const BrowsingActivity = require('../models/BrowsingActivity');
const { extensionAuth } = require('../middleware/auth');

function normalizedDomain(value) {
  const domain = String(value || '').trim().toLowerCase().replace(/^www\./, '');
  if (!domain || domain.length > 253 || !/^[a-z0-9.-]+$/.test(domain)) return '';
  if (domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')) return '';
  return domain;
}

// Report a threat from extension
router.post('/threats', extensionAuth, async (req, res) => {
  try {
    const { category, severity, detail, url, domain, detectionLayer, action, extensionVersion } = req.body;

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
      extensionVersion: String(extensionVersion || '').slice(0, 30),
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
        extensionVersion: String(t.extensionVersion || '').slice(0, 30),
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

// Store privacy-preserving top-level browsing analytics. Full URLs are never saved.
router.post('/activity', extensionAuth, async (req, res) => {
  try {
    const domain = normalizedDomain(req.body.domain);
    const protocol = req.body.protocol === 'https:' ? 'https:' : req.body.protocol === 'http:' ? 'http:' : '';
    if (!domain || !protocol) {
      return res.status(400).json({ success: false, message: 'A valid domain and protocol are required' });
    }

    const visitedAtValue = new Date(req.body.visitedAt || Date.now());
    const visitedAt = Number.isNaN(visitedAtValue.getTime()) ? new Date() : visitedAtValue;
    const day = visitedAt.toISOString().slice(0, 10);
    const secure = protocol === 'https:';

    await BrowsingActivity.findOneAndUpdate(
      { userId: req.extensionUser.id, domain, day },
      {
        $inc: {
          visits: 1,
          secureVisits: secure ? 1 : 0,
          insecureVisits: secure ? 0 : 1,
        },
        $set: {
          lastVisitedAt: visitedAt,
          extensionVersion: String(req.body.extensionVersion || '').slice(0, 30),
        },
        $setOnInsert: { firstVisitedAt: visitedAt },
      },
      { upsert: true, setDefaultsOnInsert: true }
    );

    if (secure) {
      const User = require('../models/User');
      await User.findByIdAndUpdate(req.extensionUser.id, { $inc: { 'stats.safeScans': 1 } });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Activity sync error:', error.message);
    res.status(500).json({ success: false, message: 'Activity sync error' });
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
