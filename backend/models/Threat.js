// ───────────────────────────────────────────────────────────
//  NetGuard Cloud Platform – Threat Model
// ───────────────────────────────────────────────────────────
const mongoose = require('mongoose');

const ThreatSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  // Threat details
  category: {
    type: String,
    enum: [
      'phishing', 'malware', 'tracker', 'crypto-miner',
      'xss-attempt', 'session-exposed', 'hidden-iframe',
      'malvertising', 'zero-trust-http', 'suspicious-redirect',
      'suspicious-keyword', 'high-risk-tld', 'credential-risk',
      'dynamic-miner-injection', 'phishing-pattern', 'dns-leak',
      'brand-spoofing', 'insecure-form',
    ],
    required: true,
  },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium',
  },
  detail: {
    type: String,
    required: true,
  },
  url: {
    type: String,
    required: true,
  },
  domain: {
    type: String,
    default: '',
  },
  ip: {
    type: String,
    default: '',
  },
  // Detection layer
  detectionLayer: {
    type: String,
    enum: [
      'behavioral', 'threat-intel', 'zero-trust',
      'session-monitor', 'content-script', 'heuristic',
    ],
  },
  // Action taken
  action: {
    type: String,
    enum: ['blocked', 'warned', 'logged', 'monitored'],
    default: 'logged',
  },
  // Extension info
  extensionVersion: {
    type: String,
    default: '2.0.0',
  },
  // Timestamps
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Index for fast queries
ThreatSchema.index({ userId: 1, createdAt: -1 });
ThreatSchema.index({ category: 1 });
ThreatSchema.index({ severity: 1 });
ThreatSchema.index({ domain: 1 });

module.exports = mongoose.model('Threat', ThreatSchema);
