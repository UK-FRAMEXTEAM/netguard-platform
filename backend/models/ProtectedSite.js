// ──────────────────────────────────────────────────────────
//  NetGuard Cloud Platform – Protected Site Model
// ───────────────────────────────────────────────────────────
const mongoose = require('mongoose');

const ProtectedSiteSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  siteUrl: {
    type: String,
    required: true,
  },
  siteName: {
    type: String,
    default: '',
  },
  protectionCode: {
    type: String,
    required: true,
    unique: true,
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  // Threats detected on this site
  threatsDetected: {
    type: Number,
    default: 0,
  },
  // Last scan
  lastScanned: {
    type: Date,
    default: Date.now,
  },
  // Site security score (0-100)
  securityScore: {
    type: Number,
    default: 100,
  },
  // SSL status
  hasSSL: {
    type: Boolean,
    default: false,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

ProtectedSiteSchema.index({ userId: 1 });
ProtectedSiteSchema.index({ protectionCode: 1 }, { unique: true });

module.exports = mongoose.model('ProtectedSite', ProtectedSiteSchema);
