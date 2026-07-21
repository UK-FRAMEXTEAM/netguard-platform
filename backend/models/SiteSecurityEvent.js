const mongoose = require('mongoose');

const SiteSecurityEventSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  siteId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ProtectedSite',
    required: true,
    index: true,
  },
  eventType: {
    type: String,
    enum: ['page-view', 'heartbeat', 'form-submit', 'client-error', 'bot-signal', 'recaptcha'],
    required: true,
  },
  category: {
    type: String,
    enum: ['normal', 'repeat-submission', 'request-burst', 'minute-rate', 'automation', 'client-error', 'challenge'],
    default: 'normal',
  },
  severity: {
    type: String,
    enum: ['info', 'low', 'medium', 'high', 'critical'],
    default: 'info',
  },
  action: {
    type: String,
    enum: ['allowed', 'challenged', 'throttled', 'blocked', 'passed', 'failed'],
    default: 'allowed',
  },
  // Privacy by design: these are keyed HMAC values, never raw IP/MAC addresses.
  ipHash: { type: String, required: true, maxlength: 64 },
  visitorHash: { type: String, default: '', maxlength: 64 },
  messageHash: { type: String, default: '', maxlength: 64 },
  route: { type: String, default: '/', maxlength: 300 },
  deviceFamily: { type: String, default: 'Other', maxlength: 30 },
  loadMs: { type: Number, default: null, min: 0, max: 300000 },
  repeatCount: { type: Number, default: 0, min: 0 },
  burstCount: { type: Number, default: 0, min: 0 },
  minuteCount: { type: Number, default: 0, min: 0 },
  createdAt: { type: Date, default: Date.now, index: true },
  expireAt: { type: Date, required: true },
}, { versionKey: false });

SiteSecurityEventSchema.index({ siteId: 1, createdAt: -1 });
SiteSecurityEventSchema.index({ siteId: 1, ipHash: 1, createdAt: -1 });
SiteSecurityEventSchema.index({ siteId: 1, ipHash: 1, messageHash: 1, createdAt: -1 });
SiteSecurityEventSchema.index({ expireAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('SiteSecurityEvent', SiteSecurityEventSchema);
