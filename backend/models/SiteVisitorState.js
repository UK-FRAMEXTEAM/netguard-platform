const mongoose = require('mongoose');

const SiteVisitorStateSchema = new mongoose.Schema({
  siteId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ProtectedSite',
    required: true,
  },
  ipHash: { type: String, required: true, maxlength: 64 },
  visitorHash: { type: String, default: '', maxlength: 64 },
  challengeRequired: { type: Boolean, default: false },
  challengeFailures: { type: Number, default: 0, min: 0 },
  verifiedUntil: { type: Date, default: null },
  blockedUntil: { type: Date, default: null },
  lastSeenAt: { type: Date, default: Date.now },
  expireAt: { type: Date, required: true },
}, { versionKey: false });

SiteVisitorStateSchema.index({ siteId: 1, ipHash: 1, visitorHash: 1 }, { unique: true });
SiteVisitorStateSchema.index({ expireAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('SiteVisitorState', SiteVisitorStateSchema);
