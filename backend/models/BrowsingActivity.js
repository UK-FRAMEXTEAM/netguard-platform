const mongoose = require('mongoose');

const BrowsingActivitySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  // Privacy by design: store only the hostname, never paths, queries, or hashes.
  domain: {
    type: String,
    required: true,
    maxlength: 253,
  },
  day: {
    type: String,
    required: true,
    match: /^\d{4}-\d{2}-\d{2}$/,
  },
  visits: {
    type: Number,
    default: 0,
    min: 0,
  },
  secureVisits: {
    type: Number,
    default: 0,
    min: 0,
  },
  insecureVisits: {
    type: Number,
    default: 0,
    min: 0,
  },
  extensionVersion: {
    type: String,
    default: '',
    maxlength: 30,
  },
  firstVisitedAt: {
    type: Date,
    default: Date.now,
  },
  lastVisitedAt: {
    type: Date,
    default: Date.now,
  },
}, { versionKey: false });

BrowsingActivitySchema.index({ userId: 1, domain: 1, day: 1 }, { unique: true });
BrowsingActivitySchema.index({ userId: 1, day: -1 });

module.exports = mongoose.model('BrowsingActivity', BrowsingActivitySchema);
