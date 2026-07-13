// ───────────────────────────────────────────────────────────
//  NetGuard Cloud Platform – User Model
// ───────────────────────────────────────────────────────────
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  googleId: {
    type: String,
    unique: true,
    sparse: true,
  },
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    default: null,
  },
  authProvider: {
    type: String,
    enum: ['local', 'google', 'local+google'],
    default: 'local',
  },
  avatar: {
    type: String,
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  },
  // Extension data synced from browser
  extensionId: {
    type: String,
    default: null,
  },
  protectionCode: {
    type: String,
    default: null,
  },
  // Protected sites
  protectedSites: [{
    url: String,
    code: String,
    addedAt: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
  }],
  // Stats
  stats: {
    threatsBlocked: { type: Number, default: 0 },
    trackersDetected: { type: Number, default: 0 },
    safeScans: { type: Number, default: 0 },
    totalSessions: { type: Number, default: 0 },
  },
  // Settings
  settings: {
    zeroTrustMode: { type: Boolean, default: true },
    behavioralDetection: { type: Boolean, default: true },
    threatIntelEnabled: { type: Boolean, default: true },
    sessionMonitoring: { type: Boolean, default: true },
    notifications: { type: Boolean, default: true },
    autoBlock: { type: Boolean, default: true },
  },
  lastLogin: {
    type: Date,
    default: Date.now,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Generate a unique protection code for the user
UserSchema.methods.generateProtectionCode = function () {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = 'NG-';
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 4; j++) {
      code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    if (i < 3) code += '-';
  }
  this.protectionCode = code;
  return code;
};

// Generate a site-specific code
UserSchema.methods.generateSiteCode = function (url) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let code = '';
  for (let i = 0; i < 16; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `netguard_${code}`;
};

module.exports = mongoose.model('User', UserSchema);
