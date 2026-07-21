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
  normalizedOrigin: {
    type: String,
    default: '',
    maxlength: 300,
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
  protectionProfile: {
    type: String,
    enum: ['balanced', 'strict', 'custom'],
    default: 'balanced',
  },
  integrationStatus: {
    type: String,
    enum: ['pending', 'connected', 'offline'],
    default: 'pending',
  },
  lastHeartbeat: {
    type: Date,
    default: null,
  },
  lastEventAt: {
    type: Date,
    default: null,
  },
  protectionSettings: {
    telemetryEnabled: { type: Boolean, default: true },
    rateLimitEnabled: { type: Boolean, default: true },
    repeatProtectionEnabled: { type: Boolean, default: true },
    botDetectionEnabled: { type: Boolean, default: true },
    formShieldEnabled: { type: Boolean, default: true },
    recaptchaEnabled: { type: Boolean, default: true },
    clientErrorMonitoring: { type: Boolean, default: true },
    autoBlockEnabled: { type: Boolean, default: true },
    autoPostureScanEnabled: { type: Boolean, default: true },
    repeatWindowSeconds: { type: Number, default: 5, min: 1, max: 30 },
    repeatMaxSubmissions: { type: Number, default: 2, min: 1, max: 20 },
    burstWindowSeconds: { type: Number, default: 5, min: 1, max: 60 },
    burstMaxRequests: { type: Number, default: 8, min: 2, max: 200 },
    minuteMaxRequests: { type: Number, default: 60, min: 10, max: 2000 },
    blockMinutes: { type: Number, default: 15, min: 1, max: 1440 },
    autoScanIntervalHours: { type: Number, default: 24, min: 1, max: 168 },
  },
  automationScan: {
    status: { type: String, enum: ['pending', 'running', 'complete', 'failed'], default: 'pending' },
    source: { type: String, enum: ['registration', 'manual', 'live-traffic'], default: 'registration' },
    lastRequestedAt: { type: Date, default: null },
    nextScanAt: { type: Date, default: null },
    lastError: { type: String, default: '', maxlength: 300 },
  },
  counters: {
    monitoredEvents: { type: Number, default: 0 },
    allowed: { type: Number, default: 0 },
    challenged: { type: Number, default: 0 },
    throttled: { type: Number, default: 0 },
    blocked: { type: Number, default: 0 },
    recaptchaPassed: { type: Number, default: 0 },
    recaptchaFailed: { type: Number, default: 0 },
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
  lastNetworkScan: {
    scannedAt: { type: Date, default: null },
    statusCode: { type: Number, default: null },
    tlsAuthorized: { type: Boolean, default: false },
    tlsProtocol: { type: String, default: '' },
    cipher: { type: String, default: '' },
    certificateIssuer: { type: String, default: '' },
    certificateValidTo: { type: Date, default: null },
    certificateDaysRemaining: { type: Number, default: null },
    hsts: { type: Boolean, default: false },
    contentSecurityPolicy: { type: Boolean, default: false },
    frameProtection: { type: Boolean, default: false },
    noSniff: { type: Boolean, default: false },
    referrerPolicy: { type: Boolean, default: false },
    permissionsPolicy: { type: Boolean, default: false },
    securityHeaderScore: { type: Number, default: null },
    error: { type: String, default: '' },
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
ProtectedSiteSchema.index({ userId: 1, normalizedOrigin: 1 }, { unique: true, sparse: true });

module.exports = mongoose.model('ProtectedSite', ProtectedSiteSchema);
