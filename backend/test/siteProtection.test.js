const test = require('node:test');
const assert = require('node:assert/strict');

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-only-secret-value';
const {
  normalizeSiteUrl,
  originMatchesSite,
  hashIdentifier,
  protectionDecision,
} = require('../lib/siteProtection');
const { settingsForProfile } = require('../lib/siteProfiles');
const { automaticScanDue } = require('../lib/siteAutomation');

const settings = {
  rateLimitEnabled: true,
  repeatProtectionEnabled: true,
  botDetectionEnabled: true,
  recaptchaEnabled: true,
  autoBlockEnabled: true,
  repeatMaxSubmissions: 2,
  burstMaxRequests: 8,
  minuteMaxRequests: 60,
};

test('normalizes a website to its origin without credentials or paths', () => {
  const oldEnvironment = process.env.NODE_ENV;
  process.env.NODE_ENV = 'development';
  const result = normalizeSiteUrl('https://user:pass@example.com/path?q=secret');
  process.env.NODE_ENV = oldEnvironment;
  assert.equal(result.siteUrl, 'https://example.com/');
  assert.equal(result.normalizedOrigin, 'https://example.com');
});

test('matches only the registered origin', () => {
  const site = { normalizedOrigin: 'https://example.com' };
  assert.equal(originMatchesSite('https://example.com', site), true);
  assert.equal(originMatchesSite('https://evil.example', site), false);
});

test('creates stable non-reversible keyed network labels', () => {
  const one = hashIdentifier('site:1:ip', '203.0.113.10');
  const two = hashIdentifier('site:1:ip', '203.0.113.10');
  assert.equal(one, two);
  assert.equal(one.length, 64);
  assert.notEqual(one, '203.0.113.10');
});

test('allows ordinary traffic', () => {
  const decision = protectionDecision({
    settings,
    counts: { repeat: 1, burst: 2, minute: 5 },
    state: null,
    event: { messageHash: 'abc', botSignal: false },
    recaptchaAvailable: true,
  });
  assert.equal(decision.action, 'allowed');
});

test('challenges repeated submissions when reCAPTCHA is available', () => {
  const decision = protectionDecision({
    settings,
    counts: { repeat: 2, burst: 2, minute: 5 },
    state: null,
    event: { messageHash: 'abc', botSignal: false },
    recaptchaAvailable: true,
  });
  assert.equal(decision.action, 'challenged');
  assert.equal(decision.category, 'repeat-submission');
});

test('temporarily blocks an extreme repeated pattern', () => {
  const decision = protectionDecision({
    settings,
    counts: { repeat: 4, burst: 3, minute: 6 },
    state: null,
    event: { messageHash: 'abc', botSignal: false },
    recaptchaAvailable: true,
  });
  assert.equal(decision.action, 'blocked');
});

test('creates independent balanced settings for a newly added website', () => {
  const result = settingsForProfile('balanced', {
    botDetectionEnabled: false,
    burstMaxRequests: 5000,
  });
  assert.equal(result.botDetectionEnabled, false);
  assert.equal(result.formShieldEnabled, true);
  assert.equal(result.burstMaxRequests, 200);
  assert.equal(result.autoPostureScanEnabled, true);
});

test('strict profile lowers rate limits and scans more often', () => {
  const result = settingsForProfile('strict');
  assert.equal(result.burstMaxRequests, 5);
  assert.equal(result.minuteMaxRequests, 30);
  assert.equal(result.blockMinutes, 30);
  assert.equal(result.autoScanIntervalHours, 12);
});

test('automatic website scan becomes due from the per-site schedule', () => {
  const due = automaticScanDue({
    protectionSettings: { autoPostureScanEnabled: true, autoScanIntervalHours: 24 },
    automationScan: { nextScanAt: new Date(Date.now() - 1000) },
  });
  const disabled = automaticScanDue({
    protectionSettings: { autoPostureScanEnabled: false },
    automationScan: { nextScanAt: new Date(Date.now() - 1000) },
  });
  assert.equal(due, true);
  assert.equal(disabled, false);
});
