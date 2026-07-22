const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeUrl } = require('../js/risk-engine');

test('allows legitimate brand and cloud infrastructure domains', () => {
  assert.equal(analyzeUrl('https://accounts.google.com/').status, 'safe');
  assert.equal(analyzeUrl('https://s3.amazonaws.com/example').status, 'safe');
  assert.equal(analyzeUrl('https://www.paypal.com/signin').status, 'safe');
  assert.equal(analyzeUrl('https://www.malwarebytes.com/account').status, 'safe');
});

test('detects exact and subdomain phishing intelligence matches', () => {
  const exact = analyzeUrl('https://paypa1.com/login');
  const subdomain = analyzeUrl('https://auth.verify-paypal.info/account');
  assert.equal(exact.status, 'danger');
  assert.equal(exact.category, 'phishing');
  assert.equal(subdomain.status, 'danger');
});

test('detects brand spoofing without flagging the real brand', () => {
  const result = analyzeUrl('https://paypal-security-check.example/login');
  assert.equal(result.status, 'danger');
  assert.equal(result.category, 'brand-spoofing');
});

test('treats a risky TLD alone as a warning to reduce false positives', () => {
  const result = analyzeUrl('https://portfolio.xyz/');
  assert.equal(result.status, 'warning');
  assert.equal(result.category, 'high-risk-tld');
});

test('detects unencrypted credential pages as dangerous', () => {
  const result = analyzeUrl('http://example.test/account/login');
  assert.equal(result.status, 'danger');
  assert.equal(result.category, 'zero-trust-http');
});

test('detects encoded XSS-like query values', () => {
  const result = analyzeUrl('https://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E');
  assert.equal(result.status, 'danger');
  assert.equal(result.category, 'xss-attempt');
});

test('keeps ordinary HTTPS pages safe and ordinary HTTP pages warning-only', () => {
  assert.equal(analyzeUrl('https://example.com/news').status, 'safe');
  assert.equal(analyzeUrl('http://example.com/news').status, 'warning');
});
