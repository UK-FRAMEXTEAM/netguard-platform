const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const {
  apiRateLimitKey,
  bearerCredential,
  globalApiLimit,
  requestPath,
  skipGlobalApiLimit,
} = require('../lib/rateLimitPolicy');

function request(method, originalUrl, headers = {}, ip = '203.0.113.7') {
  return { method, originalUrl, headers, ip };
}

test('Google OAuth navigation bypasses the shared API request quota', () => {
  assert.equal(skipGlobalApiLimit(request('GET', '/api/auth/google')), true);
  assert.equal(skipGlobalApiLimit(request('GET', '/api/auth/google?source=login')), true);
  assert.equal(skipGlobalApiLimit(request('GET', '/api/auth/google/callback?code=abc&state=xyz')), true);
  assert.equal(skipGlobalApiLimit(request('GET', '/api/auth/google/failure')), true);
});

test('health checks bypass the shared API quota', () => {
  assert.equal(skipGlobalApiLimit(request('GET', '/api/health')), true);
});

test('administrator recovery login bypasses only the shared quota', () => {
  assert.equal(skipGlobalApiLimit(request('POST', '/api/auth/admin-login')), true);
  assert.equal(skipGlobalApiLimit(request('GET', '/api/auth/admin-login')), false);
});

test('normal API and password-auth requests remain globally rate limited', () => {
  assert.equal(skipGlobalApiLimit(request('GET', '/api/dashboard/overview')), false);
  assert.equal(skipGlobalApiLimit(request('POST', '/api/auth/login')), false);
  assert.equal(skipGlobalApiLimit(request('POST', '/api/auth/register')), false);
});

test('requestPath ignores query strings and one trailing slash', () => {
  assert.equal(requestPath(request('GET', '/api/auth/google/?x=1')), '/api/auth/google');
});

test('authenticated clients use private credential-scoped quota buckets', () => {
  const previousSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'rate-limit-test-secret-at-least-32-bytes';
  const options = { issuer: 'netguard-api', audience: 'netguard-client' };
  const tokenOne = jwt.sign({ id: 'user-1' }, process.env.JWT_SECRET, options);
  const tokenTwo = jwt.sign({ id: 'user-2' }, process.env.JWT_SECRET, options);
  const first = request('GET', '/api/dashboard/overview', { authorization: `Bearer ${tokenOne}` });
  const same = request('GET', '/api/dashboard/sites', { authorization: `bearer ${tokenOne}` });
  const second = request('GET', '/api/dashboard/overview', { authorization: `Bearer ${tokenTwo}` });
  assert.equal(bearerCredential(first), tokenOne);
  assert.equal(apiRateLimitKey(first), apiRateLimitKey(same));
  assert.notEqual(apiRateLimitKey(first), apiRateLimitKey(second));
  assert.equal(apiRateLimitKey(first).includes(tokenOne), false);
  if (previousSecret === undefined) delete process.env.JWT_SECRET;
  else process.env.JWT_SECRET = previousSecret;
});

test('fake bearer tokens cannot create fresh quota buckets', () => {
  const previousSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'rate-limit-test-secret-at-least-32-bytes';
  const first = request('GET', '/api/dashboard/overview', { authorization: 'Bearer fake-one' });
  const second = request('GET', '/api/dashboard/overview', { authorization: 'Bearer fake-two' });
  assert.equal(apiRateLimitKey(first), 'ip:203.0.113.7');
  assert.equal(apiRateLimitKey(second), 'ip:203.0.113.7');
  if (previousSecret === undefined) delete process.env.JWT_SECRET;
  else process.env.JWT_SECRET = previousSecret;
});

test('unauthenticated clients fall back to an IP-scoped quota bucket', () => {
  assert.equal(apiRateLimitKey(request('GET', '/api/public/status')), 'ip:203.0.113.7');
});

test('global quota is suitable for dashboard and extension traffic and remains configurable', () => {
  const previous = process.env.API_RATE_LIMIT_MAX;
  const previousNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  delete process.env.API_RATE_LIMIT_MAX;
  assert.equal(globalApiLimit(), 3000);
  process.env.API_RATE_LIMIT_MAX = '4500';
  assert.equal(globalApiLimit(), 4500);
  if (previous === undefined) delete process.env.API_RATE_LIMIT_MAX;
  else process.env.API_RATE_LIMIT_MAX = previous;
  if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = previousNodeEnv;
});
