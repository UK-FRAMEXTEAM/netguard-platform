const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const jwt = require('jsonwebtoken');
const { createApiLimiter } = require('../lib/apiRateLimiter');

test('essential routes survive quota exhaustion and verified sessions use separate buckets', async (t) => {
  const previousSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'api-limiter-integration-test-secret';

  const app = express();
  app.use(express.json());
  app.use('/api', createApiLimiter({ windowMs: 60_000, limit: 2 }));
  app.get('/api/data', (_req, res) => res.json({ success: true }));
  app.get('/api/health', (_req, res) => res.json({ success: true }));
  app.post('/api/auth/admin-login', (_req, res) => res.json({ success: true }));

  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  t.after(() => {
    server.close();
    if (previousSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = previousSecret;
  });

  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;
  assert.equal((await fetch(`${base}/api/data`)).status, 200);
  assert.equal((await fetch(`${base}/api/data`)).status, 200);

  const limited = await fetch(`${base}/api/data`);
  assert.equal(limited.status, 429);
  const limitedBody = await limited.json();
  assert.equal(limitedBody.code, 'API_RATE_LIMITED');
  assert.ok(limitedBody.retryAfterSeconds > 0);

  assert.equal((await fetch(`${base}/api/health`)).status, 200);
  assert.equal((await fetch(`${base}/api/auth/admin-login`, { method: 'POST' })).status, 200);

  const token = jwt.sign({ id: 'verified-user' }, process.env.JWT_SECRET, {
    issuer: 'netguard-api',
    audience: 'netguard-client',
  });
  assert.equal((await fetch(`${base}/api/data`, {
    headers: { Authorization: `Bearer ${token}` },
  })).status, 200);

  assert.equal((await fetch(`${base}/api/data`, {
    headers: { Authorization: 'Bearer fake-token' },
  })).status, 429);
});
