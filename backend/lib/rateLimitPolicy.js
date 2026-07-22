const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const GOOGLE_OAUTH_PATHS = new Set([
  '/api/auth/google',
  '/api/auth/google/callback',
  '/api/auth/google/failure',
]);

function requestPath(req) {
  return String(req.originalUrl || req.url || '')
    .split('?')[0]
    .replace(/\/$/, '') || '/';
}

function bearerCredential(req) {
  const authorization = String(req.headers?.authorization || '').trim();
  const bearerMatch = authorization.match(/^Bearer\s+(.+)$/i);
  if (bearerMatch?.[1]) return bearerMatch[1].trim();
  return String(req.headers?.['x-auth-token'] || '').trim();
}

function apiRateLimitKey(req) {
  const suppliedCredential = bearerCredential(req);
  let credential = '';
  if (suppliedCredential && process.env.JWT_SECRET) {
    try {
      jwt.verify(suppliedCredential, process.env.JWT_SECRET, {
        issuer: 'netguard-api',
        audience: 'netguard-client',
      });
      credential = suppliedCredential;
    } catch {
      // Invalid/untrusted credentials stay in the IP bucket so an attacker
      // cannot bypass throttling by rotating fake Authorization headers.
    }
  }
  if (credential) {
    // Keep authenticated users/extensions in separate buckets without storing
    // their bearer token as a rate-limit key.
    const fingerprint = crypto.createHash('sha256').update(credential).digest('hex').slice(0, 32);
    return `credential:${fingerprint}`;
  }
  return `ip:${String(req.ip || req.socket?.remoteAddress || 'unknown')}`;
}

function globalApiLimit() {
  const configured = Number.parseInt(process.env.API_RATE_LIMIT_MAX || '', 10);
  if (Number.isFinite(configured) && configured >= 100) return configured;
  return process.env.NODE_ENV === 'production' ? 3000 : 10000;
}

function skipGlobalApiLimit(req) {
  const method = String(req.method || '').toUpperCase();
  const path = requestPath(req);
  // The administrator recovery endpoint has its own strict failed-attempt
  // limiter. Keeping it outside the shared quota makes a viva/demo login work
  // even when extension telemetry has consumed the public-IP API allowance.
  if (method === 'POST' && path === '/api/auth/admin-login') return true;
  if (method !== 'GET') return false;
  return path === '/api/health' || GOOGLE_OAUTH_PATHS.has(path);
}

module.exports = {
  apiRateLimitKey,
  bearerCredential,
  globalApiLimit,
  requestPath,
  skipGlobalApiLimit,
};
