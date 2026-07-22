const rateLimit = require('express-rate-limit');
const {
  apiRateLimitKey,
  globalApiLimit,
  skipGlobalApiLimit,
} = require('./rateLimitPolicy');

function createApiLimiter({
  windowMs = 15 * 60 * 1000,
  limit = globalApiLimit(),
} = {}) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    keyGenerator: apiRateLimitKey,
    // OAuth navigation, health checks, and administrator recovery each have
    // safer dedicated controls and must survive unrelated dashboard traffic.
    skip: skipGlobalApiLimit,
    handler(req, res) {
      const resetTime = req.rateLimit?.resetTime instanceof Date
        ? req.rateLimit.resetTime.getTime()
        : Date.now() + 60_000;
      const retryAfterSeconds = Math.max(1, Math.ceil((resetTime - Date.now()) / 1000));
      res.set('Retry-After', String(retryAfterSeconds));
      res.status(429).json({
        success: false,
        code: 'API_RATE_LIMITED',
        message: 'Request limit reached. Please wait briefly and try again.',
        retryAfterSeconds,
      });
    },
  });
}

module.exports = { createApiLimiter };
