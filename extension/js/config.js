/*
 * Replace these three localhost URLs with your final Vercel and Render URLs
 * before creating the public extension ZIP.
 */
self.NETGUARD_CONFIG = Object.freeze({
  API_BASE: 'http://localhost:5000',
  DASHBOARD_URL: 'http://localhost:5173',
  RELEASE_URL: 'http://localhost:5173/release.json',
  ALLOWED_DASHBOARD_ORIGINS: ['http://localhost:5173'],
});
