const ProtectedSite = require('../models/ProtectedSite');
const { scanPublicWebsite } = require('./websiteScanner');

const activeScans = new Set();
const queuedScans = new Set();

function scanIntervalMs(site) {
  const hours = Math.min(168, Math.max(1, Number(site.protectionSettings?.autoScanIntervalHours) || 24));
  return hours * 60 * 60 * 1000;
}

function automaticScanDue(site, now = new Date()) {
  if (site.protectionSettings?.autoPostureScanEnabled === false) return false;
  const next = site.automationScan?.nextScanAt;
  if (next) return new Date(next) <= now;
  const last = site.lastNetworkScan?.scannedAt;
  return !last || now.getTime() - new Date(last).getTime() >= scanIntervalMs(site);
}

function scanDocument(scan) {
  return {
    scannedAt: new Date(scan.inspectedAt),
    statusCode: scan.headers.statusCode,
    tlsAuthorized: scan.certificate.authorized,
    tlsProtocol: scan.certificate.protocol || '',
    cipher: scan.certificate.cipher || '',
    certificateIssuer: scan.certificate.issuer || '',
    certificateValidTo: scan.certificate.validTo ? new Date(scan.certificate.validTo) : null,
    certificateDaysRemaining: scan.daysRemaining,
    hsts: scan.headers.hsts,
    contentSecurityPolicy: scan.headers.contentSecurityPolicy,
    frameProtection: scan.headers.frameProtection,
    noSniff: scan.headers.noSniff,
    referrerPolicy: scan.headers.referrerPolicy,
    permissionsPolicy: scan.headers.permissionsPolicy,
    securityHeaderScore: scan.securityHeaderScore,
    error: scan.headers.headerError || '',
  };
}

async function resolveSite(siteOrId) {
  if (siteOrId && typeof siteOrId.save === 'function') return siteOrId;
  return ProtectedSite.findById(siteOrId);
}

async function runStoredWebsiteScan(siteOrId, { force = false, source = 'manual' } = {}) {
  const site = await resolveSite(siteOrId);
  if (!site) return { ok: false, skipped: true, message: 'Protected site was not found.' };
  const key = String(site._id);
  if (activeScans.has(key)) return { ok: true, skipped: true, site, message: 'A website scan is already running.' };
  if (!force && !automaticScanDue(site)) return { ok: true, skipped: true, site, message: 'The automatic scan is not due yet.' };

  activeScans.add(key);
  const now = new Date();
  site.automationScan = {
    status: 'running',
    source,
    lastRequestedAt: now,
    nextScanAt: new Date(now.getTime() + scanIntervalMs(site)),
    lastError: '',
  };
  await site.save();

  try {
    const scan = await scanPublicWebsite(site.siteUrl);
    site.lastNetworkScan = scanDocument(scan);
    site.hasSSL = Boolean(scan.certificate.authorized);
    site.securityScore = scan.securityHeaderScore;
    site.lastScanned = new Date();
    site.updatedAt = new Date();
    site.automationScan = {
      status: 'complete',
      source,
      lastRequestedAt: now,
      nextScanAt: new Date(Date.now() + scanIntervalMs(site)),
      lastError: '',
    };
    await site.save();
    return { ok: true, skipped: false, site, scan: site.lastNetworkScan };
  } catch (error) {
    const message = String(error.message || 'Network scan failed').slice(0, 300);
    site.lastNetworkScan = { scannedAt: new Date(), error: message };
    site.lastScanned = new Date();
    site.updatedAt = new Date();
    site.automationScan = {
      status: 'failed',
      source,
      lastRequestedAt: now,
      nextScanAt: new Date(Date.now() + scanIntervalMs(site)),
      lastError: message,
    };
    await site.save();
    return { ok: false, skipped: false, site, message };
  } finally {
    activeScans.delete(key);
  }
}

function queueAutomaticScan(site) {
  const key = String(site._id);
  if (!automaticScanDue(site) || activeScans.has(key) || queuedScans.has(key)) return false;
  queuedScans.add(key);
  runStoredWebsiteScan(site._id, { source: 'live-traffic' })
    .catch((error) => {
      console.error('[site-automation] Automatic posture scan failed:', error.message);
    })
    .finally(() => queuedScans.delete(key));
  return true;
}

module.exports = {
  automaticScanDue,
  runStoredWebsiteScan,
  queueAutomaticScan,
  scanDocument,
};
