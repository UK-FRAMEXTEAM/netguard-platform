const tls = require('tls');
const https = require('https');
const { resolvePublicHost } = require('./networkSafety');

function inspectCertificate(hostname, address) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: address,
      port: 443,
      servername: hostname,
      rejectUnauthorized: true,
      timeout: 8000,
    });
    socket.once('secureConnect', () => {
      const certificate = socket.getPeerCertificate();
      const cipher = socket.getCipher();
      const result = {
        authorized: socket.authorized,
        protocol: socket.getProtocol(),
        cipher: cipher?.standardName || cipher?.name || null,
        subject: certificate.subject?.CN || null,
        issuer: certificate.issuer?.CN || certificate.issuer?.O || null,
        validFrom: certificate.valid_from || null,
        validTo: certificate.valid_to || null,
        fingerprint256: certificate.fingerprint256 || null,
      };
      socket.end();
      resolve(result);
    });
    socket.once('timeout', () => socket.destroy(new Error('TLS connection timed out')));
    socket.once('error', reject);
  });
}

function inspectHeaders(hostname, address) {
  return new Promise((resolve) => {
    const request = https.request({
      host: address,
      port: 443,
      servername: hostname,
      method: 'HEAD',
      path: '/',
      timeout: 8000,
      rejectUnauthorized: true,
      headers: { Host: hostname, 'User-Agent': 'NetGuard-Pro/3.4' },
    }, (response) => {
      response.resume();
      const headers = response.headers;
      resolve({
        statusCode: response.statusCode,
        hsts: Boolean(headers['strict-transport-security']),
        hstsHeader: headers['strict-transport-security'] || null,
        contentSecurityPolicy: Boolean(headers['content-security-policy']),
        frameProtection: Boolean(headers['x-frame-options'] || /frame-ancestors/i.test(headers['content-security-policy'] || '')),
        noSniff: String(headers['x-content-type-options'] || '').toLowerCase() === 'nosniff',
        referrerPolicy: Boolean(headers['referrer-policy']),
        permissionsPolicy: Boolean(headers['permissions-policy']),
      });
    });
    request.once('timeout', () => request.destroy(new Error('Header inspection timed out')));
    request.once('error', (error) => resolve({
      statusCode: null,
      hsts: false,
      hstsHeader: null,
      contentSecurityPolicy: false,
      frameProtection: false,
      noSniff: false,
      referrerPolicy: false,
      permissionsPolicy: false,
      headerError: error.message,
    }));
    request.end();
  });
}

async function scanPublicWebsite(value) {
  const parsed = new URL(value);
  if (parsed.protocol !== 'https:') throw new Error('Network posture scans require HTTPS');
  const { hostname, address } = await resolvePublicHost(parsed.hostname);
  const [certificate, headers] = await Promise.all([
    inspectCertificate(hostname, address),
    inspectHeaders(hostname, address),
  ]);
  const validTo = certificate.validTo ? new Date(certificate.validTo) : null;
  const daysRemaining = validTo && !Number.isNaN(validTo.valueOf())
    ? Math.ceil((validTo - Date.now()) / 86400000)
    : null;
  const checks = [
    certificate.authorized,
    /^TLSv1\.[23]$/.test(certificate.protocol || ''),
    daysRemaining === null ? false : daysRemaining > 14,
    headers.hsts,
    headers.contentSecurityPolicy,
    headers.frameProtection,
    headers.noSniff,
    headers.referrerPolicy,
    headers.permissionsPolicy,
  ];
  const securityHeaderScore = Math.round((checks.filter(Boolean).length / checks.length) * 100);
  return {
    hostname,
    certificate,
    headers,
    daysRemaining,
    securityHeaderScore,
    inspectedAt: new Date().toISOString(),
  };
}

module.exports = { scanPublicWebsite };
