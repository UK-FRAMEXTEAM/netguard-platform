const express = require('express');
const tls = require('tls');
const https = require('https');
const { resolvePublicHost } = require('../lib/networkSafety');

const router = express.Router();

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

function inspectHsts(hostname, address) {
  return new Promise((resolve) => {
    const request = https.request({
      host: address,
      port: 443,
      servername: hostname,
      method: 'HEAD',
      path: '/',
      timeout: 8000,
      rejectUnauthorized: true,
      headers: { Host: hostname, 'User-Agent': 'NetGuard-Pro/3.1' },
    }, (response) => {
      response.resume();
      resolve({
        enabled: Boolean(response.headers['strict-transport-security']),
        header: response.headers['strict-transport-security'] || null,
        statusCode: response.statusCode,
      });
    });
    request.once('timeout', () => request.destroy());
    request.once('error', () => resolve({ enabled: false, header: null, statusCode: null }));
    request.end();
  });
}

router.get('/tls-inspect', async (req, res) => {
  try {
    const { hostname, address } = await resolvePublicHost(req.query.host);
    const [certificate, hsts] = await Promise.all([
      inspectCertificate(hostname, address),
      inspectHsts(hostname, address),
    ]);

    const validTo = certificate.validTo ? new Date(certificate.validTo) : null;
    const daysRemaining = validTo && !Number.isNaN(validTo.valueOf())
      ? Math.ceil((validTo - Date.now()) / 86400000)
      : null;

    res.json({
      success: true,
      data: {
        hostname,
        ...certificate,
        hsts,
        daysRemaining,
        inspectedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    const clientError = /valid public|public address|certificate|self signed|unable to verify|timed out/i.test(error.message);
    res.status(clientError ? 400 : 502).json({ success: false, message: error.message || 'TLS inspection failed' });
  }
});

module.exports = router;
