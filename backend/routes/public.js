const express = require('express');
const { scanPublicWebsite } = require('../lib/websiteScanner');

const router = express.Router();

router.get('/tls-inspect', async (req, res) => {
  try {
    const input = String(req.query.host || '').trim();
    const url = input.startsWith('http') ? input : `https://${input}`;
    const scan = await scanPublicWebsite(url);
    res.json({
      success: true,
      data: {
        hostname: scan.hostname,
        ...scan.certificate,
        hsts: {
          enabled: scan.headers.hsts,
          header: scan.headers.hstsHeader,
          statusCode: scan.headers.statusCode,
        },
        securityHeaders: scan.headers,
        securityHeaderScore: scan.securityHeaderScore,
        daysRemaining: scan.daysRemaining,
        inspectedAt: scan.inspectedAt,
      },
    });
  } catch (error) {
    const clientError = /valid public|public address|certificate|self signed|unable to verify|timed out|require HTTPS/i.test(error.message);
    res.status(clientError ? 400 : 502).json({ success: false, message: error.message || 'TLS inspection failed' });
  }
});

module.exports = router;
