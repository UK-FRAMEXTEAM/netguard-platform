// NetGuard shared URL risk engine v3.5
// Runs in Chrome extension pages, content scripts, the service worker, and Node tests.
(function exposeRiskEngine(root, factory) {
  const engine = factory();
  if (typeof module === 'object' && module.exports) module.exports = engine;
  root.NETGUARD_RISK_ENGINE = engine;
})(typeof globalThis !== 'undefined' ? globalThis : this, function createRiskEngine() {
  'use strict';

  const PHISHING_DOMAINS = [
    'paypa1.com', 'amazon-secure-login.com', 'g00gle.com', 'faceb00k.com',
    'netflix-billing-update.com', 'apple-id-verify.net', 'secure-bankofamerica.com',
    'microsoft-support-alert.com', 'login-instagram.xyz', 'verify-paypal.info',
    'account-google-verify.com', 'icloud-locked.net', 'ebay-account-verify.org',
    'dropbox-shared-files.com', 'linkedin-premium-free.com',
    'signin-paypal-account.com', 'update-amazon-account.net', 'google-security-alert.xyz',
  ];

  const MALWARE_DOMAINS = [
    'malware-download.ru', 'virus-host.cn', 'exploit-kit.io', 'botnet-c2.xyz',
    'ransomware-spread.tk', 'trojan-dropper.ml', 'keylogger-host.pw',
    'cryptominer-pool.ru', 'adware-injector.cn', 'spyware-collect.xyz',
  ];

  const TRACKER_DOMAINS = [
    'doubleclick.net', 'googletagmanager.com', 'facebook.com',
    'analytics.twitter.com', 'hotjar.com', 'mixpanel.com', 'segment.io',
    'amplitude.com', 'heap.io', 'fullstory.com', 'criteo.com', 'taboola.com',
  ];

  const LEGITIMATE_BRANDS = [
    ['paypal', ['paypal.com', 'paypalobjects.com']],
    ['amazon', ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazonaws.com']],
    ['google', ['google.com', 'google.lk', 'googleapis.com', 'googleusercontent.com']],
    ['apple', ['apple.com', 'icloud.com', 'apple.news']],
    ['microsoft', ['microsoft.com', 'microsoftonline.com', 'live.com']],
    ['netflix', ['netflix.com']],
    ['facebook', ['facebook.com', 'facebook.net', 'fb.com']],
    ['instagram', ['instagram.com']],
    ['dropbox', ['dropbox.com', 'dropboxapi.com']],
    ['linkedin', ['linkedin.com', 'linkedin.cn']],
  ];

  const PHISHING_HOST_PATTERNS = [
    /paypa1/i, /amaz0n/i, /g00gle/i, /faceb00k/i,
    /login[-.]secure/i, /secure[-.]login/i, /account[-.]verify/i,
    /verify[-.]account/i, /apple[-.]id[-.]verify/i,
    /microsoft[-.]support[-.]alert/i, /netflix[-.]billing/i,
  ];
  const RISKY_TLD = /\.(tk|ml|pw|xyz|ru|cn|top|club|gq|cf|ga)$/i;
  const MALWARE_WORDS = /(^|[.\-_/])(exploit|botnet|ransom|trojan|keylog|cryptominer|spyware|adware|malware|virus)([.\-_/]|$)/i;
  const CREDENTIAL_WORDS = /(^|[.\-_/])(login|signin|verify|account|billing|password|wallet|security|unlock|support)([.\-_/]|$)/i;
  const XSS_QUERY = /(<script[\s>]|javascript:|on\w+\s*=|document\.cookie|eval\s*\()/i;
  const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

  function domainMatches(hostname, domain) {
    return hostname === domain || hostname.endsWith(`.${domain}`);
  }

  function parseUrl(value) {
    try {
      const raw = String(value || '').trim();
      const candidate = /^[a-z][a-z\d+.-]*:/i.test(raw) ? raw : `https://${raw}`;
      const parsed = new URL(candidate);
      if (!['http:', 'https:'].includes(parsed.protocol)) return null;
      return parsed;
    } catch {
      return null;
    }
  }

  function finding(status, category, severity, score, label, reason, layer, signals = []) {
    return { status, category, severity, score, label, reason, layer, signals };
  }

  function safeFinding() {
    return finding('safe', 'safe', 'none', 0, 'URL IS SAFE',
      'No high-confidence URL threat signals were detected.', 'All Layers');
  }

  function analyzeUrl(value) {
    const parsed = parseUrl(value);
    if (!parsed) {
      return finding('warning', 'invalid-url', 'medium', 45, 'INVALID URL',
        'The address could not be validated as an HTTP or HTTPS website.', 'URL Validation');
    }

    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
    const hostAndPath = `${hostname}${parsed.pathname}`.toLowerCase();

    const phishingMatch = PHISHING_DOMAINS.find((domain) => domainMatches(hostname, domain));
    if (phishingMatch) {
      return finding('danger', 'phishing', 'critical', 100, 'PHISHING WEBSITE DETECTED',
        `This domain matches the NetGuard phishing intelligence list (${phishingMatch}).`,
        'Threat Intelligence', ['known-phishing-domain']);
    }

    const malwareMatch = MALWARE_DOMAINS.find((domain) => domainMatches(hostname, domain));
    if (malwareMatch) {
      return finding('danger', 'malware', 'critical', 100, 'MALWARE HOST DETECTED',
        `This domain matches the NetGuard malware intelligence list (${malwareMatch}).`,
        'Threat Intelligence', ['known-malware-domain']);
    }

    const spoofedBrand = LEGITIMATE_BRANDS.find(([brand, validDomains]) => (
      hostname.includes(brand) && !validDomains.some((domain) => domainMatches(hostname, domain))
    ));
    if (spoofedBrand) {
      return finding('danger', 'brand-spoofing', 'critical', 96, 'BRAND SPOOFING DETECTED',
        `The domain uses “${spoofedBrand[0]}” but is not an authorized ${spoofedBrand[0]} domain.`,
        'Heuristic Analysis', ['brand-name-mismatch']);
    }

    if (PHISHING_HOST_PATTERNS.some((pattern) => pattern.test(hostname))) {
      return finding('danger', 'phishing-pattern', 'high', 92, 'PHISHING PATTERN DETECTED',
        'The hostname contains a high-confidence credential-theft pattern.',
        'Heuristic Analysis', ['phishing-host-pattern']);
    }

    if (MALWARE_WORDS.test(hostAndPath) && (RISKY_TLD.test(hostname) || CREDENTIAL_WORDS.test(hostAndPath))) {
      return finding('danger', 'suspicious-keyword', 'high', 88, 'MALICIOUS URL PATTERN',
        'The address combines malware-related wording with other high-risk URL signals.',
        'Heuristic Analysis', ['malware-keyword', 'compound-risk']);
    }

    if (hostname.split('.').some((label) => label.startsWith('xn--')) && CREDENTIAL_WORDS.test(hostAndPath)) {
      return finding('danger', 'phishing', 'high', 86, 'DECEPTIVE DOMAIN DETECTED',
        'An internationalized hostname is combined with credential-related wording.',
        'Heuristic Analysis', ['punycode-host', 'credential-keyword']);
    }

    for (const [, valuePart] of parsed.searchParams) {
      if (XSS_QUERY.test(valuePart)) {
        return finding('danger', 'xss-attempt', 'critical', 98, 'XSS PAYLOAD DETECTED',
          'The address contains script-like input that may attempt to execute in the page.',
          'Content Security', ['xss-query-payload']);
      }
    }

    if (parsed.protocol === 'http:' && CREDENTIAL_WORDS.test(hostAndPath)) {
      return finding('danger', 'zero-trust-http', 'high', 82, 'UNENCRYPTED LOGIN RISK',
        'This credential-related page uses HTTP, so submitted information would not be encrypted.',
        'Zero Trust', ['unencrypted-http', 'credential-keyword']);
    }

    const tracker = TRACKER_DOMAINS.find((domain) => domainMatches(hostname, domain));
    if (tracker) {
      return finding('warning', 'tracker', 'medium', 55, 'TRACKER DOMAIN',
        'This address belongs to a known cross-site tracking service.',
        'Behavioral Analysis', ['known-tracker']);
    }

    if (RISKY_TLD.test(hostname)) {
      return finding('warning', 'high-risk-tld', 'medium', 55, 'HIGH-RISK DOMAIN ENDING',
        'This top-level domain needs extra caution, but it is not malicious by itself.',
        'Heuristic Analysis', ['high-risk-tld']);
    }

    if (IPV4.test(hostname)) {
      return finding('warning', 'dns-leak', 'medium', 50, 'DIRECT IP ACCESS',
        'The address bypasses normal hostname validation.', 'DNS Monitor', ['direct-ip']);
    }

    if (parsed.protocol === 'http:') {
      return finding('warning', 'zero-trust-http', 'high', 65, 'UNENCRYPTED CONNECTION',
        'This site does not use HTTPS encryption.', 'Zero Trust', ['unencrypted-http']);
    }

    return safeFinding();
  }

  return {
    analyzeUrl,
    domainMatches,
    parseUrl,
    PHISHING_DOMAINS: Object.freeze([...PHISHING_DOMAINS]),
    MALWARE_DOMAINS: Object.freeze([...MALWARE_DOMAINS]),
  };
});
