const DEFAULT_SITE_SETTINGS = Object.freeze({
  telemetryEnabled: true,
  rateLimitEnabled: true,
  repeatProtectionEnabled: true,
  botDetectionEnabled: true,
  formShieldEnabled: true,
  recaptchaEnabled: true,
  clientErrorMonitoring: true,
  autoBlockEnabled: true,
  autoPostureScanEnabled: true,
  repeatWindowSeconds: 5,
  repeatMaxSubmissions: 2,
  burstWindowSeconds: 5,
  burstMaxRequests: 8,
  minuteMaxRequests: 60,
  blockMinutes: 15,
  autoScanIntervalHours: 24,
});

const SITE_BOOLEAN_SETTINGS = [
  'telemetryEnabled', 'rateLimitEnabled', 'repeatProtectionEnabled',
  'botDetectionEnabled', 'formShieldEnabled', 'recaptchaEnabled',
  'clientErrorMonitoring', 'autoBlockEnabled', 'autoPostureScanEnabled',
];

const SITE_NUMBER_SETTINGS = Object.freeze({
  repeatWindowSeconds: [1, 30],
  repeatMaxSubmissions: [1, 20],
  burstWindowSeconds: [1, 60],
  burstMaxRequests: [2, 200],
  minuteMaxRequests: [10, 2000],
  blockMinutes: [1, 1440],
  autoScanIntervalHours: [1, 168],
});

const PROFILE_SETTINGS = Object.freeze({
  balanced: DEFAULT_SITE_SETTINGS,
  strict: Object.freeze({
    ...DEFAULT_SITE_SETTINGS,
    burstMaxRequests: 5,
    minuteMaxRequests: 30,
    blockMinutes: 30,
    autoScanIntervalHours: 12,
  }),
});

function normalizeProfile(value) {
  return value === 'strict' || value === 'custom' ? value : 'balanced';
}

function sanitizeSiteSettings(incoming, base = DEFAULT_SITE_SETTINGS) {
  const result = { ...base };
  if (!incoming || typeof incoming !== 'object') return result;

  SITE_BOOLEAN_SETTINGS.forEach((key) => {
    if (typeof incoming[key] === 'boolean') result[key] = incoming[key];
  });
  Object.entries(SITE_NUMBER_SETTINGS).forEach(([key, [minimum, maximum]]) => {
    if (incoming[key] === undefined) return;
    const number = Number(incoming[key]);
    if (Number.isFinite(number)) result[key] = Math.min(maximum, Math.max(minimum, Math.round(number)));
  });
  return result;
}

function settingsForProfile(profile, incoming) {
  const normalized = normalizeProfile(profile);
  const base = normalized === 'strict' ? PROFILE_SETTINGS.strict : PROFILE_SETTINGS.balanced;
  return sanitizeSiteSettings(incoming, base);
}

module.exports = {
  DEFAULT_SITE_SETTINGS,
  PROFILE_SETTINGS,
  SITE_BOOLEAN_SETTINGS,
  SITE_NUMBER_SETTINGS,
  normalizeProfile,
  sanitizeSiteSettings,
  settingsForProfile,
};
