function normalizeEmail(value = '') {
  return String(value).trim().toLowerCase();
}

function normalizeUsername(value = '') {
  return String(value).trim().toLowerCase();
}

function adminUsername() {
  return normalizeUsername(process.env.ADMIN_USERNAME || 'admin');
}

function adminLoginEmail() {
  return normalizeEmail(process.env.ADMIN_LOGIN_EMAIL || 'admin@netguard.local');
}

function adminPassword() {
  return String(process.env.ADMIN_PASSWORD || '');
}

function adminLoginIsConfigured() {
  return Boolean(adminUsername() && adminPassword());
}

function isAdminUsername(value) {
  return normalizeUsername(value) === adminUsername();
}

function isOwnerEmail(value) {
  const email = normalizeEmail(value);
  if (!email) return false;
  const configuredOwner = normalizeEmail(process.env.ADMIN_EMAIL);
  return email === adminLoginEmail() || Boolean(configuredOwner && email === configuredOwner);
}

module.exports = {
  adminLoginEmail,
  adminLoginIsConfigured,
  adminPassword,
  adminUsername,
  isAdminUsername,
  isOwnerEmail,
  normalizeEmail,
};
