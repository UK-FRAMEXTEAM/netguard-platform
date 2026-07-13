const dns = require('dns').promises;
const net = require('net');
const { domainToASCII } = require('url');

function isPrivateIPv4(address) {
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b, c] = parts;
  return a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224;
}

function isPrivateAddress(address) {
  const family = net.isIP(address);
  if (family === 4) return isPrivateIPv4(address);
  if (family !== 6) return true;

  const normalized = address.toLowerCase();
  if (normalized.startsWith('::ffff:')) return isPrivateIPv4(normalized.slice(7));
  return normalized === '::' || normalized === '::1' ||
    normalized.startsWith('fc') || normalized.startsWith('fd') ||
    normalized.startsWith('fe8') || normalized.startsWith('fe9') ||
    normalized.startsWith('fea') || normalized.startsWith('feb') ||
    normalized.startsWith('2001:db8');
}

async function resolvePublicHost(input) {
  const hostname = domainToASCII(String(input || '').trim().toLowerCase().replace(/\.$/, ''));
  if (!hostname || hostname.length > 253 || !/^[a-z0-9.-]+$/.test(hostname) || !hostname.includes('.')) {
    throw new Error('Enter a valid public hostname');
  }
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || net.isIP(hostname)) {
    throw new Error('Only public hostnames can be inspected');
  }

  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!records.length || records.some((record) => isPrivateAddress(record.address))) {
    throw new Error('Hostname does not resolve to a public address');
  }

  return { hostname, address: records[0].address, family: records[0].family };
}

module.exports = { resolvePublicHost, isPrivateAddress };
