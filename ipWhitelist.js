const fs = require('fs');
const path = require('path');
const ipRangeCheck = require('ip-range-check');

const WHITELIST_FILE = path.join(__dirname, 'whitelist.json');
let whitelist = [];

// Load whitelist from file
function loadWhitelist() {
  try {
    if (fs.existsSync(WHITELIST_FILE)) {
      const data = fs.readFileSync(WHITELIST_FILE, 'utf8');
      whitelist = JSON.parse(data);
    } else {
      // Default: allow localhost and common private ranges
      whitelist = ['127.0.0.1', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];
      saveWhitelist();
    }
  } catch (err) {
    console.error('Error loading whitelist:', err);
    whitelist = ['127.0.0.1', '::1'];
  }
}

function saveWhitelist() {
  fs.writeFileSync(WHITELIST_FILE, JSON.stringify(whitelist, null, 2));
}

// Get client IP (considering proxies)
function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() ||
         req.headers['x-real-ip'] ||
         req.connection.remoteAddress ||
         req.socket.remoteAddress ||
         req.connection.socket?.remoteAddress;
}

// Check if IP is allowed
function isIpAllowed(ip) {
  if (!ip) return false;
  // Normalize IPv6-mapped IPv4
  if (ip.startsWith('::ffff:')) ip = ip.substring(7);
  return whitelist.some(range => ipRangeCheck(ip, range));
}

// Middleware to enforce whitelist (applied globally except login page maybe)
function ipWhitelistMiddleware(req, res, next) {
  const clientIp = getClientIp(req);
  if (isIpAllowed(clientIp)) {
    return next();
  }
  // Log blocked attempt
  logAccess(req, 'BLOCKED');
  res.status(403).send('Access denied: Your IP is not whitelisted.');
}

// In-memory log storage (max 1000 entries)
const accessLogs = [];
const MAX_LOGS = 1000;

function logAccess(req, status = 'ALLOWED') {
  const entry = {
    timestamp: new Date().toISOString(),
    ip: getClientIp(req),
    method: req.method,
    path: req.originalUrl,
    user: req.session?.userEmail || 'unauthenticated',
    status
  };
  accessLogs.push(entry);
  if (accessLogs.length > MAX_LOGS) accessLogs.shift();
  // Also console log
  console.log(`[${entry.status}] ${entry.ip} - ${entry.user} - ${entry.method} ${entry.path}`);
}

// Initialize
loadWhitelist();

module.exports = {
  ipWhitelistMiddleware,
  getWhitelist: () => [...whitelist],
  addToWhitelist: (entry) => {
    if (!whitelist.includes(entry)) {
      whitelist.push(entry);
      saveWhitelist();
      return true;
    }
    return false;
  },
  removeFromWhitelist: (entry) => {
    const index = whitelist.indexOf(entry);
    if (index > -1) {
      whitelist.splice(index, 1);
      saveWhitelist();
      return true;
    }
    return false;
  },
  getAccessLogs: () => [...accessLogs].reverse(), // newest first
  getClientIp,
  logAccess
};