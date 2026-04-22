const db = require('./database'); // PostgreSQL pool
const ipRangeCheck = require('ip-range-check');

// Get client IP
function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() ||
         req.headers['x-real-ip'] ||
         req.connection.remoteAddress ||
         req.socket.remoteAddress ||
         req.connection.socket?.remoteAddress;
}

// Check if IP is allowed for a specific user
async function isIpAllowedForUser(ip, userId) {
  if (!ip) return false;
  // Normalize IPv6-mapped IPv4
  if (ip.startsWith('::ffff:')) ip = ip.substring(7);
  
  try {
    const result = await db.query(
      'SELECT ip_range FROM user_ip_whitelist WHERE user_id = $1',
      [userId]
    );
    const ranges = result.rows.map(r => r.ip_range);
    return ranges.some(range => ipRangeCheck(ip, range));
  } catch (err) {
    console.error('IP whitelist check error:', err);
    return false; // fail closed
  }
}

// Middleware to enforce per‑user whitelist
async function ipWhitelistMiddleware(req, res, next) {
  // Skip for static assets and public paths
  if (req.path.startsWith('/public') || req.path === '/login' || req.path === '/logout' || req.path === '/verify-2fa') {
    return next();
  }
  
  const userId = req.session.userId;
  if (!userId) {
    return next();
  }
  
  // ✅ Bypass IP check for admin and boss
  const userRole = req.session.userRole;
  if (userRole === 'admin' || userRole === 'boss') {
    logAccess(req, 'ALLOWED (admin/boss bypass)');
    return next();
  }
  
  const clientIp = getClientIp(req);
  const allowed = await isIpAllowedForUser(clientIp, userId);
  
  if (allowed) {
    logAccess(req, 'ALLOWED');
    return next();
  }
  
  logAccess(req, 'BLOCKED');
  req.session.destroy(() => {
    res.status(403).send(`
      <!DOCTYPE html>
      <html>
      <head><title>Access Denied</title><style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5;}</style></head>
      <body><h1 style="color:#333;">You are not belong in here.</h1></body>
      </html>
    `);
  });
}

// In-memory access logs (unchanged)
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
  console.log(`[${entry.status}] ${entry.ip} - ${entry.user} - ${entry.method} ${entry.path}`);
}

function getAccessLogs() {
  return [...accessLogs].reverse();
}

module.exports = {
  ipWhitelistMiddleware,
  getAccessLogs,
  getClientIp,
  logAccess,
  // Functions for admin panel
  getUserWhitelist: async (userId) => {
    const result = await db.query(
      'SELECT id, ip_range, label, created_at FROM user_ip_whitelist WHERE user_id = $1 ORDER BY created_at',
      [userId]
    );
    return result.rows;
  },
  addUserWhitelist: async (userId, ipRange, label) => {
    await db.query(
      'INSERT INTO user_ip_whitelist (user_id, ip_range, label) VALUES ($1, $2, $3) ON CONFLICT (user_id, ip_range) DO NOTHING',
      [userId, ipRange, label]
    );
  },
  removeUserWhitelist: async (entryId) => {
    await db.query('DELETE FROM user_ip_whitelist WHERE id = $1', [entryId]);
  }
};