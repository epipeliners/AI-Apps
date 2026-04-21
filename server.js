require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const pgSession = require('connect-pg-simple')(session);
const db = require('./database'); // PostgreSQL pool
const axios = require('axios');
const { ipWhitelistMiddleware, logAccess } = require('./ipWhitelist');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(session({
  store: new pgSession({
    pool: db,
    tableName: 'session'
  }),
  secret: process.env.SESSION_SECRET || 'devsecret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 days
}));

// Helper: require login
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

function hasModuleAccess(role, module) {
  const fullAccess = ['admin', 'boss'];
  const hrFull = ['leader'];
  const hrOwn = ['cs', 'joker'];
  const toolsOnly = ['user'];
  
  if (fullAccess.includes(role)) return true;
  
  if (module === 'hr') {
    return hrFull.includes(role) || hrOwn.includes(role);
  }
  if (module === 'hr_full') {
    return hrFull.includes(role) || fullAccess.includes(role);
  }
  if (module === 'calculator' || module === 'converter') {
    return true; // all logged-in users
  }
  return false;
}

// Helper: require admin
async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  try {
    const result = await db.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
    const role = result.rows[0].role;
    if (role !== 'admin' && role !== 'boss') {
      return res.status(403).send('Access denied');
    }
    next();
  } catch (err) {
    return res.status(500).send('Server error');
  }
}

// Custom reCAPTCHA v3 verification middleware
async function verifyRecaptcha(req, res, next) {
  const token = req.body.recaptcha_token;
  if (!token) {
    return res.render('login', { error: 'Captcha verification failed. Please try again.' });
  }

  try {
    const response = await axios.post(
      'https://www.google.com/recaptcha/api/siteverify',
      null,
      {
        params: {
          secret: process.env.RECAPTCHA_SECRET_KEY,
          response: token
        }
      }
    );

    const { success, score, action } = response.data;
    if (success && score >= 0.5 && action === 'login') {
      return next();
    } else {
      console.warn(`reCAPTCHA failed: success=${success}, score=${score}`);
      return res.render('login', { error: 'Suspicious activity detected. Please try again.' });
    }
  } catch (err) {
    console.error('reCAPTCHA verification error:', err);
    return res.render('login', { error: 'Captcha service error. Please try later.' });
  }
}

async function renumberDisplayOrders(userWeb, userRole) {
  try {
    let query;
    let params = [];
    if (userRole === 'admin' || userRole === 'boss') {
      // Renumber per web
      const webs = await db.query('SELECT DISTINCT web FROM phone_subscriptions');
      for (const row of webs.rows) {
        const web = row.web;
        await db.query(`
          UPDATE phone_subscriptions
          SET display_order = new_order
          FROM (
            SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS new_order
            FROM phone_subscriptions
            WHERE web = $1
          ) AS ranked
          WHERE phone_subscriptions.id = ranked.id AND phone_subscriptions.web = $1
        `, [web]);
      }
    } else {
      // Renumber only the user's web
      await db.query(`
        UPDATE phone_subscriptions
        SET display_order = new_order
        FROM (
          SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS new_order
          FROM phone_subscriptions
          WHERE web = $1
        ) AS ranked
        WHERE phone_subscriptions.id = ranked.id AND phone_subscriptions.web = $1
      `, [userWeb]);
    }
  } catch (err) {
    console.error('Renumbering error:', err);
  }
}

// ---------- Phone Tracker Module ----------
async function requirePhoneAccess(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  try {
    const result = await db.query('SELECT role, web_access FROM users WHERE id = $1', [req.session.userId]);
    const user = result.rows[0];
    if (user.role === 'admin') {
      req.userWebAccess = null; // admin sees all
      return next();
    }
    if (!user.web_access) {
      return res.status(403).send('Access denied – no web assigned');
    }
    req.userWebAccess = user.web_access;
    next();
  } catch (err) {
    return res.status(500).send('Server error');
  }
}

// HR access middleware (leader, cs, joker, admin, boss)
async function requireHRAccess(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  try {
    const result = await db.query('SELECT role, web_access FROM users WHERE id = $1', [req.session.userId]);
    const user = result.rows[0];
    const allowedRoles = ['admin', 'boss', 'leader', 'cs', 'joker'];
    if (!allowedRoles.includes(user.role)) {
      return res.status(403).send('Access denied');
    }
    req.userRole = user.role;
    req.userWeb = user.web_access;
    next();
  } catch (err) {
    return res.status(500).send('Server error');
  }
}

// ---------- Public Routes ----------
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', verifyRecaptcha, async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.render('login', { error: 'Invalid email or password' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.render('login', { error: 'Invalid email or password' });
    }

    // Check if 2FA is enabled
    if (user.twofa_enabled) {
      req.session.tempUserId = user.id;
      req.session.tempUserEmail = user.email;
      return res.redirect('/verify-2fa');
    }

    // No 2FA, log in directly
    req.session.userId = user.id;
    req.session.userEmail = user.email;
    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Server error' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// 2FA verification pages
app.get('/verify-2fa', (req, res) => {
  if (!req.session.tempUserId) {
    return res.redirect('/login');
  }
  res.render('verify-2fa', { error: null });
});

app.post('/verify-2fa', async (req, res) => {
  const { token } = req.body;
  const tempUserId = req.session.tempUserId;

  if (!tempUserId) {
    return res.redirect('/login');
  }

  try {
    const result = await db.query('SELECT * FROM users WHERE id = $1', [tempUserId]);
    const user = result.rows[0];

    if (!user || !user.twofa_secret) {
      return res.redirect('/login');
    }

    const verified = speakeasy.totp.verify({
      secret: user.twofa_secret,
      encoding: 'base32',
      token: token,
      window: 1
    });

    if (verified) {
      req.session.userId = user.id;
      req.session.userEmail = user.email;
      delete req.session.tempUserId;
      delete req.session.tempUserEmail;
      return res.redirect('/dashboard');
    } else {
      res.render('verify-2fa', { error: 'Invalid 2FA code. Try again.' });
    }
  } catch (err) {
    console.error(err);
    res.render('verify-2fa', { error: 'Server error' });
  }
});

// ---------- Dashboard ----------
app.get('/dashboard', requireLogin, async (req, res) => {
  try {
    const result = await db.query('SELECT email, role FROM users WHERE id = $1', [req.session.userId]);
    if (result.rows.length === 0) return res.redirect('/login');
    const user = result.rows[0];
    res.render('dashboard', { email: user.email, role: user.role });
  } catch (err) {
    res.redirect('/login');
  }
});

// ---------- Profile & 2FA ----------
app.get('/profile', requireLogin, async (req, res) => {
  try {
    const result = await db.query('SELECT email, twofa_enabled, role FROM users WHERE id = $1', [req.session.userId]);
    const user = result.rows[0];
    res.render('profile', {
      email: user.email,
      twofaEnabled: user.twofa_enabled,
      role: user.role,
      qrCode: null,
      secret: null,
      error: null,
      success: null
    });
  } catch (err) {
    res.redirect('/dashboard');
  }
});

app.get('/phone-tracker', requireLogin, requirePhoneAccess, async (req, res) => {
  try {
    const userWeb = req.userWebAccess;
    let query = 'SELECT * FROM phone_subscriptions';
    let params = [];
    let whereClause = '';
    
    if (userWeb) {
      whereClause = ' WHERE web = $1';
      query += ' ORDER BY display_order, id';
      const result = await db.query(query, params);
      params.push(userWeb);
    }
    
    // Check if reminder filter is active
    const showReminder = req.query.reminder === 'true';
    if (showReminder) {
      const sixtyDaysFromNow = new Date();
      sixtyDaysFromNow.setDate(sixtyDaysFromNow.getDate() + 60);
      const today = new Date().toISOString().split('T')[0];
      const future = sixtyDaysFromNow.toISOString().split('T')[0];
      
      whereClause = whereClause 
        ? `${whereClause} AND expired BETWEEN $${params.length+1} AND $${params.length+2}`
        : ` WHERE expired BETWEEN $1 AND $2`;
      if (!userWeb) {
        params = [today, future];
      } else {
        params.push(today, future);
      }
    }
    
    query += whereClause + ' ORDER BY display_order, id';
    const result = await db.query(query, params);
    
    const userRole = (await db.query('SELECT role FROM users WHERE id=$1', [req.session.userId])).rows[0].role;
    res.render('phone-tracker/index', {
      subscriptions: result.rows,
      showReminder,
      error: null,
      success: null,
      role: userRole,
      canEdit: true, // all logged-in users with access can edit their web's entries
      userWeb
    });
  } catch (err) {
    console.error(err);
    res.render('phone-tracker/index', { subscriptions: [], error: 'Failed to load data', success: null });
  }
});

app.get('/phone-tracker/bulk', requireLogin, requirePhoneAccess, async (req, res) => {
  const userRole = (await db.query('SELECT role FROM users WHERE id=$1', [req.session.userId])).rows[0].role;
  res.render('phone-tracker/bulk', { error: null, role: userRole });
});

app.post('/phone-tracker/bulk', requireLogin, requirePhoneAccess, async (req, res) => {
  const { data } = req.body;
  const userWeb = req.userWebAccess;
  const userId = req.session.userId;

  const lines = data.split('\n').filter(line => line.trim() !== '');
  const errors = [];
  const success = [];

  // Month mapping (extended)
  const monthMap = {
    'jan': '01', 'januari': '01',
    'feb': '02', 'februari': '02',
    'mar': '03', 'maret': '03',
    'apr': '04', 'april': '04',
    'mei': '05', 'may': '05',
    'jun': '06', 'juni': '06',
    'jul': '07', 'juli': '07',
    'agt': '08', 'agustus': '08', 'aug': '08',
    'sep': '09', 'september': '09',
    'okt': '10', 'oktober': '10', 'oct': '10',
    'nov': '11', 'november': '11',
    'des': '12', 'desember': '12', 'dec': '12'
  };

  function parseIndonesianDate(dateStr) {
    let cleaned = dateStr.trim().replace(/[\s\/]+/g, '-');
    const match = cleaned.match(/^(\d{1,2})-([A-Za-z]{3,})-(\d{4})$/i);
    if (!match) return null;
    const day = match[1].padStart(2, '0');
    const monthAbbr = match[2].toLowerCase();
    const year = match[3];
    const month = monthMap[monthAbbr];
    if (!month) return null;
    return `${year}-${month}-${day}`;
  }

  for (const line of lines) {
    const trimmedLine = line.trim();
    
    // Determine delimiter
    let parts = [];
    if (trimmedLine.includes('\t')) {
      parts = trimmedLine.split('\t');
    } else {
      parts = trimmedLine.split(/\s{2,}/);
      if (parts.length < 5) {
        const singleSpaceParts = trimmedLine.split(/\s+/);
        if (singleSpaceParts.length >= 5) {
          parts = singleSpaceParts;
        }
      }
    }

    // Pad parts to at least 9 elements
    while (parts.length < 9) parts.push('');

    const display_order = parts[0]?.trim() || '';
    const name = parts[1]?.trim() || '';
    const bank = parts[2]?.trim() || '';
    const code = parts[3]?.trim() || '';
    const phone = parts[4]?.trim() || '';
    const expiredRaw = parts[5]?.trim() || '';
    
    // Handle remaining fields (notes, web, credit)
    let remaining = parts.slice(6).join(' ').trim();
    let notes = '';
    let web = '';
    let credit = '';

    // Extract credit (numeric at end)
    const creditMatch = remaining.match(/([\d.,]+)$/);
    if (creditMatch) {
      credit = creditMatch[1];
      remaining = remaining.slice(0, creditMatch.index).trim();
    }

    if (userWeb) {
      web = userWeb;
      notes = remaining;
    } else {
      const words = remaining.split(/\s+/);
      if (words.length >= 2) {
        web = words.pop();
        notes = words.join(' ');
      } else {
        notes = remaining;
      }
    }

    // Validation
    if (!name || !phone || !expiredRaw) {
      errors.push(`Missing required fields: ${trimmedLine.substring(0, 60)}...`);
      continue;
    }

    // Duplicate check
    try {
      const existing = await db.query(
        'SELECT id FROM phone_subscriptions WHERE phone = $1',
        [phone]
      );
      if (existing.rows.length > 0) {
        errors.push(`Skipped duplicate phone: ${phone} (${name})`);
        continue;
      }
    } catch (err) {
      errors.push(`DB error checking duplicate for ${phone}: ${err.message}`);
      continue;
    }

    // Parse date
    let expired;
    if (/^\d{4}-\d{2}-\d{2}$/.test(expiredRaw)) {
      expired = expiredRaw;
    } else {
      expired = parseIndonesianDate(expiredRaw);
      if (!expired) {
        errors.push(`Invalid date format: "${expiredRaw}" – expected DD-MMM-YYYY`);
        continue;
      }
    }

    // Insert
    try {
      await db.query(
        `INSERT INTO phone_subscriptions 
         (display_order, name, bank, code, phone, expired, notes, web, credit, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [display_order, name, bank, code, phone, expired, notes, web, credit, userId]
      );
      success.push(`Added: ${name}`);
    } catch (err) {
      errors.push(`DB insert error for ${name}: ${err.message}`);
    }
  }

  const userRole = (await db.query('SELECT role FROM users WHERE id=$1', [req.session.userId])).rows[0].role;
  res.render('phone-tracker/bulk', {
    error: errors.length ? errors.join('<br>') : null,
    success: success.length ? `Successfully added ${success.length} records.` : null,
    role: userRole
  });
});

// Single entry form
app.get('/phone-tracker/create', requireLogin, requirePhoneAccess, async (req, res) => {
  const userRole = (await db.query('SELECT role FROM users WHERE id=$1', [req.session.userId])).rows[0].role;
  res.render('phone-tracker/create', { error: null, role: userRole, userWeb: req.userWebAccess });
});

app.post('/phone-tracker/create', requireLogin, requirePhoneAccess, async (req, res) => {
  const { display_order, name, bank, code, phone, expired, notes, web, credit } = req.body;
  const userWeb = req.userWebAccess;
  const userId = req.session.userId;

  // Convert date if needed (though the form uses type="date", but just in case)
  let finalExpired = expired;
  // If it came as DD-MMM-YYYY, convert (but the form should give YYYY-MM-DD)
  if (expired && !/^\d{4}-\d{2}-\d{2}$/.test(expired)) {
    finalExpired = parseIndonesianDate(expired);
    if (!finalExpired) {
      const userRole = (await db.query('SELECT role FROM users WHERE id=$1', [userId])).rows[0].role;
      return res.render('phone-tracker/create', { error: 'Invalid date format', role: userRole, userWeb });
    }
  }

  let finalWeb = web;
  if (userWeb) {
    finalWeb = userWeb;
  }

  try {
    await db.query(
      `INSERT INTO phone_subscriptions (display_order, name, bank, code, phone, expired, notes, web, credit, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [display_order, name, bank, code, phone, finalExpired, notes, finalWeb, credit, userId]
    );
    res.redirect('/phone-tracker?success=Entry added');
  } catch (err) {
    const userRole = (await db.query('SELECT role FROM users WHERE id=$1', [userId])).rows[0].role;
    res.render('phone-tracker/create', { error: 'Failed to add entry: ' + err.message, role: userRole, userWeb });
  }
});

app.get('/phone-tracker/:id/edit', requireLogin, requirePhoneAccess, async (req, res) => {
  try {
    const id = req.params.id;
    const userWeb = req.userWebAccess;
    
    let query = 'SELECT * FROM phone_subscriptions WHERE id = $1';
    let params = [id];
    if (userWeb) {
      query += ' AND web = $2';
      params.push(userWeb);
    }
    
    const result = await db.query(query, params);
    if (result.rows.length === 0) {
      return res.status(403).send('Not found or access denied');
    }
    
    const userRole = (await db.query('SELECT role FROM users WHERE id=$1', [req.session.userId])).rows[0].role;
    res.render('phone-tracker/edit', { sub: result.rows[0], error: null, role: userRole });
  } catch (err) {
    res.redirect('/phone-tracker');
  }
});

app.post('/phone-tracker/:id/edit', requireLogin, requirePhoneAccess, async (req, res) => {
  const id = req.params.id;
  const { phone, expired, notes } = req.body;
  const userWeb = req.userWebAccess;
  
  try {
    // Verify ownership
    let checkQuery = 'SELECT * FROM phone_subscriptions WHERE id = $1';
    let checkParams = [id];
    if (userWeb) {
      checkQuery += ' AND web = $2';
      checkParams.push(userWeb);
    }
    const check = await db.query(checkQuery, checkParams);
    if (check.rows.length === 0) {
      return res.status(403).send('Access denied');
    }
    
    await db.query(
      `UPDATE phone_subscriptions SET phone=$1, expired=$2, notes=$3, credit=$4, updated_at=NOW() WHERE id=$5`,
      [phone, expired, notes, credit, id]
    );
    
    res.redirect('/phone-tracker?success=Entry updated');
  } catch (err) {
    const sub = (await db.query('SELECT * FROM phone_subscriptions WHERE id=$1', [id])).rows[0];
    const userRole = (await db.query('SELECT role FROM users WHERE id=$1', [req.session.userId])).rows[0].role;
    res.render('phone-tracker/edit', { sub, error: 'Update failed', role: userRole });
  }
});

app.post('/profile/enable-2fa', requireLogin, async (req, res) => {
  const secret = speakeasy.generateSecret({
    length: 20,
    name: `AI Apps (${req.session.userEmail})`
  });

  try {
    await db.query('UPDATE users SET twofa_secret = $1 WHERE id = $2', [secret.base32, req.session.userId]);
    const qrCodeDataURL = await QRCode.toDataURL(secret.otpauth_url);
    const userResult = await db.query('SELECT email, twofa_enabled, role FROM users WHERE id = $1', [req.session.userId]);
    const user = userResult.rows[0];
    res.render('profile', {
      email: user.email,
      twofaEnabled: user.twofa_enabled,
      role: user.role,
      qrCode: qrCodeDataURL,
      secret: secret.base32,
      error: null,
      success: null
    });
  } catch (err) {
    res.redirect('/profile');
  }
});

app.post('/profile/verify-2fa', requireLogin, async (req, res) => {
  const { token } = req.body;

  try {
    const result = await db.query('SELECT twofa_secret, email, twofa_enabled, role FROM users WHERE id = $1', [req.session.userId]);
    const user = result.rows[0];

    if (!user.twofa_secret) return res.redirect('/profile');

    const verified = speakeasy.totp.verify({
      secret: user.twofa_secret,
      encoding: 'base32',
      token: token,
      window: 1
    });

    if (verified) {
      await db.query('UPDATE users SET twofa_enabled = 1 WHERE id = $1', [req.session.userId]);
      return res.redirect('/profile?success=2FA enabled');
    } else {
      const otpauthUrl = `otpauth://totp/AI%20Apps:${encodeURIComponent(user.email)}?secret=${user.twofa_secret}&issuer=AI%20Apps`;
      const qrCodeDataURL = await QRCode.toDataURL(otpauthUrl);
      res.render('profile', {
        email: user.email,
        twofaEnabled: user.twofa_enabled,
        role: user.role,
        qrCode: qrCodeDataURL,
        secret: user.twofa_secret,
        error: 'Invalid token. Try again.',
        success: null
      });
    }
  } catch (err) {
    res.redirect('/profile');
  }
});

app.post('/phone-tracker/:id/delete', requireLogin, requireAdmin, async (req, res) => {
  await db.query('DELETE FROM phone_subscriptions WHERE id=$1', [req.params.id]);
  res.redirect('/phone-tracker?success=Entry deleted');
});

// Date formatting helper for DD-MMM-YYYY
function formatDateDDMMMYYYY(dateString) {
  if (!dateString) return '';
  const date = new Date(dateString);
  if (isNaN(date)) return dateString;
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const day = String(date.getDate()).padStart(2, '0');
  const month = months[date.getMonth()];
  const year = date.getFullYear();
  return `${day}-${month}-${year}`;
}

// Make it available to all views
app.locals.formatDate = formatDateDDMMMYYYY;

// ---------- Admin Routes ----------
app.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const usersResult = await db.query('SELECT id, email, role, twofa_enabled FROM users ORDER BY id');
    const currentUserResult = await db.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
    res.render('admin/users', {
      users: usersResult.rows,
      error: null,
      success: null,
      currentUserId: req.session.userId,
      role: currentUserResult.rows[0].role
    });
  } catch (err) {
    res.render('admin/users', {
      users: [],
      error: 'Failed to load users',
      success: null,
      currentUserId: req.session.userId,
      role: 'admin'
    });
  }
});

app.get('/admin/users/create', requireAdmin, async (req, res) => {
  try {
    const result = await db.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
    res.render('admin/create-user', { error: null, role: result.rows[0].role });
  } catch (err) {
    res.redirect('/admin/users');
  }
});

app.post('/admin/users/create', requireAdmin, async (req, res) => {
  const { email, password, role } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    await db.query('INSERT INTO users (email, password, role) VALUES ($1, $2, $3)',
      [email, hashed, role || 'user']);
    res.redirect('/admin/users?success=User created');
  } catch (err) {
    const currentUserResult = await db.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
    res.render('admin/create-user', {
      error: 'Email already exists',
      role: currentUserResult.rows[0].role
    });
  }
});

app.get('/admin/users/:id/edit', requireAdmin, async (req, res) => {
  const targetUserId = req.params.id;
  try {
    const currentUserResult = await db.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
    const userResult = await db.query('SELECT id, email, role FROM users WHERE id = $1', [targetUserId]);
    if (userResult.rows.length === 0) return res.redirect('/admin/users');
    res.render('admin/edit-user', {
      user: userResult.rows[0],
      error: null,
      role: currentUserResult.rows[0].role
    });
  } catch (err) {
    res.redirect('/admin/users');
  }
});

// IP Whitelist Management
app.get('/admin/whitelist', requireAdmin, (req, res) => {
  const { getWhitelist, getAccessLogs } = require('./ipWhitelist');
  res.render('admin/whitelist', {
    whitelist: getWhitelist(),
    logs: getAccessLogs().slice(0, 100), // show last 100
    error: null,
    success: null,
    role: 'admin' // or pass actual role
  });
});

app.post('/admin/whitelist/add', requireAdmin, (req, res) => {
  const { ip } = req.body;
  const { addToWhitelist } = require('./ipWhitelist');
  if (addToWhitelist(ip)) {
    res.redirect('/admin/whitelist?success=IP added');
  } else {
    res.redirect('/admin/whitelist?error=IP already exists');
  }
});

app.post('/admin/whitelist/remove', requireAdmin, (req, res) => {
  const { ip } = req.body;
  const { removeFromWhitelist } = require('./ipWhitelist');
  removeFromWhitelist(ip);
  res.redirect('/admin/whitelist?success=IP removed');
});

app.post('/admin/users/:id/edit', requireAdmin, async (req, res) => {
  const { email, password, role } = req.body;
  const userId = req.params.id;
  try {
    if (password && password.trim() !== '') {
      const hashed = await bcrypt.hash(password, 10);
      await db.query('UPDATE users SET email = $1, password = $2, role = $3 WHERE id = $4',
        [email, hashed, role, userId]);
    } else {
      await db.query('UPDATE users SET email = $1, role = $2 WHERE id = $3',
        [email, role, userId]);
    }
    res.redirect('/admin/users?success=User updated');
  } catch (err) {
    const currentUserResult = await db.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
    const userResult = await db.query('SELECT id, email, role FROM users WHERE id = $1', [userId]);
    res.render('admin/edit-user', {
      user: userResult.rows[0],
      error: 'Update failed. Email may already exist.',
      role: currentUserResult.rows[0].role
    });
  }
});

app.post('/admin/users/:id/delete', requireAdmin, async (req, res) => {
  const userId = req.params.id;
  if (userId == req.session.userId) {
    return res.redirect('/admin/users?error=Cannot delete your own admin account');
  }
  try {
    await db.query('DELETE FROM users WHERE id = $1', [userId]);
    res.redirect('/admin/users?success=User deleted');
  } catch (err) {
    res.redirect('/admin/users?error=Delete failed');
  }
});

// ---------- Tools ----------
app.get('/tools/calculator', requireLogin, async (req, res) => {
  try {
    const result = await db.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
    res.render('calculator', { role: result.rows[0].role });
  } catch (err) {
    res.redirect('/login');
  }
});

// Format Converter Tool
app.get('/tools/converter', requireLogin, async (req, res) => {
  try {
    const result = await db.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
    res.render('converter', { role: result.rows[0].role });
  } catch (err) {
    res.redirect('/login');
  }
});

// Single entry form
app.get('/phone-tracker/create', requireLogin, requirePhoneAccess, async (req, res) => {
  const userRole = (await db.query('SELECT role FROM users WHERE id=$1', [req.session.userId])).rows[0].role;
  res.render('phone-tracker/create', { error: null, role: userRole, userWeb: req.userWebAccess });
});

app.post('/phone-tracker/create', requireLogin, requirePhoneAccess, async (req, res) => {
  const { display_order, name, bank, code, phone, expired, notes, credit } = req.body;
  let web = req.body.web;
  const userWeb = req.userWebAccess;
  const userId = req.session.userId;

  // Force web if user is restricted
  if (userWeb) {
    web = userWeb;
  }

  try {
    await db.query(
      `INSERT INTO phone_subscriptions 
       (display_order, name, bank, code, phone, expired, notes, web, credit, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [display_order || null, name, bank, code, phone, expired, notes, web, credit, userId]
    );
    res.redirect('/phone-tracker?success=Entry created');
  } catch (err) {
    const userRole = (await db.query('SELECT role FROM users WHERE id=$1', [req.session.userId])).rows[0].role;
    res.render('phone-tracker/create', { error: 'Failed to create: ' + err.message, role: userRole, userWeb });
  }
});

app.post('/phone-tracker/bulk-delete', requireLogin, requirePhoneAccess, async (req, res) => {
  const { ids } = req.body;
  if (!ids) return res.redirect('/phone-tracker');

  const idArray = Array.isArray(ids) ? ids : [ids];
  const userWeb = req.userWebAccess;
  const userId = req.session.userId;
  const userRole = (await db.query('SELECT role FROM users WHERE id=$1', [userId])).rows[0].role;

  try {
    // Build query with web restriction for non-admin/boss
    let query = 'DELETE FROM phone_subscriptions WHERE id = ANY($1)';
    let params = [idArray];
    if (userRole !== 'admin' && userRole !== 'boss') {
      query += ' AND web = $2';
      params.push(userWeb);
    }
    await db.query(query, params);
    
    // Renumber display_order for the affected webs
    await renumberDisplayOrders(userWeb, userRole);
    
    res.redirect('/phone-tracker?success=Selected entries deleted');
  } catch (err) {
    console.error(err);
    res.redirect('/phone-tracker?error=Delete failed');
  }
});

app.post('/phone-tracker/:id/delete', requireLogin, requirePhoneAccess, async (req, res) => {
  const id = req.params.id;
  const userWeb = req.userWebAccess;
  const userRole = (await db.query('SELECT role FROM users WHERE id=$1', [req.session.userId])).rows[0].role;

  try {
    let query = 'DELETE FROM phone_subscriptions WHERE id = $1';
    let params = [id];
    if (userRole !== 'admin' && userRole !== 'boss') {
      query += ' AND web = $2';
      params.push(userWeb);
    }
    await db.query(query, params);
    await renumberDisplayOrders(userWeb, userRole);
    res.redirect('/phone-tracker?success=Entry deleted');
  } catch (err) {
    res.redirect('/phone-tracker?error=Delete failed');
  }
});

// ---------- HR Module ----------

// List employees (with visibility rules)
app.get('/hr/employees', requireLogin, requireHRAccess, async (req, res) => {
  try {
    const userRole = req.userRole;
    const userWeb = req.userWeb;
    const userId = req.session.userId;
    
    let query = 'SELECT * FROM employees';
    let params = [];
    let whereConditions = [];
    
    // Non-admin/boss: restrict by web or user_id
    if (userRole !== 'admin' && userRole !== 'boss') {
      if (userRole === 'leader') {
        // Leader sees all employees in their assigned web
        if (userWeb) {
          whereConditions.push('web = $1');
          params.push(userWeb);
        }
      } else if (userRole === 'cs' || userRole === 'joker') {
        // CS/Joker see only their own linked employee record
        whereConditions.push('user_id = $1');
        params.push(userId);
      }
    }
    
    if (whereConditions.length) {
      query += ' WHERE ' + whereConditions.join(' AND ');
    }
    query += ' ORDER BY id';
    
    const result = await db.query(query, params);
    const employees = result.rows;
    
    res.render('hr/employees', {
      employees,
      error: null,
      success: null,
      role: userRole,
      canEdit: ['admin', 'boss', 'leader'].includes(userRole)
    });
  } catch (err) {
    console.error(err);
    res.render('hr/employees', { employees: [], error: 'Failed to load employees', success: null });
  }
});

// Form to add employee (admin, boss, leader only)
app.get('/hr/employees/create', requireLogin, requireHRAccess, async (req, res) => {
  const userRole = req.userRole;
  if (!['admin', 'boss', 'leader'].includes(userRole)) {
    return res.status(403).send('Access denied');
  }
  // Fetch users for linking (for admin/boss)
  let users = [];
  if (userRole === 'admin' || userRole === 'boss') {
    users = (await db.query('SELECT id, email FROM users ORDER BY email')).rows;
  }
  res.render('hr/create-employee', { error: null, role: userRole, users, userWeb: req.userWeb });
});

app.post('/hr/employees/create', requireLogin, requireHRAccess, async (req, res) => {
  const userRole = req.userRole;
  if (!['admin', 'boss', 'leader'].includes(userRole)) {
    return res.status(403).send('Access denied');
  }
  const { employee_code, full_name, email, phone, department, position, join_date, status, user_id, web } = req.body;
  const assignedWeb = (userRole === 'leader') ? req.userWeb : web;
  
  try {
    await db.query(
      `INSERT INTO employees (employee_code, full_name, email, phone, department, position, join_date, status, user_id, web)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [employee_code, full_name, email, phone, department, position, join_date, status || 'active', user_id || null, assignedWeb || null]
    );
    res.redirect('/hr/employees?success=Employee added');
  } catch (err) {
    let users = [];
    if (userRole === 'admin' || userRole === 'boss') {
      users = (await db.query('SELECT id, email FROM users ORDER BY email')).rows;
    }
    res.render('hr/create-employee', { error: 'Employee code may already exist', role: userRole, users, userWeb: req.userWeb });
  }
});

// Edit form (admin, boss, leader only)
app.get('/hr/employees/:id/edit', requireLogin, requireHRAccess, async (req, res) => {
  const userRole = req.userRole;
  if (!['admin', 'boss', 'leader'].includes(userRole)) {
    return res.status(403).send('Access denied');
  }
  try {
    const id = req.params.id;
    const result = await db.query('SELECT * FROM employees WHERE id = $1', [id]);
    if (result.rows.length === 0) return res.redirect('/hr/employees');
    const employee = result.rows[0];
    
    let users = [];
    if (userRole === 'admin' || userRole === 'boss') {
      users = (await db.query('SELECT id, email FROM users ORDER BY email')).rows;
    }
    res.render('hr/edit-employee', { employee, error: null, role: userRole, users, userWeb: req.userWeb });
  } catch (err) {
    res.redirect('/hr/employees');
  }
});

app.post('/hr/employees/:id/edit', requireLogin, requireHRAccess, async (req, res) => {
  const userRole = req.userRole;
  if (!['admin', 'boss', 'leader'].includes(userRole)) {
    return res.status(403).send('Access denied');
  }
  const id = req.params.id;
  const { employee_code, full_name, email, phone, department, position, join_date, status, user_id, web } = req.body;
  const assignedWeb = (userRole === 'leader') ? req.userWeb : web;
  
  try {
    await db.query(
      `UPDATE employees SET employee_code=$1, full_name=$2, email=$3, phone=$4, department=$5, position=$6, join_date=$7, status=$8, user_id=$9, web=$10, updated_at=NOW()
       WHERE id=$11`,
      [employee_code, full_name, email, phone, department, position, join_date, status, user_id || null, assignedWeb || null, id]
    );
    res.redirect('/hr/employees?success=Employee updated');
  } catch (err) {
    const employee = (await db.query('SELECT * FROM employees WHERE id=$1', [id])).rows[0];
    let users = [];
    if (userRole === 'admin' || userRole === 'boss') {
      users = (await db.query('SELECT id, email FROM users ORDER BY email')).rows;
    }
    res.render('hr/edit-employee', { employee, error: 'Update failed', role: userRole, users, userWeb: req.userWeb });
  }
});

// Delete (admin, boss only)
app.post('/hr/employees/:id/delete', requireLogin, requireHRAccess, async (req, res) => {
  const userRole = req.userRole;
  if (!['admin', 'boss'].includes(userRole)) {
    return res.status(403).send('Access denied');
  }
  await db.query('DELETE FROM employees WHERE id=$1', [req.params.id]);
  res.redirect('/hr/employees?success=Employee deleted');
});

// ---------- Start Server ----------
app.listen(PORT, () => {
  console.log(`AI Apps running on http://localhost:${PORT}`);
});