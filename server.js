require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const pgSession = require('connect-pg-simple')(session);
const db = require('./database'); // PostgreSQL pool
const axios = require('axios');
const { ipWhitelistMiddleware } = require('./ipWhitelist');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const multer = require('multer');

// Memory storage (file in buffer)
const storage = multer.memoryStorage();

const upload = multer({
  storage: storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'image/png') {
      cb(null, true);
    } else {
      cb(new Error('Only PNG images are allowed'), false);
    }
  }
});
const PORT = process.env.PORT || 3000;

// Supabase client for storage
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY; // Use service_role for server-side
const supabase = createClient(supabaseUrl, supabaseKey);

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
app.use(ipWhitelistMiddleware);

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
    if (userRole === 'admin' || userRole === 'boss') {
      // Renumber globally but per web, ordered by code
      const webs = await db.query('SELECT DISTINCT web FROM phone_subscriptions');
      for (const row of webs.rows) {
        const web = row.web;
        await db.query(`
          UPDATE phone_subscriptions
          SET display_order = new_order
          FROM (
            SELECT id, ROW_NUMBER() OVER (ORDER BY code, id) AS new_order
            FROM phone_subscriptions
            WHERE web = $1
          ) AS ranked
          WHERE phone_subscriptions.id = ranked.id AND phone_subscriptions.web = $1
        `, [web]);
      }
    } else {
      // Renumber only the user's web, ordered by code
      await db.query(`
        UPDATE phone_subscriptions
        SET display_order = new_order
        FROM (
          SELECT id, ROW_NUMBER() OVER (ORDER BY code, id) AS new_order
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
    
    // ✅ ALWAYS store the role
    req.userRole = user.role;

    if (user.role === 'admin' || user.role === 'boss') {
      req.userWebAccess = null;          // see all webs
      return next();
    }
    if (!user.web_access) {
      return res.status(403).send('Access denied – no web assigned');
    }
    req.userWebAccess = user.web_access;  // restrict to this web
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

async function uploadPhotoToSupabase(fileBuffer, fileName) {
  const bucketName = 'employee-photos';
  const filePath = `employees/${Date.now()}-${fileName}`;
  
  const { data, error } = await supabase.storage
    .from(bucketName)
    .upload(filePath, fileBuffer, {
      contentType: 'image/png',
      upsert: false
    });
  
  if (error) throw error;
  
  // Get public URL
  const { data: publicUrlData } = supabase.storage
    .from(bucketName)
    .getPublicUrl(filePath);
  
  return publicUrlData.publicUrl;
}

async function deletePhotoFromSupabase(photoUrl) {
  if (!photoUrl) return;
  try {
    const url = new URL(photoUrl);
    const pathParts = url.pathname.split('/');
    const bucketIndex = pathParts.indexOf('employee-photos');
    if (bucketIndex === -1) return;
    const filePath = pathParts.slice(bucketIndex + 1).join('/');
    await supabase.storage.from('employee-photos').remove([filePath]);
  } catch (err) {
    console.error('Failed to delete photo:', err);
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
      req.session.userRole = user.role;
      return res.redirect('/verify-2fa');
    }

    // No 2FA, log in directly
    req.session.userId = user.id;
    req.session.userEmail = user.email;
    req.session.userRole = user.role;
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
    const userRole = req.userRole;
    const { web: filterWeb, startDate, endDate } = req.query;
    const exportQuery = new URLSearchParams(req.query).toString();

    let query = 'SELECT * FROM phone_subscriptions';
    let params = [];
    let conditions = [];

    // Row‑level security
    if (userWeb) {
      conditions.push('web = $' + (params.length + 1));
      params.push(userWeb);
    } else if (userRole !== 'admin' && userRole !== 'boss') {
      conditions.push('1 = 0');
    }

    // Web filter (admin/boss)
    if ((userRole === 'admin' || userRole === 'boss') && filterWeb && filterWeb !== 'all') {
      conditions.push('web = $' + (params.length + 1));
      params.push(filterWeb);
    }

    // Date range filter
    if (startDate && endDate) {
      conditions.push(`expired BETWEEN $${params.length+1} AND $${params.length+2}`);
      params.push(startDate, endDate);
    }

    if (conditions.length) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    query += ' ORDER BY code, id';

    const result = await db.query(query, params);
    const subscriptions = result.rows;

    // Summary counts (using same conditions)
    let summary = { active: 0, expiring_soon: 0, expired: 0 };
    if (conditions.length) {
      const summaryQuery = `
        SELECT
          COUNT(*) FILTER (WHERE expired >= CURRENT_DATE) AS active,
          COUNT(*) FILTER (WHERE expired BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '60 days') AS expiring_soon,
          COUNT(*) FILTER (WHERE expired < CURRENT_DATE) AS expired
        FROM phone_subscriptions
        WHERE ${conditions.join(' AND ')}
      `;
      const summaryResult = await db.query(summaryQuery, params);
      summary = summaryResult.rows[0];
    } else {
      const summaryResult = await db.query(`
        SELECT
          COUNT(*) FILTER (WHERE expired >= CURRENT_DATE) AS active,
          COUNT(*) FILTER (WHERE expired BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '60 days') AS expiring_soon,
          COUNT(*) FILTER (WHERE expired < CURRENT_DATE) AS expired
        FROM phone_subscriptions
      `);
      summary = summaryResult.rows[0];
    }

    // Distinct webs for admin filter
    let webs = [];
    if (userRole === 'admin' || userRole === 'boss') {
      const webQuery = 'SELECT DISTINCT web FROM phone_subscriptions ORDER BY web';
      const webResult = await db.query(webQuery);
      webs = webResult.rows.map(r => r.web);
    }

    res.render('phone-tracker/index', {
      subscriptions,
      summary,
      webs,
      filterWeb: filterWeb || 'all',
      startDate: startDate || '',
      endDate: endDate || '',
      exportQuery,
      error: null,
      success: null,
      role: userRole,
      canEdit: true,
      userWeb
    });
  } catch (err) {
    console.error(err);
    res.render('phone-tracker/index', { subscriptions: [], summary: {}, webs: [], error: 'Failed to load data', success: null });
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
  if (!trimmedLine) continue;

  // ===== 1. Find the date anywhere in the line =====
  let expired = null;
  let dateMatch = null;

  const isoDateMatch = trimmedLine.match(/(\d{4}-\d{2}-\d{2})/);
  if (isoDateMatch) {
    expired = isoDateMatch[1];
    dateMatch = isoDateMatch;
  } else {
    const indoDateMatch = trimmedLine.match(/(\d{1,2})[-\s\/]+([A-Za-z]{3,})[-\s\/]+(\d{4})/i);
    if (indoDateMatch) {
      const parsed = parseIndonesianDate(indoDateMatch[0]);
      if (parsed) {
        expired = parsed;
        dateMatch = indoDateMatch;
      }
    }
  }

  if (!expired) {
    errors.push(`No valid date found in: ${trimmedLine.substring(0, 60)}...`);
    continue;
  }

  // ===== 2. Split line by the date =====
  const leftPart = trimmedLine.substring(0, dateMatch.index).trim();
  const rightPart = trimmedLine.substring(dateMatch.index + dateMatch[0].length).trim();

  // ===== 3. Parse left part: Name, Bank, Code, Phone =====
  // Use multiple spaces or tabs
  let leftFields;
  if (leftPart.includes('\t')) {
    leftFields = leftPart.split('\t').filter(p => p.trim() !== '');
  } else {
    leftFields = leftPart.split(/\s{2,}/).filter(p => p.trim() !== '');
    if (leftFields.length < 4) {
      // Try single space split
      leftFields = leftPart.split(/\s+/).filter(p => p.trim() !== '');
    }
  }

  // Remove optional leading number (display_order)
  if (leftFields.length > 0 && /^\d+$/.test(leftFields[0]) && leftFields.length > 4) {
    leftFields.shift(); // drop the manual number
  }

  // Fill missing fields with empty strings
  while (leftFields.length < 4) leftFields.push('');

  const name = leftFields[0] || '';
  const bank = leftFields[1] || '';
  const code = leftFields[2] || '';
  const phone = leftFields[3] || '';   // ← guaranteed to be the field just before the date

  // ===== 4. Parse right part: Notes, Web, Credit =====
  let notes = '';
  let web = '';
  let credit = '';

  const rightFields = rightPart.split(/\s+/).filter(p => p.trim() !== '');
  // Extract credit (last numeric)
  if (rightFields.length > 0 && /^[\d.,]+$/.test(rightFields[rightFields.length - 1])) {
    credit = rightFields.pop();
  }

  if (userWeb) {
    web = userWeb;
    notes = rightFields.join(' ');
  } else {
    // Last remaining word is web (if any)
    if (rightFields.length > 0) {
      web = rightFields.pop();
    }
    notes = rightFields.join(' ');
  }

  // ===== 5. Validation =====
  if (!name || !phone) {
    errors.push(`Missing name or phone in: ${trimmedLine.substring(0, 60)}...`);
    continue;
  }

  // ===== 6. Duplicate check & insert =====
  try {
    const existing = await db.query('SELECT id FROM phone_subscriptions WHERE phone = $1', [phone]);
    if (existing.rows.length > 0) {
      errors.push(`Skipped duplicate phone: ${phone} (${name})`);
      continue;
    }
  } catch (err) {
    errors.push(`DB error checking duplicate: ${err.message}`);
    continue;
  }

  try {
    await db.query(
      `INSERT INTO phone_subscriptions (name, bank, code, phone, expired, notes, web, credit, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [name, bank, code, phone, expired, notes, web, credit, userId]
    );
    success.push(`Added: ${name}`);
  } catch (err) {
    errors.push(`DB insert error: ${err.message}`);
  }
}

  // ✅ Re‑number all rows (per web) after import
  const userRole = (await db.query('SELECT role FROM users WHERE id = $1', [userId])).rows[0].role;
  await renumberDisplayOrders(userWeb, userRole);   // userWeb may be null for admin
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
    const userRole = (await db.query('SELECT role FROM users WHERE id = $1', [userId])).rows[0].role;
    await renumberDisplayOrders(userWeb, userRole);
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
  const { phone, expired, notes, credit, web } = req.body;
  const userWeb = req.userWebAccess;
  const userRole = req.userRole;

  // Determine final web value
  let finalWeb;
  if (userRole === 'admin' || userRole === 'boss') {
    finalWeb = web || '';  // admin/boss can change web
  } else {
    finalWeb = userWeb;    // leader/cs/joker forced to their assigned web
  }

  try {
    // Ownership check
    let checkQuery = 'SELECT * FROM phone_subscriptions WHERE id = $1';
    let checkParams = [id];
    if (userRole !== 'admin' && userRole !== 'boss') {
      checkQuery += ' AND web = $2';
      checkParams.push(userWeb);
    }
    const check = await db.query(checkQuery, checkParams);
    if (check.rows.length === 0) return res.status(403).send('Access denied');

    await db.query(
      `UPDATE phone_subscriptions 
       SET phone = $1, expired = $2, notes = $3, credit = $4, web = $5, updated_at = NOW()
       WHERE id = $6`,
      [phone, expired, notes, credit, finalWeb, id]
    );

    // ✅ Auto‑renumber after edit
    await renumberDisplayOrders(finalWeb, userRole);

    res.redirect('/phone-tracker?success=Entry updated');
  } catch (err) {
    console.error(err);
    const sub = (await db.query('SELECT * FROM phone_subscriptions WHERE id = $1', [id])).rows[0];
    res.render('phone-tracker/edit', { sub, error: 'Update failed', role: userRole, userWeb });
  }
});

app.get('/phone-tracker/export', requireLogin, requirePhoneAccess, async (req, res) => {
  function formatDateCSV(dateStr) {
  const months = ['Jan','Feb','Mar','Apr','Mei','Jun','Jul','Agt','Sep','Okt','Nov','Des'];
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return dateStr;
  return String(d.getDate()).padStart(2,'0') + '-' + months[d.getMonth()] + '-' + d.getFullYear();
}
  try {
    const userWeb = req.userWebAccess;
    const userRole = req.userRole;
    const { web: filterWeb, startDate, endDate } = req.query;

    let query = 'SELECT * FROM phone_subscriptions';
    let params = [];
    let conditions = [];

    if (userWeb) {
      conditions.push('web = $' + (params.length + 1));
      params.push(userWeb);
    }

    if ((userRole === 'admin' || userRole === 'boss') && filterWeb && filterWeb !== 'all') {
      conditions.push('web = $' + (params.length + 1));
      params.push(filterWeb);
    }

    if (startDate && endDate) {
      conditions.push(`expired BETWEEN $${params.length+1} AND $${params.length+2}`);
      params.push(startDate, endDate);
    }

    if (conditions.length) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    query += ' ORDER BY code, id';

    const result = await db.query(query, params);
    const rows = result.rows;

    // Build CSV
    const headers = ['No', 'Name', 'Bank', 'Code', 'Phone', 'Expired', 'Notes', 'Web', 'Credit'];
    let csv = headers.join(',') + '\n';

    rows.forEach((row, index) => {
      csv += [
        index + 1,
        `"${(row.name || '').replace(/"/g, '""')}"`,
        `"${(row.bank || '').replace(/"/g, '""')}"`,
        `"${(row.code || '').replace(/"/g, '""')}"`,
        `"${(row.phone || '').replace(/"/g, '""')}"`,
        row.expired ? formatDateCSV(row.expired) : '',
        `"${(row.notes || '').replace(/"/g, '""')}"`,
        `"${(row.web || '').replace(/"/g, '""')}"`,
        `"${(row.credit || '').replace(/"/g, '""')}"`
      ].join(',') + '\n';
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=phone-tracker.csv');
    res.send(csv);
  } catch (err) {
    console.error(err);
    res.status(500).send('Export failed');
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

// View whitelist for a specific user (admin selects user)
app.get('/admin/users/:id/whitelist', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const userResult = await db.query('SELECT email FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) return res.redirect('/admin/users');
    
    const { getUserWhitelist } = require('./ipWhitelist');
    const whitelist = await getUserWhitelist(userId);
    
    res.render('admin/user-whitelist', {
      user: userResult.rows[0],
      userId,
      whitelist,
      error: null,
      success: null,
      role: 'admin' // or pass actual role
    });
  } catch (err) {
    res.redirect('/admin/users?error=Failed to load whitelist');
  }
});

// Add entry to user's whitelist
app.post('/admin/users/:id/whitelist/add', requireAdmin, async (req, res) => {
  const userId = req.params.id;
  const { ip_range, label } = req.body;
  try {
    const { addUserWhitelist } = require('./ipWhitelist');
    await addUserWhitelist(userId, ip_range, label);
    res.redirect(`/admin/users/${userId}/whitelist?success=Entry added`);
  } catch (err) {
    res.redirect(`/admin/users/${userId}/whitelist?error=Failed to add`);
  }
});

// Remove entry
app.post('/admin/users/:id/whitelist/remove', requireAdmin, async (req, res) => {
  const userId = req.params.id;
  const { entryId } = req.body;
  try {
    const { removeUserWhitelist } = require('./ipWhitelist');
    await removeUserWhitelist(entryId);
    res.redirect(`/admin/users/${userId}/whitelist?success=Entry removed`);
  } catch (err) {
    res.redirect(`/admin/users/${userId}/whitelist?error=Failed to remove`);
  }
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
  // ... [your existing code to delete] ...
  await renumberDisplayOrders(userWeb, userRole);
  res.redirect('/phone-tracker?success=Selected entries deleted');

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

app.post('/hr/employees/create', requireLogin, requireHRAccess, upload.single('photo'), async (req, res) => {
  const userRole = req.userRole;
  if (!['admin', 'boss', 'leader'].includes(userRole)) {
    return res.status(403).send('Access denied');
  }
  const { employee_code, full_name, email, phone, department, position, join_date, status, user_id, web } = req.body;
  const assignedWeb = (userRole === 'leader') ? req.userWeb : web;
  
  let photoUrl = null;
  try {
    if (req.file) {
      photoUrl = await uploadPhotoToSupabase(req.file.buffer, req.file.originalname);
    }
    
    await db.query(
      `INSERT INTO employees (employee_code, full_name, email, phone, department, position, join_date, status, user_id, web, photo)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [employee_code, full_name, email, phone, department, position, join_date, status || 'active', user_id || null, assignedWeb || null, photoUrl]
    );
    res.redirect('/hr/employees?success=Employee added');
  } catch (err) {
    // If upload succeeded but DB failed, attempt to delete the uploaded photo
    if (photoUrl) await deletePhotoFromSupabase(photoUrl);
    
    let users = [];
    if (userRole === 'admin' || userRole === 'boss') {
      users = (await db.query('SELECT id, email FROM users ORDER BY email')).rows;
    }
    res.render('hr/create-employee', { error: err.message, role: userRole, users, userWeb: req.userWeb });
  }
});

// Edit form (admin, boss, leader only)
app.post('/hr/employees/:id/edit', requireLogin, requireHRAccess, upload.single('photo'), async (req, res) => {
  const userRole = req.userRole;
  if (!['admin', 'boss', 'leader'].includes(userRole)) {
    return res.status(403).send('Access denied');
  }
  const id = req.params.id;
  const { employee_code, full_name, email, phone, department, position, join_date, status, user_id, web, existing_photo } = req.body;
  const assignedWeb = (userRole === 'leader') ? req.userWeb : web;
  
  let photoUrl = existing_photo || null;
  try {
    if (req.file) {
      // Upload new photo
      photoUrl = await uploadPhotoToSupabase(req.file.buffer, req.file.originalname);
      // Delete old photo if exists
      if (existing_photo) await deletePhotoFromSupabase(existing_photo);
    }
    
    await db.query(
      `UPDATE employees SET employee_code=$1, full_name=$2, email=$3, phone=$4, department=$5, position=$6, join_date=$7, status=$8, user_id=$9, web=$10, photo=$11, updated_at=NOW()
       WHERE id=$12`,
      [employee_code, full_name, email, phone, department, position, join_date, status, user_id || null, assignedWeb || null, photoUrl, id]
    );
    res.redirect('/hr/employees?success=Employee updated');
  } catch (err) {
    if (req.file && photoUrl) await deletePhotoFromSupabase(photoUrl);
    
    const employee = (await db.query('SELECT * FROM employees WHERE id=$1', [id])).rows[0];
    let users = [];
    if (userRole === 'admin' || userRole === 'boss') {
      users = (await db.query('SELECT id, email FROM users ORDER BY email')).rows;
    }
    res.render('hr/edit-employee', { employee, error: err.message, role: userRole, users, userWeb: req.userWeb });
  }
});

// Delete (admin, boss only)
app.post('/hr/employees/:id/delete', requireLogin, requireHRAccess, async (req, res) => {
  const userRole = req.userRole;
  if (!['admin', 'boss'].includes(userRole)) {
    return res.status(403).send('Access denied');
  }
  const id = req.params.id;
  try {
    // Get photo URL before deletion
    const emp = await db.query('SELECT photo FROM employees WHERE id=$1', [id]);
    if (emp.rows[0]?.photo) {
      await deletePhotoFromSupabase(emp.rows[0].photo);
    }
    await db.query('DELETE FROM employees WHERE id=$1', [id]);
    res.redirect('/hr/employees?success=Employee deleted');
  } catch (err) {
    res.redirect('/hr/employees?error=Delete failed');
  }
});

app.listen(PORT, () => {
  console.log(`AI Apps running on http://localhost:${PORT}`);
});