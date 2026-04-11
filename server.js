require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const pgSession = require('connect-pg-simple')(session);
const db = require('./database'); // PostgreSQL pool

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

// Helper: require admin
async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  try {
    const result = await db.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
    if (result.rows.length === 0 || result.rows[0].role !== 'admin') {
      return res.status(403).send('Access denied');
    }
    next();
  } catch (err) {
    return res.status(500).send('Server error');
  }
}

// Helper: generate captcha
function generateCaptcha() {
  const num1 = Math.floor(Math.random() * 10) + 1;
  const num2 = Math.floor(Math.random() * 10) + 1;
  return { question: `${num1} + ${num2} = ?`, answer: num1 + num2 };
}

// ---------- Public Routes ----------
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
  const captcha = generateCaptcha();
  req.session.captchaAnswer = captcha.answer;
  res.render('login', { captchaQuestion: captcha.question, error: null });
});

app.post('/login', async (req, res) => {
  const { email, password, captcha } = req.body;
  const storedAnswer = req.session.captchaAnswer;

  // Validate captcha
  if (!captcha || parseInt(captcha) !== storedAnswer) {
    const newCaptcha = generateCaptcha();
    req.session.captchaAnswer = newCaptcha.answer;
    return res.render('login', { captchaQuestion: newCaptcha.question, error: 'Invalid captcha' });
  }

  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      const newCaptcha = generateCaptcha();
      req.session.captchaAnswer = newCaptcha.answer;
      return res.render('login', { captchaQuestion: newCaptcha.question, error: 'Invalid email or password' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      const newCaptcha = generateCaptcha();
      req.session.captchaAnswer = newCaptcha.answer;
      return res.render('login', { captchaQuestion: newCaptcha.question, error: 'Invalid email or password' });
    }

    // Check if 2FA is enabled
    if (user.twofa_enabled) {
      // Store user ID temporarily for 2FA verification
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
    const newCaptcha = generateCaptcha();
    req.session.captchaAnswer = newCaptcha.answer;
    res.render('login', { captchaQuestion: newCaptcha.question, error: 'Server error' });
  }
});

// GET: Show 2FA verification page
app.get('/verify-2fa', (req, res) => {
  if (!req.session.tempUserId) {
    return res.redirect('/login');
  }
  res.render('verify-2fa', { error: null });
});

// POST: Verify 2FA token
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
      // Clear temp session and set real session
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

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
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

// ---------- Start Server ----------
app.listen(PORT, () => {
  console.log(`AI Apps running on http://localhost:${PORT}`);
});