// server.js (with advanced logging)
require('dotenv').config();

// Import the new logger and its utility functions
const { log, attachRequestLogger, expressErrorHandler, installProcessHandlers } = require('./logger');

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const pool = require('./db'); // export pool.promise() from db.js
const { authRequired, requireAdmin } = require('./authMiddleware');
const axios = require('axios');
const webpush = require('web-push');
const path = require('path');
const fs = require('fs');
const multer = require('multer'); // Import multer

// --- Setup ---

// Optional mapping of template variable names via env
const VAR_TO      = process.env.EMAILJS_VAR_TO      || 'to_email';
const VAR_NAME    = process.env.EMAILJS_VAR_NAME    || 'to_name';
const VAR_APP     = process.env.EMAILJS_VAR_APP     || 'app_name';
const VAR_LINK    = process.env.EMAILJS_VAR_LINK    || 'reset_link';
const VAR_EXPIRES = process.env.EMAILJS_VAR_EXPIRES || 'expires_minutes';

// Install global handlers to catch crashes and unhandled promise rejections
installProcessHandlers();
log.start('API booting…');

// Load keys from .env
const vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
const vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;


const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.set('trust proxy', true);

// Create a multer instance that stores files in memory as buffers
const storage = multer.memoryStorage();
const memoryUpload = multer({ storage: storage });

// Add the request logger middleware. It will log every incoming request and its response.
// Place it right after express.json() to ensure it can log request bodies.
app.use(attachRequestLogger());

if (vapidPublicKey && vapidPrivateKey) {
  webpush.setVapidDetails(
    'mailto:your-email@example.com', // Your contact email
    vapidPublicKey,
    vapidPrivateKey
  );
  log.start('Web-push configured');
} else {
  log.warn('VAPID keys not set. Push notifications will be disabled.');
}



// Human-friendly masking
const maskEmail = (email) => {
  if (!email || typeof email !== 'string') return email;
  const [u, d] = email.trim().toLowerCase().split('@');
  if (!d) return email;
  const maskedUser = u.length <= 2 ? (u[0] || '') + '*' : u[0] + '*'.repeat(u.length - 2) + u.slice(-1);
  return `${maskedUser}@${d}`;
};

// Mask helper for logs
function _maskEmail(email) {
  if (!email || typeof email !== 'string') return email;
  const [u, d] = email.trim().toLowerCase().split('@');
  if (!d) return email;
  const maskedUser = u.length <= 2 ? (u[0] || '') + '*' : u[0] + '*'.repeat(u.length - 2) + u.slice(-1);
  return `${maskedUser}@${d}`;
}

// Respect EmailJS rate limit: 1 request / second
let __lastSendAt = 0;
async function _respectEmailJsRateLimit() {
  const now = Date.now();
  const delta = now - __lastSendAt;
  if (delta < 1000) {
    await new Promise(r => setTimeout(r, 1000 - delta));
  }
  __lastSendAt = Date.now();
}


/* -------------------- Settings Helpers -------------------- */
// server.js

// We'll create the table once on first use
let settingsTableCreated = false;
async function _ensureSettingsTable() {
  if (settingsTableCreated) return;
  try {
    // This query creates the key-value table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_settings (
        setting_key VARCHAR(100) PRIMARY KEY NOT NULL,
        setting_value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB
    `);
    settingsTableCreated = true;
    log.ok('Settings table (app_settings) verified/created.');
  } catch (e) {
    log.err('Failed to create app_settings table', { message: e.message });
  }
}

/**
 * Get a value from the app_settings table
 * @param {string} key - The setting_key
 * @param {any} [defaultValue=null] - Value to return if key not found
 */
async function getSetting(key, defaultValue = null) {
  await _ensureSettingsTable(); // Ensure table exists
  try {
    const [[row]] = await pool.query(
      'SELECT setting_value FROM app_settings WHERE setting_key = ?',
      [key]
    );
    // Return the value if found, otherwise the default
    return row ? row.setting_value : defaultValue;
  } catch (e) {
    log.err('getSetting failed', { key, message: e.message });
    return defaultValue;
  }
}

/**
 * Set a value in the app_settings table (UPSERT)
 * @param {string} key - The setting_key
 * @param {string|null} value - The value to set
 */
async function setSetting(key, value) {
  await _ensureSettingsTable(); // Ensure table exists
  try {
    // This query inserts a new row or updates the value if the key already exists
    await pool.query(
      `INSERT INTO app_settings (setting_key, setting_value)
       VALUES (?, ?)
       ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)`,
      [key, value]
    );
  } catch (e) {
    log.err('setSetting failed', { key, message: e.message });
    // Re-throw so the route handler can catch it and send a 500
    throw e;
  }
}

// --- PREMONITIONS TABLES (final, safe) ---
let premonitionsTableCreated = false;

async function _ensurePremonitionsTables() {
  if (premonitionsTableCreated) return;
  try {
    // main premonitions
    await pool.query(`
      CREATE TABLE IF NOT EXISTS premonitions (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        sender_id INT NOT NULL,
        content_type ENUM('text','image','video') NOT NULL,
        content_text TEXT,
        content_url VARCHAR(2048),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY sender_id_idx (sender_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // who received what
    await pool.query(`
      CREATE TABLE IF NOT EXISTS premonition_recipients (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        premonition_id INT UNSIGNED NOT NULL,
        user_id INT NOT NULL,
        viewed_at TIMESTAMP NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_premonition_user (premonition_id, user_id),
        CONSTRAINT fk_premonition_id
          FOREIGN KEY (premonition_id)
          REFERENCES premonitions(id)
          ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    premonitionsTableCreated = true;
    log.ok('Premonition tables ready');
  } catch (e) {
    log.err('Failed to create premonition tables', { message: e.message });
  }
}


let premonitionMediaTableCreated = false;
async function _ensurePremonitionsMediaTables() {
  if (premonitionMediaTableCreated) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS premonition_media (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        filename VARCHAR(255),
        mime VARCHAR(100) NOT NULL,
        size INT UNSIGNED NOT NULL,
        data MEDIUMBLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB;
    `);
    premonitionMediaTableCreated = true;
    log.ok('Premonition media table (premonition_media) verified/created.');
  } catch (e) {
    log.err('Failed to create premonition_media table', { message: e.message });
  }
}

// run once on boot
_ensurePremonitionsTables().catch(err =>
  log.err('premonitions init failed', { message: err.message })
);
_ensurePremonitionsMediaTables().catch(err =>
  log.err('premonition media init failed', { message: err.message })
);


/* ------------------ Start server Mail ------------------ */

async function sendResetEmailWithEmailJS({
  to,                // recipient email (string)
  name,              // display name (string)
  link,              // absolute reset URL
  appName = process.env.APP_NAME || 'Erebus Portal',
  expiresMinutes = 30
}) {
  // Build exactly what EmailJS expects
  const payload = {
    service_id:  process.env.EMAILJS_SERVICE_ID,
    template_id: process.env.EMAILJS_TEMPLATE_ID,
    user_id:     process.env.EMAILJS_PUBLIC_KEY,     // "user_id" = PUBLIC key
    accessToken: process.env.EMAILJS_PRIVATE_KEY || undefined, // optional
    template_params: {
      [VAR_TO]: to,
      [VAR_NAME]: name || 'there',
      [VAR_APP]: appName,
      [VAR_LINK]: link,
      [VAR_EXPIRES]: expiresMinutes,
    },
  };

  // Pre-flight log (no secrets)
  log.mail('EmailJS → sending reset', {
    to: _maskEmail(to),
    service_id: process.env.EMAILJS_SERVICE_ID ? 'set' : 'MISSING',
    template_id: process.env.EMAILJS_TEMPLATE_ID ? 'set' : 'MISSING',
    user_id: process.env.EMAILJS_PUBLIC_KEY ? 'set' : 'MISSING',
    // show the exact param keys we send so you can align the template
    vars: Object.keys(payload.template_params)
  });

  // Hard sanity checks (fail fast with meaningful error in logs)
  if (!payload.service_id || !payload.template_id || !payload.user_id) {
    const err = 'EmailJS env vars missing (need EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, EMAILJS_PUBLIC_KEY).';
    log.err('EmailJS config error', { err });
    throw new Error(err);
  }
  if (!payload.template_params[VAR_TO]) {
    const err = `Missing recipient email for template var ${VAR_TO}. Check your route inputs.`;
    log.err('EmailJS param error', { err });
    throw new Error(err);
  }

  // Respect 1 rps
  await _respectEmailJsRateLimit();

  // Send (per docs)
  const res = await axios.post(
    'https://api.emailjs.com/api/v1.0/email/send',
    payload,
    {
      timeout: 20000,
      headers: { 'Content-Type': 'application/json' },
      validateStatus: () => true, // log non-2xx too
    }
  );

  const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
  if (res.status >= 200 && res.status < 300) {
    // EmailJS success format: 200 "OK"
    log.ok('EmailJS ← OK', { status: res.status, body });
  } else {
    // Typical failure: 400 "The parameters are invalid..."
    log.err('EmailJS ← NON-2XX', {
      status: res.status,
      statusText: res.statusText,
      body
    });
    throw new Error(`EmailJS responded ${res.status} ${res.statusText}: ${body}`);
  }
}

module.exports = { sendResetEmailWithEmailJS };




/* -------------------- Helpers -------------------- */
// *** NEW MIDDLEWARE ***
const requireCourt = (req, res, next) => {
  if (req.user && (req.user.role === 'admin' || req.user.role === 'courtuser')) {
    return next();
  }
  log.warn('Court access denied', { user_id: req.user?.id, role: req.user?.role });
  return res.status(403).json({ error: 'Forbidden: Court access required' });
};

const issueToken = (user) =>
  jwt.sign(
    { id: user.id, email: user.email, role: user.role, display_name: user.display_name },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

function startOfMonth(d = new Date()) { return new Date(d.getFullYear(), d.getMonth(), 1); }
function endOfMonth(d = new Date()) { return new Date(d.getFullYear(), d.getMonth() + 1, 1); }
function feedingFromPredator(pred) {
  const map = { Alleycat: 'Violent Hunt', Sandman: 'Sleeping Prey', Siren: 'Seduction', Osiris: 'Cult Feeding', Farmer: 'Animal/Bagged', Bagger: 'Bagged Blood', 'Scene Queen': 'Scene Influence', Consensualist: 'Consent Feeding', Extortionist: 'Blackmail Feeding', 'Blood Leech': 'Vitae Theft' };
  return map[pred] || 'Standard Feeding';
}
function xpCost({ type, newLevel, ritualLevel, formulaLevel, dots = 1, disciplineKind }) {
  if (type === 'attribute') return Number(newLevel) * 5;
  if (type === 'skill') return Number(newLevel) * 3;
  if (type === 'specialty') return 3;
  if (type === 'discipline') {
    if (disciplineKind === 'clan') return Number(newLevel) * 5;
    if (disciplineKind === 'caitiff') return Number(newLevel) * 6;
    return Number(newLevel) * 7;
  }
  if (type === 'ritual' || type === 'ceremony') {
    const lvl = Number(ritualLevel ?? newLevel ?? 1);
    return lvl * 3;
  }
  if (type === 'thin_blood_formula') {
    const lvl = Number(formulaLevel ?? newLevel ?? 1);
    return lvl * 3;
  }
  if (type === 'advantage') return 3 * Number(dots || 1);
  if (type === 'blood_potency') return Number(newLevel) * 10;
  throw new Error('Unknown XP type');
}
// --- Simple status/health ---

// Optional: capture server start time
const startedAt = new Date();

// JSON health probe (good for uptime checks / Kubernetes / monitors)
app.get('/api/health', async (req, res) => {
  try {
    // Quick DB ping (remove if you don't want DB coupled to health)
    const [rows] = await pool.query('SELECT 1 AS ok');
    const dbOk = rows?.[0]?.ok === 1;

    res.set('Cache-Control', 'no-store');
    return res.json({
      ok: true,
      db: dbOk,
      env: process.env.NODE_ENV || 'stable',
      uptime_sec: Math.floor(process.uptime()),
      started_at: startedAt.toISOString(),
      now: new Date().toISOString(),
    });
  } catch (e) {
    return res.status(500).json({
      ok: false,
      db: false,
      error: e.message,
      now: new Date().toISOString(),
    });
  }
});

// Friendly HTML at "/" (quick glance in the browser)
app.get('/', async (req, res) => {
  // Optionally also check DB here; keep it light
  let dbStatus = 'unknown';
  try {
    const [rows] = await pool.query('SELECT 1 AS ok');
    dbStatus = rows?.[0]?.ok === 1 ? 'OK' : 'DOWN';
  } catch {
    dbStatus = 'DOWN';
  }

  res.set('Cache-Control', 'no-store').type('html').send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>API Status</title>
<style>
  :root { --bg:#0b0b0c; --card:#141418; --fg:#e8e8ea; --muted:#a3a3ad; --ok:#3ecf8e; --bad:#ff6b6b; --dim:#1f1f24; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,Ubuntu,Helvetica,Arial,sans-serif; background:var(--bg); color:var(--fg); display:grid; place-items:center; min-height:100vh; }
  .card { background:var(--card); border:1px solid var(--dim); border-radius:14px; padding:20px 22px; width:min(680px,92vw); box-shadow:0 10px 30px rgba(0,0,0,.35); }
  h1 { margin:0 0 6px; font-size:22px; letter-spacing:.25px; }
  .muted { color:var(--muted); font-size:13px; }
  .grid { display:grid; grid-template-columns: 160px 1fr; row-gap:8px; column-gap:12px; margin-top:14px; }
  .k { color:var(--muted); }
  .v { font-weight:600; }
  .ok { color:var(--ok); }
  .bad { color:var(--bad); }
  code { background:var(--dim); padding:2px 6px; border-radius:6px; font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; }
  a { color:#8ab4f8; text-decoration:none; }
  a:hover { text-decoration:underline; }
</style>
</head>
<body>
  <main class="card" role="status" aria-live="polite">
    <h1>Erebus🦇 API Status: <span class="${dbStatus === 'OK' ? 'ok' : 'bad'}">${dbStatus === 'OK' ? 'OK' : 'DEGRADED'}</span></h1>
    <div class="muted">This page is served by the API process.</div>
    <div class="grid">
      <div class="k">Environment</div><div class="v"><code>${process.env.NODE_ENV || 'stable'}</code></div>
      <div class="k">Node.js</div><div class="v"><code>${process.version}</code></div>
      <div class="k">Uptime</div><div class="v">${Math.floor(process.uptime())}s</div>
      <div class="k">Started</div><div class="v">${startedAt.toISOString()}</div>
      <div class="k">Now</div><div class="v">${new Date().toISOString()}</div>
      <div class="k">DB</div><div class="v ${dbStatus === 'OK' ? 'ok' : 'bad'}">${dbStatus}</div>
      <div class="k">Health JSON</div><div class="v"><a href="/api/health">/api/health</a></div>
    </div>
  </main>
</body>
</html>`);
});


/* -------------------- Auth Routes -------------------- */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, display_name, password } = req.body;
    if (!email || !display_name || !password) {
      log.warn('Register missing fields', { email, display_name });
      return res.status(400).json({ error: 'Missing fields' });
    }
    const [exists] = await pool.query('SELECT id FROM users WHERE email=?', [email]);
    if (exists.length) {
      log.warn('Register email in use', { email });
      return res.status(409).json({ error: 'Email already in use' });
    }
    const hash = await bcrypt.hash(password, 12);
    const [r] = await pool.query('INSERT INTO users (email, display_name, password_hash) VALUES (?,?,?)', [email, display_name, hash]);
    log.auth('User registered', { id: r.insertId, email });
    const [rows] = await pool.query('SELECT id, email, display_name, role FROM users WHERE id=?', [r.insertId]);
    res.json({ token: issueToken(rows[0]) });
  } catch (e) {
    log.err('Register failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Register failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  // best-effort client IP (works with proxies/CDNs)
  const ip =
    req.headers['cf-connecting-ip'] ||
    req.headers['x-real-ip'] ||
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.ip ||
    req.socket?.remoteAddress ||
    'unknown';
  const ua = req.get('user-agent');

  try {
    const { email, password } = req.body || {};
    const [rows] = await pool.query('SELECT * FROM users WHERE email=?', [email]);
    const user = rows[0];

    if (!user) {
      log.warn('Login invalid email', { email, ip, ua, req_id: req.id });
      return res.status(401).json({ error: 'Invalid credentials', req_id: req.id });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      log.warn('Login wrong password', { email, ip, ua, req_id: req.id });
      return res.status(401).json({ error: 'Invalid credentials', req_id: req.id });
    }

    log.auth('User logged in', { user_id: user.id, email, ip, ua, req_id: req.id });
    res.json({ token: issueToken(user) });
  } catch (e) {
    log.err('Login failed', { message: e.message, stack: e.stack, ip, ua, req_id: req.id });
    res.status(500).json({ error: 'Login failed', req_id: req.id });
  }
});


app.get('/api/auth/me', authRequired, async (req, res) => {
  log.auth('Auth me', { id: req.user.id, email: req.user.email, role: req.user.role });
  res.json({ user: req.user });
});

// --- COMPLETE /api/auth/forgot ---
app.post('/api/auth/forgot', async (req, res) => {
  const { email } = req.body || {};
  const norm = (email || '').trim().toLowerCase();
  const okResponse = () => res.json({ ok: true, message: 'If the email exists, a reset link has been sent.' });

  // Configurable cooldown (minutes). In dev set RESET_COOLDOWN_MIN=0 to disable.
  const COOLDOWN_MIN = Number(process.env.RESET_COOLDOWN_MIN ?? 10);
  const IS_PROD = (process.env.NODE_ENV || '').toLowerCase() === 'production';

  // Force resend in dev only: ?resend=1 or header x-reset-resend: 1
  const wantResend = (req.query?.resend === '1') || (req.get('x-reset-resend') === '1');
  const forceResend = wantResend && !IS_PROD;

  try {
    if (!norm) {
      log.warn('Forgot: missing email');
      return okResponse();
    }

    // Only select columns that exist in your schema
    const [rows] = await pool.query(
      'SELECT id, display_name FROM users WHERE email = ? LIMIT 1',
      [norm]
    );
    const user = rows[0];
    if (!user) {
      log.mail('Forgot: email not found (OK sent)', { email: maskEmail(norm) });
      return okResponse();
    }

    // Get the latest non-used reset (if any)
    const [recentRows] = await pool.query(
      'SELECT id, created_at FROM password_resets WHERE user_id=? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1',
      [user.id]
    );
    if (recentRows.length) {
      const last = recentRows[0];
      const lastTs = new Date(last.created_at).getTime();
      const sinceMs = Date.now() - lastTs;
      const sinceMin = Math.floor(sinceMs / 60000);
      const remain = Math.max(0, COOLDOWN_MIN - sinceMin);

      if (remain > 0 && !forceResend) {
        log.mail('Forgot: recent reset exists (cooldown active, OK sent)', {
          email: maskEmail(norm),
          cooldown_min: COOLDOWN_MIN,
          since_min: sinceMin,
          remaining_min: remain,
          note: 'use ?resend=1 in DEV to bypass',
        });
        return okResponse();
      }

      if (forceResend) {
        log.mail('Forgot: cooldown bypass via resend (DEV)', {
          email: maskEmail(norm),
          since_min: sinceMin,
        });
      }
    }

    // Create fresh token (invalidate nothing explicitly; old unused tokens remain but still expire)
    const tokenId    = crypto.randomUUID();
    const secret     = crypto.randomBytes(32).toString('hex');
    const combined   = `${tokenId}.${secret}`;
    const secretHash = await bcrypt.hash(secret, 12);
    const expiresAt  = new Date(Date.now() + 30 * 60 * 1000); // 30 min

    await pool.query(
      'INSERT INTO password_resets (user_id, token_id, secret_hash, expires_at) VALUES (?,?,?,?)',
      [user.id, tokenId, secretHash, expiresAt]
    );

    const appBase = (process.env.APP_BASE_URL || req.headers.origin || '').replace(/\/$/, '') || 'http://localhost:3000';
    const link = `${appBase}/reset?token=${encodeURIComponent(combined)}`;

    log.mail('Reset token created', {
      email: maskEmail(norm),
      link_path: new URL(link).pathname,
      expires_min: 30,
      cooldown_min: COOLDOWN_MIN,
    });

    try {
      await sendResetEmailWithEmailJS({
        to: norm,
        name: user.display_name || 'there',
        link,
        appName: process.env.APP_NAME || 'Erebus Portal',
      });
    } catch (e) {
      log.err('EmailJS send failed', { error: e?.message || String(e) });
    }

    return okResponse();
  } catch (e) {
    log.err('Forgot password error', { message: e.message, stack: e.stack });
    return okResponse();
  }
});



app.post('/api/auth/reset', async (req, res) => {
    // (Your existing route)
    const { token, password } = req.body || {};
    if (typeof token !== 'string' || typeof password !== 'string' || password.length < 8) {
        return res.status(400).json({ error: 'Bad request (password must be at least 8 chars).' });
    }
    const parts = token.split('.');
    if (parts.length !== 2) return res.status(400).json({ error: 'Invalid token' });
    const [tokenId, secret] = parts;
    try {
        const [rows] = await pool.query('SELECT * FROM password_resets WHERE token_id=? AND used_at IS NULL AND expires_at > NOW()', [tokenId]);
        const row = rows[0];
        if (!row) return res.status(400).json({ error: 'Invalid or expired token' });
        const ok = await bcrypt.compare(secret, row.secret_hash);
        if (!ok) return res.status(400).json({ error: 'Invalid or expired token' });
        const hash = await bcrypt.hash(password, 12);
        await pool.query('UPDATE users SET password_hash=? WHERE id=?', [hash, row.user_id]);
        await pool.query('UPDATE password_resets SET used_at=NOW() WHERE id=?', [row.id]);
        await pool.query('UPDATE password_resets SET used_at=NOW() WHERE user_id=? AND used_at IS NULL', [row.user_id]);
        log.auth('Password reset complete', { user_id: row.user_id });
        return res.json({ ok: true });
    } catch (e) {
        log.err('Reset password error', { message: e.message, stack: e.stack });
        return res.status(500).json({ error: 'Reset failed' });
    }
});


/* -------------------- Characters -------------------- */
// Get my character (parse sheet if string)
app.get('/api/characters/me', authRequired, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
  const ch = rows[0] || null;
  if (ch && ch.sheet && typeof ch.sheet === 'string') {
    try { ch.sheet = JSON.parse(ch.sheet); } catch {}
  }
  log.char('Fetch my character', { user_id: req.user.id, hasCharacter: !!ch });
  res.json({ character: ch });
});

// Create character (stores sheet JSON and xp=50)
app.post('/api/characters', authRequired, async (req, res) => {
  const { name, clan, sheet } = req.body;
  if (!name || !clan) {
    log.warn('Create character missing fields', { user_id: req.user.id });
    return res.status(400).json({ error: 'Name and clan are required' });
  }

  try {
    const [exists] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
    if (exists.length) {
      log.warn('Create character already exists', { user_id: req.user.id });
      return res.status(409).json({ error: 'Character already exists' });
    }

    const [r] = await pool.query(
      'INSERT INTO characters (user_id, name, clan, sheet, xp) VALUES (?,?,?,?,?)',
      [req.user.id, name, clan, sheet ? JSON.stringify(sheet) : null, 50]
    );

    const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [r.insertId]);
    const ch = rows[0];
    if (ch && ch.sheet && typeof ch.sheet === 'string') { try { ch.sheet = JSON.parse(ch.sheet); } catch {} }
    log.char('Character created', { id: r.insertId, user_id: req.user.id, name, clan, xp: ch?.xp });
    res.json({ character: ch });
  } catch (e) {
    log.err('Failed to create character', e);
    res.status(500).json({ error: 'Failed to create character' });
  }
});

// Update my character (optional)
app.put('/api/characters', authRequired, async (req, res) => {
  const { name, clan, sheet } = req.body;
  const [rows] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
  if (!rows.length) {
    log.warn('Update character not found', { user_id: req.user.id });
    return res.status(404).json({ error: 'No character' });
  }

  const fields = [], vals = [];
  if (name) { fields.push('name=?'); vals.push(name); }
  if (clan) { fields.push('clan=?'); vals.push(clan); }
  if (sheet !== undefined) { fields.push('sheet=?'); vals.push(sheet ? JSON.stringify(sheet) : null); }
  if (!fields.length) {
    log.warn('Update character no fields', { user_id: req.user.id });
    return res.status(400).json({ error: 'Nothing to update' });
  }

  vals.push(rows[0].id);
  await pool.query(`UPDATE characters SET ${fields.join(', ')} WHERE id=?`, vals);

  const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [rows[0].id]);
  const ch = out[0];
  if (ch && ch.sheet && typeof ch.sheet === 'string') { try { ch.sheet = JSON.parse(ch.sheet); } catch {} }
  log.char('Character updated', { id: rows[0].id, user_id: req.user.id, updates: fields });
  res.json({ character: ch });
});

// ================== XP Totals ==================
app.get('/api/characters/xp/total', authRequired, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
    const ch = rows[0];
    if (!ch) return res.status(404).json({ error: 'Character not found' });

    // Remaining XP is in characters.xp
    const remaining = ch.xp || 0;

    // If xp_log table exists, calculate spent total
    let spent = 0;
    try {
      const [logRows] = await pool.query(
        'SELECT SUM(cost) AS total_spent FROM xp_log WHERE character_id=?',
        [ch.id]
      );
      spent = Number(logRows[0]?.total_spent || 0);
    } catch {
      // fallback if xp_log missing
      spent = 0;
    }

    const granted = remaining + spent;

    res.json({ character_id: ch.id, granted, spent, remaining });
  } catch (e) {
    log.err('XP total fetch failed', e);
    res.status(500).json({ error: 'Failed to calculate XP total' });
  }
});


/* -------------------- XP Spend -------------------- */
app.post('/api/characters/xp/spend', authRequired, async (req, res) => {
  const {
    type, target, currentLevel, newLevel,
    ritualLevel, formulaLevel, dots,
    disciplineKind, patchSheet
  } = req.body;

  const [rows] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
  const ch = rows[0];
  if (!ch) {
    log.warn('XP spend without character', { user_id: req.user.id });
    return res.status(400).json({ error: 'Create a character first' });
  }

  // Determine cost (special-case free power assignment)
  let cost = 0;
  try {
    if (
      type === 'discipline' &&
      (
        disciplineKind === 'select' ||                           // explicit "assignment only"
        Number(newLevel) === Number(currentLevel)                // or no level change
      )
    ) {
      cost = 0; // assigning a specific power for an existing dot is free
    } else {
      cost = xpCost({ type, newLevel, ritualLevel, formulaLevel, dots, disciplineKind });
    }
  } catch (e) {
    log.warn('XP spend bad type', { type });
    return res.status(400).json({ error: e.message });
  }

  // If this is a paid action, verify balance and deduct XP
  if (cost > 0) {
    if ((ch.xp || 0) < cost) {
      log.warn('XP spend insufficient', { user_id: req.user.id, have: ch.xp, need: cost });
      return res.status(400).json({ error: `Not enough XP (need ${cost}, have ${ch.xp})` });
    }
    log.xp('XP spend request', { user_id: req.user.id, type, target, currentLevel, newLevel, cost });
    await pool.query('UPDATE characters SET xp = xp - ? WHERE id=?', [cost, ch.id]);
  } else {
    log.xp('Discipline power assignment (free)', { user_id: req.user.id, target, level: newLevel });
  }

  // Apply optional sheet patch for both paid and free actions
  if (patchSheet !== undefined) {
    await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(patchSheet), ch.id]);
    log.xp('Sheet patched after action', { user_id: req.user.id, character_id: ch.id });
  }

  // XP log (store 0-cost entries too)
  try {
    await pool.query(
      'INSERT INTO xp_log (character_id, action, target, from_level, to_level, cost, payload) VALUES (?,?,?,?,?,?,?)',
      [ch.id, type, target || null, currentLevel || null, newLevel || null, cost,
        JSON.stringify({ disciplineKind, ritualLevel, formulaLevel, dots })]
    );
    log.xp('XP logged', { character_id: ch.id, cost });
  } catch (_) { /* ignore if xp_log missing */ }

  const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [ch.id]);
  const outCh = out[0];
  if (outCh && outCh.sheet && typeof outCh.sheet === 'string') { try { outCh.sheet = JSON.parse(outCh.sheet); } catch {} }

  if (cost > 0) {
    log.ok('XP spend complete', { user_id: req.user.id, remaining_xp: outCh?.xp });
  } else {
    log.ok('Power assignment saved (no XP charged)', { user_id: req.user.id });
  }

  res.json({ character: outCh, spent: cost });
});

/* -------------------- Admin add/remove XP -------------------- */
app.patch('/api/admin/characters/:id/xp', authRequired, requireAdmin, async (req, res) => {
  const { delta } = req.body;
  if (typeof delta !== 'number') return res.status(400).json({ error: 'delta must be a number' });

  await pool.query('UPDATE characters SET xp = GREATEST(0, xp + ?) WHERE id=?', [delta, req.params.id]);
  const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [req.params.id]);
  log.adm('Admin XP adjust', { character_id: req.params.id, delta, new_xp: out[0]?.xp });
  res.json({ character: out[0] });
});

// --- Admin: edit character ---
app.patch('/api/admin/characters/:id', authRequired, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const { name, clan, sheet } = req.body;

  const fields = [];
  const vals = [];

  if (typeof name === 'string') { fields.push('name=?'); vals.push(name.trim()); }
  if (typeof clan === 'string') { fields.push('clan=?'); vals.push(clan.trim()); }

  if (sheet !== undefined) {
    let jsonStr = null;
    try {
      const obj = (typeof sheet === 'string') ? JSON.parse(sheet) : sheet;
      jsonStr = JSON.stringify(obj ?? {});
    } catch {
      return res.status(400).json({ error: 'sheet must be valid JSON (object or stringified object)' });
    }
    fields.push('sheet=?'); vals.push(jsonStr);
  }

  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });

  vals.push(id);
  await pool.query(`UPDATE characters SET ${fields.join(', ')} WHERE id=?`, vals);

  const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [id]);
  const ch = rows[0];
  if (ch && ch.sheet && typeof ch.sheet === 'string') { try { ch.sheet = JSON.parse(ch.sheet); } catch {} }
  log.adm('Character updated', { id, fields });
  res.json({ character: ch });
});

// Delete Character (admin)
app.delete('/api/admin/characters/:id', authRequired, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid character id' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Remove/neutralize references to this character
    await conn.query('DELETE FROM domain_members WHERE character_id=?', [id]);
    await conn.query('DELETE FROM downtimes WHERE character_id=?', [id]);
    try { await conn.query('DELETE FROM xp_log WHERE character_id=?', [id]); } catch (_) { /* xp_log may not exist */ }
    await conn.query('UPDATE domain_claims SET owner_character_id=NULL WHERE owner_character_id=?', [id]);

    // Finally delete the character
    const [result] = await conn.query('DELETE FROM characters WHERE id=?', [id]);
    await conn.commit();

    if (result.affectedRows === 0) return res.status(404).json({ error: 'Character not found' });

    log.adm('Character deleted', { id, by_user_id: req.user.id });
    res.json({ ok: true });
  } catch (e) {
    await conn.rollback();
    log.err('Delete character failed', { message: e.message, stack: e.stack, id });
    res.status(500).json({ error: 'Failed to delete character' });
  } finally {
    conn.release();
  }
});


/* -------------------- NPCs (Admin only) -------------------- */


// List NPCs (admin) — single canonical route
app.get('/api/admin/npcs', authRequired, requireAdmin, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM npcs ORDER BY id DESC');

  // Parse JSON sheet if stored as string
  rows.forEach(r => {
    if (r.sheet && typeof r.sheet === 'string') {
      try { r.sheet = JSON.parse(r.sheet); } catch {}
    }
  });

  // DEBUG: confirm DB and count to diagnose “empty” responses
  try {
    const [[db]] = await pool.query('SELECT DATABASE() AS db');
    console.log('🛡️ NPC list', { db: db.db, count: rows.length });
  } catch {}

  res.json({ npcs: rows });
});




/// Create NPC
app.post('/api/admin/npcs', authRequired, requireAdmin, async (req, res) => {
  const { name, clan, sheet } = req.body;
  if (!name || !clan) return res.status(400).json({ error: 'Name and clan are required' });

  const [r] = await pool.query(
    'INSERT INTO npcs (name, clan, sheet, xp) VALUES (?,?,?,?)',
    [name, clan, sheet ? JSON.stringify(sheet) : null, 10000]
  );

  const [rows] = await pool.query('SELECT * FROM npcs WHERE id=?', [r.insertId]);
  const npc = rows[0];
  if (npc?.sheet && typeof npc.sheet === 'string') { try { npc.sheet = JSON.parse(npc.sheet); } catch {} }
  res.json({ npc });
});

// Get NPC by id
app.get('/api/admin/npcs/:id', authRequired, requireAdmin, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM npcs WHERE id=?', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'NPC not found' });
  const npc = rows[0];
  if (npc?.sheet && typeof npc.sheet === 'string') { try { npc.sheet = JSON.parse(npc.sheet); } catch {} }
  res.json({ npc });
});

// Update NPC
app.patch('/api/admin/npcs/:id', authRequired, requireAdmin, async (req, res) => {
  const { name, clan, sheet, xp } = req.body;
  const fields = [], vals = [];
  if (name != null) { fields.push('name=?'); vals.push(name); }
  if (clan != null) { fields.push('clan=?'); vals.push(clan); }
  if (sheet !== undefined) { fields.push('sheet=?'); vals.push(sheet ? JSON.stringify(sheet) : null); }
  if (typeof xp === 'number') { fields.push('xp=?'); vals.push(xp); }
  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });

  vals.push(req.params.id);
  await pool.query(`UPDATE npcs SET ${fields.join(', ')} WHERE id=?`, vals);

  const [rows] = await pool.query('SELECT * FROM npcs WHERE id=?', [req.params.id]);
  const npc = rows[0];
  if (npc?.sheet && typeof npc.sheet === 'string') { try { npc.sheet = JSON.parse(npc.sheet); } catch {} }
  res.json({ npc });
});

// Delete NPC
app.delete('/api/admin/npcs/:id', authRequired, requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM npcs WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});

// Spend XP (NPC)
app.post('/api/admin/npcs/:id/xp/spend', authRequired, requireAdmin, async (req, res) => {
  const { type, target, currentLevel, newLevel, ritualLevel, formulaLevel, dots, disciplineKind, patchSheet } = req.body;

  const [rows] = await pool.query('SELECT * FROM npcs WHERE id=?', [req.params.id]);
  const ch = rows[0];
  if (!ch) return res.status(404).json({ error: 'NPC not found' });

  // cost calc same as before
  let cost = 0;
  try {
    if (type === 'discipline' && (disciplineKind === 'select' || Number(newLevel) === Number(currentLevel))) {
      cost = 0;
    } else {
      cost = xpCost({ type, newLevel, ritualLevel, formulaLevel, dots, disciplineKind });
    }
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  if ((ch.xp || 0) < cost) {
    return res.status(400).json({ error: `Not enough XP (need ${cost}, have ${ch.xp})` });
  }

  if (cost > 0) {
    await pool.query('UPDATE npcs SET xp = xp - ? WHERE id=?', [cost, ch.id]);
  }
  if (patchSheet !== undefined) {
    await pool.query('UPDATE npcs SET sheet=? WHERE id=?', [JSON.stringify(patchSheet), ch.id]);
  }

  // optional: log to xp_log if you want, but use character_id=null or a separate npc_id column if your schema supports it

  const [out] = await pool.query('SELECT * FROM npcs WHERE id=?', [ch.id]);
  const outCh = out[0];
  if (outCh?.sheet && typeof outCh.sheet === 'string') { try { outCh.sheet = JSON.parse(outCh.sheet); } catch {} }
  res.json({ character: outCh, spent: cost });
});

app.get('/api/admin/chat/npc-conversations/:npcId', authRequired, requireAdmin, async (req, res) => {
  const npcId = Number(req.params.npcId);
  try {
    // Query to get distinct users who have messaged this NPC, ordered by last message time.
    const [rows] = await pool.query(`
      SELECT 
        u.id AS user_id, 
        u.display_name, 
        c.name AS char_name, 
        MAX(m.created_at) AS last_message_at
      FROM npc_chat_messages m
      JOIN users u ON m.user_id = u.id
      LEFT JOIN characters c ON u.character_id = c.id
      WHERE m.npc_id = ?
      GROUP BY u.id, u.display_name, c.name
      ORDER BY last_message_at DESC
    `, [npcId]);
    
    res.json({ conversations: rows });
  } catch (e) {
    log.err('Admin get NPC conversations failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to fetch NPC conversations' });
  }
});

/** Admin: Get chat history between a specific NPC and a specific User */
app.get('/api/admin/chat/npc-history/:npcId/:userId', authRequired, requireAdmin, async (req, res) => {
  const npcId = Number(req.params.npcId);
  const userId = Number(req.params.userId);

  try {
    const [messages] = await pool.query(
      `SELECT id, body, from_side, created_at FROM npc_chat_messages 
       WHERE npc_id = ? AND user_id = ? 
       ORDER BY created_at ASC`,
      [npcId, userId]
    );
    
    res.json({ messages });
  } catch (e) {
    log.err('Admin fetch NPC chat history failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to fetch chat history' });
  }
});

/** Admin: Send a message from an NPC to a User */
app.post('/api/admin/chat/reply-as-npc/:npcId/:userId', authRequired, requireAdmin, async (req, res) => {
  const npcId = Number(req.params.npcId);
  const userId = Number(req.params.userId);
  const { body } = req.body;

  if (!body || body.trim().length === 0) {
    return res.status(400).json({ error: 'Message body is required' });
  }

  try {
    // Basic validation (NPC/User existence, assuming tables/data models)
    const [npcRows] = await pool.query('SELECT id FROM npcs WHERE id=?', [npcId]);
    if (npcRows.length === 0) {
      return res.status(404).json({ error: 'NPC not found' });
    }
    const [userRows] = await pool.query('SELECT id FROM users WHERE id=?', [userId]);
    if (userRows.length === 0) {
      return res.status(404).json({ error: 'Target user not found' });
    }

    // Insert message into the NPC chat table, sent from the 'npc' side
    await pool.query(
      'INSERT INTO npc_chat_messages (user_id, npc_id, body, from_side) VALUES (?, ?, ?, ?)',
      [userId, npcId, body, 'npc']
    );
    
    log.adm('Admin replied as NPC', { admin_id: req.user.id, npc_id: npcId, to_user_id: userId });
    res.json({ ok: true, message: 'Message sent as NPC' });
  } catch (e) {
    log.err('Admin reply as NPC failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to send message as NPC' });
  }
});

// List all NPCs (public for logged-in players)
app.get('/api/chat/npcs', authRequired, async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, name, clan
       FROM npcs
       ORDER BY name ASC`
    );
    res.json({ npcs: rows });
  } catch (e) {
    log.err('Failed to list NPCs', { message: e.message });
    res.status(500).json({ error: 'Failed to list NPCs' });
  }
});

// Player: get my conversation with an NPC
app.get('/api/chat/npc-history/:npcId', authRequired, async (req, res) => {
  try {
    const npcId = Number(req.params.npcId);
    const userId = req.user.id;

    const [rows] = await pool.query(
      `SELECT id, npc_id, user_id, from_side, body, created_at
         FROM npc_messages
        WHERE npc_id=? AND user_id=?
        ORDER BY created_at ASC`,
      [npcId, userId]
    );
    res.json({ messages: rows });
  } catch (e) {
    log.err('Failed to get NPC chat history', { message: e.message });
    res.status(500).json({ error: 'Failed to get history' });
  }
});

// Player: send message to an NPC
app.post('/api/chat/npc/messages', authRequired, async (req, res) => {
  try {
    const userId = req.user.id;
    const { npc_id, body } = req.body || {};
    if (!npc_id || !body || String(body).trim().length === 0) {
      return res.status(400).json({ error: 'npc_id and non-empty body are required' });
    }

    const [r] = await pool.query(
      'INSERT INTO npc_messages (npc_id, user_id, from_side, body) VALUES (?,?,?,?)',
      [Number(npc_id), userId, 'user', String(body).trim()]
    );

    const [[message]] = await pool.query(
      `SELECT id, npc_id, user_id, from_side, body, created_at
         FROM npc_messages
        WHERE id=?`,
      [r.insertId]
    );
    log.ok('NPC message (player)', { user_id: userId, npc_id, msg_id: r.insertId });
    res.status(201).json({ message });
  } catch (e) {
    log.err('Failed to send NPC message', { message: e.message });
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// --- Admin: reply as NPC to a specific player ---
app.get('/api/admin/chat/npc/history', authRequired, requireAdmin, async (req, res) => {
  try {
    const npcId = Number(req.query.npc_id);
    const userId = Number(req.query.user_id);
    if (!npcId || !userId) return res.status(400).json({ error: 'npc_id and user_id are required' });

    const [rows] = await pool.query(
      `SELECT id, npc_id, user_id, from_side, body, created_at
         FROM npc_messages
        WHERE npc_id=? AND user_id=?
        ORDER BY created_at ASC`,
      [npcId, userId]
    );
    res.json({ messages: rows });
  } catch (e) {
    log.err('Admin: NPC history failed', { message: e.message });
    res.status(500).json({ error: 'Failed to get history' });
  }
});

app.post('/api/admin/chat/npc/messages', authRequired, requireAdmin, async (req, res) => {
  try {
    const { npc_id, user_id, body } = req.body || {};
    if (!npc_id || !user_id || !body || String(body).trim().length === 0) {
      return res.status(400).json({ error: 'npc_id, user_id and non-empty body are required' });
    }

    const [r] = await pool.query(
      'INSERT INTO npc_messages (npc_id, user_id, from_side, body) VALUES (?,?,?,?)',
      [Number(npc_id), Number(user_id), 'npc', String(body).trim()]
    );

    const [[message]] = await pool.query(
      `SELECT id, npc_id, user_id, from_side, body, created_at
         FROM npc_messages
        WHERE id=?`,
      [r.insertId]
    );

    log.ok('Admin NPC reply', { npc_id, to_user: user_id, msg_id: r.insertId });
    res.status(201).json({ message });
  } catch (e) {
    log.err('Admin NPC reply failed', { message: e.message });
    res.status(500).json({ error: 'Failed to send NPC reply' });
  }
});


/* -------------------- Downtimes -------------------- */
// My quota this month
app.get('/api/downtimes/quota', authRequired, async (req, res) => {
  const [chars] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
  const ch = chars[0];
  if (!ch) {
    log.dt('Quota check (no character)', { user_id: req.user.id });
    return res.json({ used: 0, limit: 3 });
  }

  const from = startOfMonth();
  const to = endOfMonth();
  const [rows] = await pool.query(
    'SELECT COUNT(*) AS c FROM downtimes WHERE character_id=? AND created_at >= ? AND created_at < ?',
    [ch.id, from, to]
  );
  log.dt('Quota check', { user_id: req.user.id, used: rows[0].c, limit: 3 });
  res.json({ used: rows[0].c, limit: 3 });
});

// List my downtimes
app.get('/api/downtimes/mine', authRequired, async (req, res) => {
  const [[char]] = await Promise.all([
    pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]),
  ]);
  if (!char?.[0]) {
    log.dt('List mine (no character)', { user_id: req.user.id });
    return res.json({ downtimes: [] });
  }

  const [rows] = await pool.query(
    'SELECT * FROM downtimes WHERE character_id=? ORDER BY created_at DESC',
    [char[0].id]
  );
  log.dt('List mine', { user_id: req.user.id, count: rows.length });
  res.json({ downtimes: rows });
});

// Create downtime (3 per calendar month; auto feeding type)
app.post('/api/downtimes', authRequired, async (req, res) => {
  const { title, body, feeding_type } = req.body;
  if (!title || !body) {
    log.warn('Downtime create missing fields', { user_id: req.user.id });
    return res.status(400).json({ error: 'Title and body required' });
  }

  const [chars] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
  const ch = chars[0];
  if (!ch) {
    log.warn('Downtime create without character', { user_id: req.user.id });
    return res.status(400).json({ error: 'Create a character first' });
  }

  const from = startOfMonth();
  const to = endOfMonth();
  const [cnt] = await pool.query(
    'SELECT COUNT(*) AS c FROM downtimes WHERE character_id=? AND created_at >= ? AND created_at < ?',
    [ch.id, from, to]
  );
  if (cnt[0].c >= 3) {
    log.warn('Downtime limit reached', { user_id: req.user.id, count: cnt[0].c });
    return res.status(400).json({ error: 'Downtime limit reached for this month (3).' });
  }

  let defaultFeed = feeding_type;
  if (!defaultFeed) {
    let pred = null;
    if (ch.sheet) {
      try {
        const parsed = typeof ch.sheet === 'string' ? JSON.parse(ch.sheet) : ch.sheet;
        pred = parsed?.predatorType || null;
      } catch {}
    }
    defaultFeed = feedingFromPredator(pred);
  }

  const [r] = await pool.query(
    'INSERT INTO downtimes (character_id, title, feeding_type, body) VALUES (?,?,?,?)',
    [ch.id, title, defaultFeed || null, body]
  );
  const [rows] = await pool.query('SELECT * FROM downtimes WHERE id=?', [r.insertId]);
  log.dt('Downtime created', { user_id: req.user.id, downtime_id: r.insertId, feeding_type: defaultFeed || feeding_type || null });
  res.json({ downtime: rows[0] });
});

/* -------------------- Domains -------------------- */
// List domains with members (for players)
app.get('/api/domains', authRequired, async (_req, res) => {
  const [doms] = await pool.query('SELECT * FROM domains ORDER BY name ASC');
  if (!doms.length) {
    log.dom('Domains list (empty)');
    return res.json({ domains: [] });
  }

  const [rows] = await pool.query(
    `SELECT dm.domain_id, c.name AS char_name, c.clan
     FROM domain_members dm
     JOIN characters c ON c.id=dm.character_id`
  );

  const byDomain = rows.reduce((acc, r) => {
    (acc[r.domain_id] ||= []).push({ name: r.char_name, clan: r.clan });
    return acc;
  }, {});

  const out = doms.map(d => ({ ...d, members: byDomain[d.id] || [] }));
  log.dom('Domains list', { count: out.length });
  res.json({ domains: out });
});

// Admin: manage domains
app.post('/api/admin/domains', authRequired, requireAdmin, async (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const [r] = await pool.query('INSERT INTO domains (name, description) VALUES (?,?)', [name, description || null]);
  const [rows] = await pool.query('SELECT * FROM domains WHERE id=?', [r.insertId]);
  log.adm('Domain created', { id: r.insertId, name });
  res.json({ domain: rows[0] });
});

app.delete('/api/admin/domains/:id', authRequired, requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM domains WHERE id=?', [req.params.id]);
  log.adm('Domain deleted', { id: req.params.id });
  res.json({ ok: true });
});

app.post('/api/admin/domains/:id/members', authRequired, requireAdmin, async (req, res) => {
  const { character_id } = req.body;
  if (!character_id) return res.status(400).json({ error: 'character_id required' });
  await pool.query('INSERT IGNORE INTO domain_members (domain_id, character_id) VALUES (?,?)', [req.params.id, character_id]);
  log.adm('Domain member added', { domain_id: req.params.id, character_id });
  res.json({ ok: true });
});

app.delete('/api/admin/domains/:id/members/:character_id', authRequired, requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM domain_members WHERE domain_id=? AND character_id=?', [req.params.id, req.params.character_id]);
  log.adm('Domain member removed', { domain_id: req.params.id, character_id: req.params.character_id });
  res.json({ ok: true });
});

/* -------------------- Boons (FIXED) -------------------- */

// GET /api/boons/entities (Court/Admin only)
// Get all players and NPCs for dropdowns
app.get('/api/boons/entities', authRequired, requireCourt, async (req, res) => {
  try {
    const [characters] = await pool.query('SELECT id, name, clan FROM characters ORDER BY name ASC');
    const [npcs] = await pool.query('SELECT id, name, clan FROM npcs ORDER BY name ASC');
    
    const players = characters.map(c => ({ type: 'player', id: c.id, name: `${c.name} (${c.clan || 'Unknown'})` }));
    const nonPlayers = npcs.map(n => ({ type: 'npc', id: n.id, name: `${n.name} (NPC)` }));
    
    res.json({ entities: [...players, ...nonPlayers] });
  } catch (e) {
    log.err('Failed to get boon entities', { message: e.message });
    res.status(500).json({ error: 'Failed to fetch entities' });
  }
});

// GET /api/boons (All logged-in users)
app.get('/api/boons', authRequired, async (req, res) => {
  try {
    // Assuming a 'boons' table exists
    const [boons] = await pool.query(
      `SELECT * FROM boons ORDER BY created_at DESC`
    );
    res.json({ boons });
  } catch (e) {
    log.err('Failed to get boons', { message: e.message });
    res.status(500).json({ error: 'Failed to fetch boons' });
  }
});

// POST /api/boons (Court/Admin only)
app.post('/api/boons', authRequired, requireCourt, async (req, res) => {
  try {
    // FIX: Removed from_id and to_id
    const { from_name, to_name, level, status, description } = req.body;

    if (!from_name || !to_name || !level || !status) {
      return res.status(400).json({ error: 'From, To, Level, and Status are required' });
    }
    
    // FIX: Removed from_id and to_id from query
    const [r] = await pool.query(
      `INSERT INTO boons (from_name, to_name, level, status, description, created_at) 
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [from_name, to_name, level, status, description || null]
    );
    
    const [[boon]] = await pool.query('SELECT * FROM boons WHERE id=?', [r.insertId]);
    log.adm('Boon created', { id: r.insertId, by_user_id: req.user.id });
    res.status(201).json({ boon });
    
  } catch (e) {
    log.err('Failed to create boon', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to create boon' });
  }
});

// PATCH /api/boons/:id (Court/Admin only)
app.patch('/api/boons/:id', authRequired, requireCourt, async (req, res) => {
  try {
    const { id } = req.params;
    // FIX: Removed from_id and to_id
    const { from_name, to_name, level, status, description } = req.body;
    
    const fields = [], vals = [];
    if (from_name !== undefined) { fields.push('from_name=?'); vals.push(from_name); }
    if (to_name !== undefined) { fields.push('to_name=?'); vals.push(to_name); }
    if (level !== undefined) { fields.push('level=?'); vals.push(level); }
    if (status !== undefined) { fields.push('status=?'); vals.push(status); }
    if (description !== undefined) { fields.push('description=?'); vals.push(description); }

    if (!fields.length) {
      return res.status(400).json({ error: 'Nothing to update' });
    }
    
    vals.push(id);
    await pool.query(`UPDATE boons SET ${fields.join(', ')} WHERE id=?`, vals);
    
    const [[boon]] = await pool.query('SELECT * FROM boons WHERE id=?', [id]);
    log.adm('Boon updated', { id, by_user_id: req.user.id });
    res.json({ boon });
    
  } catch (e) {
    log.err('Failed to update boon', { message: e.message });
    res.status(500).json({ error: 'Failed to update boon' });
  }
});

// DELETE /api/boons/:id (Court/Admin only)
app.delete('/api/boons/:id', authRequired, requireCourt, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM boons WHERE id=?', [id]);
    log.adm('Boon deleted', { id, by_user_id: req.user.id });
    res.json({ ok: true });
  } catch (e) {
    log.err('Failed to delete boon', { message: e.message });
    res.status(500).json({ error: 'Failed to delete boon' });
  }
});


/* -------------------- Chat -------------------- */
// NOTE TO USER: You may need to add 'chat' to your logger configuration if it's a custom one.
// Get list of users to chat with (all except me)
app.get('/api/chat/users', authRequired, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `
      SELECT
        u.id,
        u.display_name,
        u.role,
        CASE WHEN u.role = 'admin' THEN 1 ELSE 0 END AS is_admin,
        /* collapse possible multiple characters to a single row */
        MAX(c.id)   AS char_id,
        MAX(c.name) AS char_name,
        MAX(c.clan) AS clan
      FROM users u
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE u.id <> ?
      GROUP BY u.id, u.display_name, u.role
      ORDER BY u.display_name ASC
      `,
      [req.user.id]
    );

    const users = rows.map(r => ({
      ...r,
      is_admin: !!r.is_admin,
      char_id: r.char_id ? Number(r.char_id) : null
    }));

    res.json({ users });
  } catch (e) {
    log.err('Failed to get chat users', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to get users' });
  }
});


// Get message history with another user
app.get('/api/chat/history/:otherUserId', authRequired, async (req, res) => {
  try {
    const otherUserId = Number(req.params.otherUserId);
    const myId = req.user.id;

    const [messages] = await pool.query(
      `SELECT cm.id, cm.sender_id, cm.recipient_id, cm.body, cm.created_at, u_sender.display_name as sender_name
       FROM chat_messages cm
       JOIN users u_sender ON cm.sender_id = u_sender.id
       WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
       ORDER BY created_at ASC`,
      [myId, otherUserId, otherUserId, myId]
    );
    res.json({ messages });
  } catch (e) {
    log.err('Failed to get chat history', { message: e.message });
    res.status(500).json({ error: 'Failed to get history' });
  }
});

// Send a message
app.post('/api/chat/messages', authRequired, async (req, res) => {
  try {
    const { recipient_id, body } = req.body;
    if (!recipient_id || !body || typeof body !== 'string' || body.trim().length === 0) {
      return res.status(400).json({ error: 'Recipient and non-empty body are required' });
    }

    const [r] = await pool.query(
      'INSERT INTO chat_messages (sender_id, recipient_id, body) VALUES (?, ?, ?)',
      [req.user.id, recipient_id, body.trim()]
    );

    const [[message]] = await pool.query(
      `SELECT cm.id, cm.sender_id, cm.recipient_id, cm.body, cm.created_at, u_sender.display_name as sender_name
       FROM chat_messages cm
       JOIN users u_sender ON cm.sender_id = u_sender.id
       WHERE cm.id = ?`,
      [r.insertId]
    );

    // --- START PUSH NOTIFICATION LOGIC ---
    try {
      // 1. Find all subscriptions for the user we are sending TO
      const [subs] = await pool.query(
        'SELECT id, subscription_json FROM push_subscriptions WHERE user_id = ?',
        [recipient_id]
      );

      if (subs.length > 0) {
        // 2. Create the notification payload
        const payload = JSON.stringify({
          title: `New message from ${req.user.display_name}`,
          body: body.trim(),
          data: {
            url: '/comms', // URL to open when clicked
            // Tagging allows notifications from the same user to stack
            tag: `chat-u-${req.user.id}` 
          }
        });

        // 3. Send a notification to each subscription
        // We use Promise.all but don't await it, so it runs in the background
        // and doesn't slow down the API response.
        const sendPromises = subs.map(row => {
          const subscription = JSON.parse(row.subscription_json);
          return webpush.sendNotification(subscription, payload)
            .catch(err => {
              // 4. If a subscription is "gone" (410), delete it from the DB
              if (err.statusCode === 410) {
                log.warn('Stale push subscription deleted', { sub_id: row.id, user_id: recipient_id });
                return pool.query('DELETE FROM push_subscriptions WHERE id = ?', [row.id]);
              } else {
                log.err('Push notification send failed', { message: err.message, statusCode: err.statusCode, user_id: recipient_id });
              }
            });
        });
        Promise.all(sendPromises);
      }
    } catch (pushError) {
      // Log the push error, but DO NOT fail the main API request
      log.err('Push notification trigger failed', { message: pushError.message, stack: pushError.stack });
    }
    // --- END PUSH NOTIFICATION LOGIC ---

    // Using `log.ok` as a generic success logger, assuming `log.chat` is not configured.
    log.ok('Message sent', { from: req.user.id, to: recipient_id, msg_id: r.insertId });
    res.status(201).json({ message });

  } catch (e) {
    log.err('Failed to send message', { message: e.message });
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Mark messages from a specific user as read
app.post('/api/chat/read', authRequired, async (req, res) => {
    try {
        const { sender_id } = req.body;
        if (!sender_id) return res.status(400).json({ error: 'sender_id is required' });

        await pool.query(
            'UPDATE chat_messages SET read_at = NOW() WHERE sender_id = ? AND recipient_id = ? AND read_at IS NULL',
            [sender_id, req.user.id]
        );
        res.json({ ok: true });
    } catch (e) {
        log.err('Failed to mark messages as read', { message: e.message });
        res.status(500).json({ error: 'Failed to mark as read' });
    }
});

// ADMIN: Get all chat messages
app.get('/api/admin/chat/all', authRequired, requireAdmin, async (req, res) => {
    try {
        const [messages] = await pool.query(
            `SELECT
                cm.id, cm.body, cm.created_at,
                s.id as sender_id, s.display_name as sender_name,
                r.id as recipient_id, r.display_name as recipient_name
            FROM chat_messages cm
            JOIN users s ON cm.sender_id = s.id
            JOIN users r ON cm.recipient_id = r.id
            ORDER BY cm.created_at DESC`
        );
        log.adm('Admin fetched all chat messages', { count: messages.length });
        res.json({ messages });
    } catch (e) {
        log.err('Failed to get all chat messages for admin', { message: e.message });
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});
// Admin: list recent conversations with one NPC
app.get('/api/admin/chat/npc/conversations', authRequired, requireAdmin, async (req, res) => {
  const npcId = Number(req.query.npc_id);
  if (!npcId) return res.status(400).json({ error: 'npc_id required' });
  try {
    const [rows] = await pool.query(`
      SELECT 
        u.id AS user_id,
        u.display_name,
        c.name AS char_name,
        MAX(m.created_at) AS last_message_at
      FROM npc_messages m
      JOIN users u ON m.user_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE m.npc_id = ?
      GROUP BY u.id, u.display_name, c.name
      ORDER BY last_message_at DESC
    `, [npcId]);
    res.json({ conversations: rows });
  } catch (e) {
    log.err('Admin get NPC conversations failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to fetch NPC conversations' });
  }
});

// Alias (path params)
app.get('/api/admin/chat/npc-conversations/:npcId', authRequired, requireAdmin, async (req, res) => {
  req.query.npc_id = req.params.npcId;
  return app._router.handle(req, res, () => {});
});

// Admin: history between NPC and specific user
app.get('/api/admin/chat/npc/history', authRequired, requireAdmin, async (req, res) => {
  const npcId  = Number(req.query.npc_id);
  const userId = Number(req.query.user_id);
  if (!npcId || !userId) return res.status(400).json({ error: 'npc_id and user_id required' });

  try {
    const [messages] = await pool.query(
      `SELECT id, npc_id, user_id, from_side, body, created_at
         FROM npc_messages
        WHERE npc_id=? AND user_id=?
        ORDER BY created_at ASC`,
      [npcId, userId]
    );
    res.json({ messages });
  } catch (e) {
    log.err('Admin fetch NPC chat history failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to fetch chat history' });
  }
});

// Alias (path params)
app.get('/api/admin/chat/npc-history/:npcId/:userId', authRequired, requireAdmin, async (req, res) => {
  req.query.npc_id  = req.params.npcId;
  req.query.user_id = req.params.userId;
  return app._router.handle(req, res, () => {});
});



/* -------------------- Admin views -------------------- */
app.get('/api/admin/users', authRequired, requireAdmin, async (_req, res) => {
  const [rows] = await pool.query(
    `SELECT u.id, u.email, u.display_name, u.role,
            c.id AS character_id, c.name AS char_name, c.clan, c.sheet, c.xp
     FROM users u
     LEFT JOIN characters c ON c.user_id=u.id
     ORDER BY u.created_at DESC`
  );
  rows.forEach(r => {
    if (r.sheet && typeof r.sheet === 'string') {
      try { r.sheet = JSON.parse(r.sheet); } catch {}
    }
  });
  log.adm('Admin users list', { count: rows.length });
  res.json({ users: rows });
});

// Player: get my recent NPC conversations (latest messages first)
app.get('/api/chat/my-recent', authRequired, async (req, res) => {
  try {
    const userId = req.user.id;
    const limit = Math.min(Number(req.query.limit) || 5, 10);

    // Last messages with any NPC for this user
    const [rows] = await pool.query(
      `
      SELECT m.npc_id,
             n.name   AS npc_name,
             m.body   AS last_message,
             m.created_at
      FROM npc_messages m
      JOIN npcs n ON n.id = m.npc_id
      WHERE m.user_id = ?
      ORDER BY m.created_at DESC
      LIMIT ?
      `,
      [userId, limit]
    );

    const conversations = rows.map(r => ({
      id: `npc-${r.npc_id}`,
      partnerName: r.npc_name,
      lastMessage: r.last_message,
      timestamp: r.created_at,
      isNPC: true,
    }));

    res.json({ conversations });
  } catch (e) {
    log.err('Failed to fetch my recent chats', { message: e.message });
    res.status(500).json({ error: 'Failed to load recent chats' });
  }
});

// Update a user (admin only)

app.patch('/api/admin/users/:id', authRequired, requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: 'Invalid user id' });
    }

    const { display_name, email, role } = req.body || {};
    const fields = [];
    const vals = [];

    // Validate role if provided
    const validRoles = new Set(['user', 'courtuser', 'admin']);
    let roleChanged = false;
    if (role !== undefined) {
      const r = String(role);
      if (!validRoles.has(r)) {
        return res.status(400).json({ error: 'Invalid role' });
      }
      fields.push('role=?'); vals.push(r);
      roleChanged = true;
    }

    // Validate display_name if provided
    let nameChanged = false;
    if (display_name !== undefined) {
      const name = String(display_name).trim();
      if (!name) return res.status(400).json({ error: 'Display name cannot be empty' });
      fields.push('display_name=?'); vals.push(name);
      nameChanged = true;
    }

    // Validate email if provided (and ensure uniqueness)
    let emailChanged = false;
    if (email !== undefined) {
      const normEmail = String(email).trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normEmail)) {
        return res.status(400).json({ error: 'Invalid email' });
      }
      const [dup] = await pool.query('SELECT id FROM users WHERE email=? AND id<>?', [normEmail, id]);
      if (dup.length) return res.status(409).json({ error: 'Email already in use' });
      fields.push('email=?'); vals.push(normEmail);
      emailChanged = true;
    }

    if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });

    vals.push(id);
    await pool.query(`UPDATE users SET ${fields.join(', ')} WHERE id=?`, vals);

    // Return the updated user row (+ basic character info for admin table)
    const [[row]] = await pool.query(
      `SELECT u.id, u.email, u.display_name, u.role,
              c.id AS character_id, c.name AS char_name, c.clan, c.xp
       FROM users u
       LEFT JOIN characters c ON c.user_id = u.id
       WHERE u.id=?`,
      [id]
    );

    if (!row) return res.status(404).json({ error: 'User not found after update' });

    const selfEdit = id === req.user.id;
    if (selfEdit && (roleChanged || nameChanged || emailChanged)) {
      // Re-issue token so /api/auth/me reflects the new role/name/email
      const freshToken = issueToken({
        id: row.id,
        email: row.email,
        display_name: row.display_name,
        role: row.role,
      });
      log?.adm?.('Admin self-updated user and refreshed token', { admin_id: req.user.id, user_id: id, fields });
      return res.json({ user: row, token: freshToken });
    }

    log?.adm?.('Admin updated user', { admin_id: req.user.id, user_id: id, fields });
    res.json({ user: row });
  } catch (e) {
    log?.err?.('Admin update user failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// 2) Auth: refresh current user's token from DB (useful beyond admin flow)
app.post('/api/auth/refresh', authRequired, async (req, res) => {
  try {
    const [[u]] = await pool.query(
      'SELECT id, email, display_name, role FROM users WHERE id=?',
      [req.user.id]
    );
    if (!u) return res.status(404).json({ error: 'User not found' });
    const token = issueToken(u);
    res.json({ token, user: u });
  } catch (e) {
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});



app.get('/api/admin/downtimes', authRequired, requireAdmin, async (_req, res) => {
  const [rows] = await pool.query(
    `SELECT d.*, c.name AS char_name, c.clan, u.display_name AS player_name, u.email
     FROM downtimes d
     JOIN characters c ON c.id=d.character_id
     JOIN users u ON u.id=c.user_id
     ORDER BY d.created_at DESC`
  );
  log.adm('Admin downtimes list', { count: rows.length });
  res.json({ downtimes: rows });
});

app.patch('/api/admin/downtimes/:id', authRequired, requireAdmin, async (req, res) => {
  const { status, gm_notes, gm_resolution } = req.body;
  const allowed = ['submitted', 'approved', 'rejected', 'resolved', 'Needs a Scene', 'Resolved in scene'];
  if (status && !allowed.includes(status)) return res.status(400).json({ error: 'Bad status' });

  const fields = [];
  const vals = [];

  if (status) { fields.push('status=?'); vals.push(status); }
  if (typeof gm_notes === 'string') { fields.push('gm_notes=?'); vals.push(gm_notes); }
  if (typeof gm_resolution === 'string') { fields.push('gm_resolution=?'); vals.push(gm_resolution); }

  // auto-set resolved_at when marking resolved
  if (status === 'resolved') {
    fields.push('resolved_at=?');
    vals.push(new Date());
  }

  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });

  vals.push(req.params.id);
  await pool.query(`UPDATE downtimes SET ${fields.join(', ')} WHERE id=?`, vals);

  const [rows] = await pool.query('SELECT * FROM downtimes WHERE id=?', [req.params.id]);
  log.adm('Downtime updated', { id: req.params.id, fields });
  res.json({ downtime: rows[0] });
});

/* -------------------- Domain Claims -------------------- */
/** List all claims (public for logged-in users) */
app.get('/api/domain-claims', authRequired, async (_req, res) => {
  const [rows] = await pool.query(
    'SELECT division, owner_name, color, owner_character_id, claimed_at FROM domain_claims'
  );
  res.json({ claims: rows });
});

/** Claim a division by number with a hex color (first come first served) */
app.post('/api/domain-claims/claim', authRequired, async (req, res) => {
  const { division, color } = req.body;
  const hex = (color || '').trim();
  if (!Number.isInteger(division)) {
    return res.status(400).json({ error: 'division must be an integer' });
  }
  if (!/^#([0-9a-fA-F]{6})$/.test(hex)) {
    return res.status(400).json({ error: 'color must be a 6-digit hex like #ff0066' });
  }

  // find caller’s character (optional owner_character_id)
  const [chars] = await pool.query('SELECT id, name FROM characters WHERE user_id=?', [req.user.id]);
  const myChar = chars[0] || null;
  const ownerName = myChar?.name || req.user.display_name || req.user.email;

  // is it already claimed?
  const [exists] = await pool.query('SELECT division FROM domain_claims WHERE division=?', [division]);
  if (exists.length) {
    return res.status(409).json({ error: 'This division is already claimed.' });
  }

  await pool.query(
    'INSERT INTO domain_claims (division, owner_character_id, owner_name, color) VALUES (?,?,?,?)',
    [division, myChar?.id || null, ownerName, hex]
  );

  const [row] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [division]);
  res.json({ claim: row[0] });
});

// --- Admin: override/transfer a claim (safe upsert) ---
app.patch('/api/admin/domain-claims/:division', authRequired, requireAdmin, async (req, res) => {
  const division = Number(req.params.division);
  const { owner_name, color, owner_character_id } = req.body;

  const fields = [];
  const vals = [];

  if (typeof owner_name === 'string' && owner_name.trim()) { fields.push('owner_name=?'); vals.push(owner_name.trim()); }
  if (typeof color === 'string') {
    if (!/^#([0-9a-fA-F]{6})$/.test(color)) return res.status(400).json({ error: 'color must be #RRGGBB' });
    fields.push('color=?'); vals.push(color);
  }
  if (owner_character_id === null) {
    fields.push('owner_character_id=NULL');
  } else if (owner_character_id !== undefined) {
    if (!Number.isInteger(owner_character_id)) return res.status(400).json({ error: 'owner_character_id must be integer or null' });
    fields.push('owner_character_id=?'); vals.push(owner_character_id);
  }

  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });

  // 1) Try update existing
  vals.push(division);
  const [upd] = await pool.query(`UPDATE domain_claims SET ${fields.join(', ')} WHERE division=?`, vals);

  if (upd.affectedRows === 0) {
    // 2) Insert new with provided fields merged onto sensible defaults
    const base = {
      owner_name: (typeof owner_name === 'string' && owner_name.trim()) ? owner_name.trim() : 'Admin Set',
      color: (typeof color === 'string') ? color : '#888888',
      owner_character_id: (owner_character_id === null || owner_character_id === undefined) ? null : Number(owner_character_id),
    };
    await pool.query(
      'INSERT INTO domain_claims (division, owner_name, color, owner_character_id) VALUES (?,?,?,?)',
      [division, base.owner_name, base.color, base.owner_character_id]
    );
  }

  const [row] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [division]);
  log.adm('Domain claim upsert', { division });
  res.json({ claim: row[0] });
});


/** Admin: unclaim (delete) */
app.delete('/api/admin/domain-claims/:division', authRequired, requireAdmin, async (req, res) => {
  const division = Number(req.params.division);
  await pool.query('DELETE FROM domain_claims WHERE division=?', [division]);
  res.json({ ok: true });
});

const readline = require('readline');

// helper to tail last N lines of a file fairly efficiently (works for large files)
async function tailFile(filePath, maxLines = 200) {
  // fallback if file missing
  if (!fs.existsSync(filePath)) return [];

  // For simplicity/readability: read file stream and keep last N lines in an array
  return new Promise((resolve, reject) => {
    const input = fs.createReadStream(filePath, { encoding: 'utf8' });
    const rl = readline.createInterface({ input, crlfDelay: Infinity });
    const buf = [];
    rl.on('line', (line) => {
      buf.push(line);
      if (buf.length > maxLines) buf.shift();
    });
    rl.on('close', () => resolve(buf));
    rl.on('error', (err) => reject(err));
  });
}

// Admin: fetch last N lines
app.get('/api/admin/logs', authRequired, requireAdmin, async (req, res) => {
  const file = process.env.LOG_FILE;
  if (!file) return res.status(404).json({ error: 'Log file not configured' });

  const lines = Number(req.query.lines || 200);
  try {
    const last = await tailFile(file, Math.min(1000, Math.max(10, lines)));
    // If LOG_JSON=1, return parsed JSON objects (best-effort)
    if (process.env.LOG_JSON === '1') {
      const parsed = last.map(l => {
        try { return JSON.parse(l); } catch { return { raw: l }; }
      });
      return res.json({ ok: true, lines: parsed });
    } else {
      return res.json({ ok: true, lines: last });
    }
  } catch (e) {
    log.err('Admin logs read failed', { message: e.message });
    return res.status(500).json({ error: 'Failed to read log file' });
  }
});

// Admin: download full log (stream)
app.get('/api/admin/logs/download', authRequired, requireAdmin, (req, res) => {
  const file = process.env.LOG_FILE;
  if (!file) return res.status(404).json({ error: 'Log file not configured' });
  const fp = path.resolve(file);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Log file missing' });

  res.setHeader('Content-Disposition', `attachment; filename="${path.basename(fp)}"`);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  const stream = fs.createReadStream(fp);
  stream.pipe(res);
  stream.on('error', (err) => {
    log.err('Admin logs download failed', { message: err.message });
    res.end();
  });
});

// Admin: clear log file (truncate) — use with care
app.post('/api/admin/logs/clear', authRequired, requireAdmin, (req, res) => {
  const file = process.env.LOG_FILE;
  if (!file) return res.status(440).json({ error: 'Log file not configured' });
  const fp = path.resolve(file);
  try {
    fs.truncateSync(fp, 0);
    log.adm('Log file truncated by admin', { admin_id: req.user.id });
    return res.json({ ok: true });
  } catch (e) {
    log.err('Admin clear logs failed', { message: e.message });
    return res.status(500).json({ error: 'Failed to clear log file' });
  }
});

// Admin: fetch ALL NPC chat messages (flat list)
app.get('/api/admin/chat/npc/all', authRequired, requireAdmin, async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT 
         id, 
         npc_id, 
         user_id, 
         from_side, 
         body, 
         created_at
       FROM npc_messages
       ORDER BY created_at ASC`
    );

    // Example shape:
    // { "messages": [ { id, npc_id, user_id, from_side, body, created_at }, ... ] }
    res.json({ messages: rows });
  } catch (e) {
    log.err('Admin fetch ALL NPC messages failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to fetch NPC messages' });
  }
});


// --- NEW ROUTE to save a subscription ---
// --- PUSH: UPSERT SUB, TEST SEND, UNSUBSCRIBE ---

// Save/Upsert subscription (auth required)
app.post('/api/push/subscribe', authRequired, async (req, res) => {
  try {
    const { subscription } = req.body || {};
    if (!subscription || !subscription.endpoint) {
      return res.status(400).json({ error: 'Valid subscription with endpoint is required' });
    }

    const endpoint = subscription.endpoint;
    const json = JSON.stringify(subscription);

    // Ensure table exists (idempotent; comment out if you already created it)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        endpoint VARCHAR(512) NOT NULL UNIQUE,
        subscription_json JSON NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB
    `);

    // Upsert by endpoint, so repeated toggles don't duplicate
    await pool.query(
      `INSERT INTO push_subscriptions (user_id, endpoint, subscription_json)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), subscription_json=VALUES(subscription_json)`,
      [req.user.id, endpoint, json]
    );

    log.ok('Push subscription upserted', { user_id: req.user.id });
    res.status(201).json({ ok: true });
  } catch (e) {
    log.err('Push subscribe failed', { message: e.message });
    res.status(500).json({ error: 'Failed to save subscription' });
  }
});

// Unsubscribe: delete by endpoint (auth required)
app.post('/api/push/unsubscribe', authRequired, async (req, res) => {
  try {
    const { endpoint } = req.body || {};
    if (!endpoint) return res.status(400).json({ error: 'endpoint is required' });

    await pool.query('DELETE FROM push_subscriptions WHERE user_id=? AND endpoint=?', [req.user.id, endpoint]);
    log.ok('Push subscription removed', { user_id: req.user.id });
    res.json({ ok: true });
  } catch (e) {
    log.err('Push unsubscribe failed', { message: e.message });
    res.status(500).json({ error: 'Failed to remove subscription' });
  }
});



// Fire a test push to current user (auth required)
app.post('/api/push/test', authRequired, async (req, res) => {
  try {
    if (!vapidPublicKey || !vapidPrivateKey) {
      return res.status(503).json({ error: 'Push not configured (VAPID keys missing)' });
    }

    const [subs] = await pool.query(
      'SELECT id, subscription_json FROM push_subscriptions WHERE user_id=?',
      [req.user.id]
    );
    if (subs.length === 0) {
      return res.status(404).json({ error: 'No push subscriptions for this user' });
    }

    const payload = JSON.stringify({
      title: '🔔 Push Test',
      body: 'If you can read this, background push works!',
      data: { url: '/comms', tag: 'push-test' }
    });

    await Promise.all(subs.map(async (row) => {
      try {
        const sub = JSON.parse(row.subscription_json);
        await webpush.sendNotification(sub, payload);
      } catch (err) {
        if (err.statusCode === 410) {
          log.warn('Stale push sub removed during test', { sub_id: row.id, user_id: req.user.id });
          await pool.query('DELETE FROM push_subscriptions WHERE id=?', [row.id]);
        } else {
          log.err('Push test send failed', { message: err.message, status: err.statusCode });
        }
      }
    }));

    res.json({ ok: true });
  } catch (e) {
    log.err('Push test failed', { message: e.message });
    res.status(500).json({ error: 'Failed to send test push' });
  }
});


// --- NEW ROUTE to remove a subscription (e.g., on logout) ---
app.post('/api/push/unsubscribe', authRequired, async (req, res) => {
    // Logic to find and delete the subscription from your DB
    // ...
    res.json({ ok: true });
});


app.use(attachRequestLogger({
  silentPaths: [/^\/api\/admin\/logs(?:\/.*)?$/] // don’t log when hitting the logs endpoints
}));

// app.use(expressErrorHandler); // This was duplicated, removed one

/* -------------------- Coteries -------------------- */

/**
 * Create a coterie
 * body: {
 * name, type, domain_id|null,
 * traits:{chasse,lien,portillon},
 * required (object of {Name: dots}),
 * backgrounds (array of {name,dots}),
 * extras (array of strings),
 * points_per_member (1|2),
 * coterie_xp (number),
 * members: [{ user_id, display_name }]
 * }
 */
app.post('/api/coteries', authRequired, async (req, res) => {
  try {
    const {
      name, type, domain_id,
      traits = {},
      required = null,
      backgrounds = [],
      extras = [],
      points_per_member = 1,
      coterie_xp = 0,
      members = []
    } = req.body || {};

    if (!name || !Array.isArray(members) || members.length < 3) {
      return res.status(400).json({ error: 'Name and ≥3 members are required' });
    }

    const chasse = Number(traits.chasse || 0);
    const lien   = Number(traits.lien   || 0);
    const portillon = Number(traits.portillon || 0);

    const [ins] = await pool.query(
      `INSERT INTO coteries
       (name, type, domain_id, chasse, lien, portillon, required_json, backgrounds_json, extras_json, points_per_member, coterie_xp, created_by)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        name.trim(),
        type || null,
        domain_id || null,
        chasse, lien, portillon,
        required ? JSON.stringify(required) : null,
        JSON.stringify(backgrounds || []),
        JSON.stringify(extras || []),
        Math.min(2, Math.max(1, Number(points_per_member || 1))),
        Number.isFinite(coterie_xp) ? coterie_xp : 0,
        req.user.id
      ]
    );
    const coterieId = ins.insertId;

    if (members.length) {
      const values = members.map(m => [coterieId, Number(m.user_id), (m.display_name || null)]);
      await pool.query(
        `INSERT INTO coterie_members (coterie_id, user_id, display_name) VALUES ?`,
        [values]
      );
    }

    const [[row]] = await pool.query(`SELECT * FROM coteries WHERE id=?`, [coterieId]);
    log.ok('Coterie created', { id: coterieId, by_user_id: req.user.id });
    res.status(201).json({ coterie: row });
  } catch (e) {
    log.err('Create coterie failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to create coterie' });
  }
});

// List coteries (admin → all, user → only where member)
app.get('/api/coteries', authRequired, async (req, res) => {
  try {
    if (req.user.role === 'admin' || req.user.permission_level === 'admin') {
      const [rows] = await pool.query(`SELECT * FROM coteries ORDER BY updated_at DESC`);
      return res.json({ coteries: rows });
    }
    const [rows] = await pool.query(`
      SELECT c.*
      FROM coteries c
      JOIN coterie_members m ON m.coterie_id=c.id
      WHERE m.user_id=?
      ORDER BY c.updated_at DESC
    `, [req.user.id]);
    res.json({ coteries: rows });
  } catch (e) {
    log.err('List coteries failed', { message: e.message });
    res.status(500).json({ error: 'Failed to load coteries' });
  }
});

// Read single coterie (member or admin)
app.get('/api/coteries/:id', authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const [[c]] = await pool.query(`SELECT * FROM coteries WHERE id=?`, [id]);
    if (!c) return res.status(404).json({ error: 'Not found' });

    // authz: admin or member
    if (!(req.user.role === 'admin' || req.user.permission_level === 'admin')) {
      const [m] = await pool.query(`SELECT 1 FROM coterie_members WHERE coterie_id=? AND user_id=?`, [id, req.user.id]);
      if (!m.length) return res.status(403).json({ error: 'Not allowed' });
    }

    const [members] = await pool.query(`SELECT user_id, display_name FROM coterie_members WHERE coterie_id=?`, [id]);
    res.json({ coterie: c, members });
  } catch (e) {
    log.err('Read coterie failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to load coterie' });
  }
});



// Update core fields (member or admin)
app.put('/api/coteries/:id', authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);

    // must be admin or member
    if (!(req.user.role === 'admin' || req.user.permission_level === 'admin')) {
      const [m] = await pool.query(`SELECT 1 FROM coterie_members WHERE coterie_id=? AND user_id=?`, [id, req.user.id]);
      if (!m.length) return res.status(403).json({ error: 'Not allowed' });
    }

    const {
      name, type, domain_id,
      traits = {},
      required = null,
      backgrounds = [],
      extras = [],
      points_per_member,
      coterie_xp
    } = req.body || {};

    const fields = [];
    const params = [];
    if (name != null) { fields.push('name=?'); params.push(String(name)); }
    if (type != null) { fields.push('type=?'); params.push(type || null); }
    if (domain_id !== undefined) { fields.push('domain_id=?'); params.push(domain_id || null); }
    if (traits) {
      fields.push('chasse=?','lien=?','portillon=?');
      params.push(Number(traits.chasse || 0), Number(traits.lien || 0), Number(traits.portillon || 0));
    }
    if (required !== undefined) { fields.push('required_json=?'); params.push(required ? JSON.stringify(required) : null); }
    if (backgrounds !== undefined) { fields.push('backgrounds_json=?'); params.push(JSON.stringify(backgrounds || [])); }
    if (extras !== undefined) { fields.push('extras_json=?'); params.push(JSON.stringify(extras || [])); }
    if (points_per_member !== undefined) { fields.push('points_per_member=?'); params.push(Math.min(2, Math.max(1, Number(points_per_member || 1)))); }
    if (coterie_xp !== undefined) { fields.push('coterie_xp=?'); params.push(Number(coterie_xp || 0)); }

    if (!fields.length) return res.json({ ok: true });

    await pool.query(`UPDATE coteries SET ${fields.join(', ')} WHERE id=?`, [...params, id]);
    const [[row]] = await pool.query(`SELECT * FROM coteries WHERE id=?`, [id]);
    res.json({ coterie: row });
  } catch (e) {
    log.err('Update coterie failed', { message: e.message });
    res.status(500).json({ error: 'Failed to update coterie' });
  }
});

// Replace members (admin or current member)
app.post('/api/coteries/:id/members/set', authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!(req.user.role === 'admin' || req.user.permission_level === 'admin')) {
      const [m] = await pool.query(`SELECT 1 FROM coterie_members WHERE coterie_id=? AND user_id=?`, [id, req.user.id]);
      if (!m.length) return res.status(403).json({ error: 'Not allowed' });
    }

    const { members = [] } = req.body || {};
    if (!Array.isArray(members) || members.length < 3) {
      return res.status(400).json({ error: '≥3 members required' });
    }

    await pool.query(`DELETE FROM coterie_members WHERE coterie_id=?`, [id]);
    const values = members.map(m => [id, Number(m.user_id), (m.display_name || null)]);
    await pool.query(`INSERT INTO coterie_members (coterie_id, user_id, display_name) VALUES ?`, [values]);

    const [rows] = await pool.query(`SELECT user_id, display_name FROM coterie_members WHERE coterie_id=?`, [id]);
    res.json({ members: rows });
  } catch (e) {
    log.err('Set coterie members failed', { message: e.message });
    res.status(500).json({ error: 'Failed to set members' });
  }
});

// Adjust Coterie XP (delta) - admin or member
// body: { delta: +N | -N }
app.post('/api/coteries/:id/xp', authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!(req.user.role === 'admin' || req.user.permission_level === 'admin')) {
      const [m] = await pool.query(`SELECT 1 FROM coterie_members WHERE coterie_id=? AND user_id=?`, [id, req.user.id]);
      if (!m.length) return res.status(403).json({ error: 'Not allowed' });
    }
    const delta = Number(req.body?.delta || 0);
    await pool.query(`UPDATE coteries SET coterie_xp = GREATEST(0, coterie_xp + ?) WHERE id=?`, [delta, id]);
    const [[row]] = await pool.query(`SELECT coterie_xp FROM coteries WHERE id=?`, [id]);
    res.json({ coterie_xp: row?.coterie_xp ?? 0 });
  } catch (e) {
    log.err('Adjust coterie XP failed', { message: e.message });
    res.status(500).json({ error: 'Failed to adjust XP' });
  }
});

// Delete coterie (admin only)
app.delete('/api/coteries/:id', authRequired, requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    await pool.query(`DELETE FROM coteries WHERE id=?`, [id]);
    log.adm('Coterie deleted', { id, by_user_id: req.user.id });
    res.json({ ok: true });
  } catch (e) {
    log.err('Delete coterie failed', { message: e.message });
    res.status(500).json({ error: 'Failed to delete coterie' });
  }
});

// GET: public to logged-in users (players need to see dates)
// READ: players (and admins) can read the two dates
app.get('/api/downtimes/config', authRequired, async (req, res) => {
  try {
    const deadline = await getSetting('downtime_deadline', null);
    const opening  = await getSetting('downtime_opening', null);
    res.json({
      downtime_deadline: deadline || null,
      downtime_opening: opening  || null,
    });
  } catch (e) {
    console.error('Fetch downtime config failed:', e);
    res.status(500).json({ error: 'Failed to fetch downtime config' });
  }
});

// WRITE (admins): save the two dates
// ⚠️ make sure the path is **/admin/downtimes/config** (no extra 'c')
app.post('/api/admin/downtimes/config', authRequired, requireAdmin, async (req, res) => {
  try {
    const { downtime_deadline, downtime_opening } = req.body || {};

    if (downtime_deadline && isNaN(new Date(downtime_deadline).getTime())) {
      return res.status(400).json({ error: 'Invalid downtime_deadline date' });
    }
    if (downtime_opening && isNaN(new Date(downtime_opening).getTime())) {
      return res.status(400).json({ error: 'Invalid downtime_opening date' });
    }

    if (typeof downtime_deadline !== 'undefined') {
      await setSetting('downtime_deadline', downtime_deadline || '');
    }
    if (typeof downtime_opening !== 'undefined') {
      await setSetting('downtime_opening', downtime_opening || '');
    }

    const deadline = await getSetting('downtime_deadline', null);
    const opening  = await getSetting('downtime_opening', null);
    res.json({
      ok: true,
      downtime_deadline: deadline || null,
      downtime_opening: opening  || null,
    });
  } catch (e) {
    console.error('Update downtime config failed:', e);
    res.status(500).json({ error: 'Failed to update downtime config' });
  }
});


/* -------------------- NEW PREMONITION ROUTES -------------------- */

// ADMIN: Get list of Malkavian players  ✅ REPLACE THIS ROUTE
app.get('/api/admin/premonitions/malkavians', authRequired, requireAdmin, async (req, res) => {
  try {
    await _ensurePremonitionsTables();

    // One row per user that has at least one Malkavian character
    const [rows] = await pool.query(`
      SELECT 
        u.id,
        u.display_name,
        COALESCE(MAX(c.name), '(no character)') AS char_name
      FROM users u
      LEFT JOIN characters c 
        ON c.user_id = u.id
      WHERE u.role <> 'admin'
        AND EXISTS (
          SELECT 1
          FROM characters c2
          WHERE c2.user_id = u.id
            AND LOWER(TRIM(c2.clan)) = 'malkavian'
        )
      GROUP BY u.id, u.display_name
      ORDER BY u.display_name ASC
    `);

    res.json({ malkavians: rows });
  } catch (e) {
    log.err('Failed to get Malkavian list', { message: e.message });
    res.status(500).json({ error: 'Failed to get Malkavians' });
  }
});

// ADMIN: Upload media and store it in the DB
app.post('/api/admin/premonitions/upload', authRequired, requireAdmin, memoryUpload.single('file'), async (req, res) => {
  try {
    await _ensurePremonitionsMediaTables(); // Ensure media table exists
    if (!req.file) {
      return res.status(400).json({ error: 'File is required' });
    }
    const { originalname, mimetype, size, buffer } = req.file;

    const [ins] = await pool.query(
      'INSERT INTO premonition_media (filename, mime, size, data) VALUES (?,?,?,?)',
      [originalname || 'upload', mimetype, size, buffer]
    );
    const media_id = ins.insertId;

    res.json({
      media_id,
      media_mime: mimetype,
      media_stream_url: `/api/premonitions/media/${media_id}`
    });
  } catch (e) {
    log.err('Premonition media upload failed', { message: e.message });
    res.status(500).json({ error: 'Failed to upload media' });
  }
});

// ADMIN: Create and send a new premonition
app.post('/api/admin/premonitions/send', authRequired, requireAdmin, async (req, res) => {
  try {
    await _ensurePremonitionsTables(); // Ensure main tables exist
    const { content_type, content_text, content_url, user_ids = [] } = req.body;
    const sendToAllMalks = user_ids.includes('all_malkavians');
    
    if (!content_type || (!content_text && !content_url)) {
      return res.status(400).json({ error: 'Type and content (text or URL) are required' });
    }

    // 1. Create the premonition content
    const [ins] = await pool.query(
      `INSERT INTO premonitions (sender_id, content_type, content_text, content_url)
       VALUES (?, ?, ?, ?)`,
      [req.user.id, content_type, content_text || null, content_url || null]
    );
    const premonitionId = ins.insertId;

    // 2. Figure out who to send it to
    let targetUserIds = [];
    if (sendToAllMalks) {
      // Get all non-admin Malkavian user IDs
      const [malks] = await pool.query(`
        SELECT DISTINCT u.id
        FROM users u
        JOIN characters c ON c.user_id = u.id
        WHERE u.role <> 'admin'
          AND LOWER(TRIM(c.clan)) = 'malkavian'
      `);
      targetUserIds = malks.map(m => m.id);
    } else {
      // Use the specific list, filtering out any non-numeric values
      targetUserIds = user_ids.map(id => parseInt(id)).filter(id => !isNaN(id));
    }

    // 3. Insert recipients
    if (targetUserIds.length > 0) {
      // Remove duplicates
      const uniqueUserIds = [...new Set(targetUserIds)];
      const values = uniqueUserIds.map(userId => [premonitionId, userId]);
      await pool.query(
        'INSERT INTO premonition_recipients (premonition_id, user_id) VALUES ?',
        [values]
      );
    }
    
    log.adm('Admin sent premonition', { id: premonitionId, by_user_id: req.user.id, targets: sendToAllMalks ? 'all_malks' : targetUserIds });
    res.status(201).json({ ok: true, premonition_id: premonitionId, count: targetUserIds.length });

  } catch (e) {
    log.err('Failed to send premonition', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to send premonition' });
  }
});

// PLAYER: Get my premonitions
app.get('/api/premonitions/mine', authRequired, async (req, res) => {
  try {
    await _ensurePremonitionsTables();

    const [rows] = await pool.query(`
      SELECT p.*
      FROM premonitions p
      JOIN premonition_recipients pr ON p.id = pr.premonition_id
      WHERE pr.user_id = ?
      ORDER BY p.created_at DESC
    `, [req.user.id]);

    // fire & forget mark viewed
    if (rows.length > 0) {
      const ids = rows.map(r => r.id);
      pool.query(
        `UPDATE premonition_recipients
         SET viewed_at = NOW()
         WHERE user_id = ? AND premonition_id IN (${ids.map(() => '?').join(',')})
           AND viewed_at IS NULL`,
        [req.user.id, ...ids]
      ).catch(err => log.err('Failed to mark premonitions as read', { message: err.message }));
    }

    // 👇 ΑΥΤΟ είναι το σημαντικό
    res.set('Cache-Control', 'no-store');
    res.status(200).json({ premonitions: rows });
  } catch (e) {
    log.err('Failed to get my premonitions', { message: e.message });
    res.status(500).json({ error: 'Failed to load premonitions' });
  }
});



// MEDIA: Stream media from DB
app.get('/api/premonitions/media/:id', authRequired, async (req, res) => {
  try {
    await _ensurePremonitionsMediaTables();
    const id = Number(req.params.id) || 0;
    
    // **FIX: Initialize hasAccess here**
    let hasAccess = req.user.role === 'admin'; 

    // Check if user is admin OR has access to this premonition
    if (!hasAccess) {
      // FIX: Build the LIKE pattern string first using a template literal (backticks)
      const likePattern = `%/api/premonitions/media/${id}%`;

      const [accessRows] = await pool.query(`
        SELECT 1 FROM premonitions p
        JOIN premonition_recipients pr ON p.id = pr.premonition_id
        WHERE p.content_url LIKE ? AND pr.user_id = ?
      `, [likePattern, req.user.id]); // FIX: Pass the correctly built string
      
      if (accessRows.length > 0) {
        hasAccess = true;
      }
    }

    if (!hasAccess) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    // User has access, fetch the media
    const [rows] = await pool.query('SELECT mime, size, data FROM premonition_media WHERE id=? LIMIT 1', [id]);
    if (!rows.length) {
      return res.status(404).send('Not found');
    }

    const { mime, size, data } = rows[0];
    res.setHeader('Content-Type', mime || 'application/octet-stream');
    res.setHeader('Content-Length', size);
    res.setHeader('Cache-Control', 'private, max-age=3600'); // 1 hour
    res.end(data); // send raw blob
  } catch (e) {
    log.err('Failed to stream media', { message: e.message });
    res.status(500).json({ error: 'Failed to stream media' });
  }
});


/* -------------------- Start Server -------------------- */
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => log.start(`API server started`, { port: PORT, env: process.env.NODE_ENV || 'stable' }));

// Add the global error handler middleware *last*
app.use(expressErrorHandler);
