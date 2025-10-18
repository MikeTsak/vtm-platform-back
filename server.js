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

// --- Setup ---

// Install global handlers to catch crashes and unhandled promise rejections
installProcessHandlers();

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.set('trust proxy', true);

// Add the request logger middleware. It will log every incoming request and its response.
// Place it right after express.json() to ensure it can log request bodies.
app.use(attachRequestLogger());

/* ------------------ Start server Mail ------------------ */
async function sendResetEmailWithEmailJS({ to, name, link, appName='Erebus Portal' }) {
  // (Your existing function)
  const payload = {
    service_id: process.env.EMAILJS_SERVICE_ID,
    template_id: process.env.EMAILJS_TEMPLATE_ID,
    user_id: process.env.EMAILJS_PUBLIC_KEY,
    accessToken: process.env.EMAILJS_PRIVATE_KEY || undefined,
    template_params: {
      to_email: to,
      to_name: name || 'there',
      app_name: appName,
      reset_link: link,
      expires_minutes: 30
    }
  };
  await axios.post('https://api.emailjs.com/api/v1.0/email/send', payload, {
    timeout: 20000,
    headers: { 'Content-Type': 'application/json' },
  });
}


/* -------------------- Helpers -------------------- */
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

app.post('/api/auth/forgot', async (req, res) => {
    // (Your existing route)
    const { email } = req.body || {};
    const norm = (email || '').trim().toLowerCase();
    const okResponse = () => res.json({ ok: true, message: 'If the email exists, a reset link has been sent.' });
    try {
        const [rows] = await pool.query('SELECT id, display_name FROM users WHERE email=?', [norm]);
        const user = rows[0];
        if (!user) return okResponse();
        const [recent] = await pool.query('SELECT id FROM password_resets WHERE user_id=? AND created_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE) AND used_at IS NULL', [user.id]);
        if (recent.length) return okResponse();
        const tokenId = crypto.randomUUID();
        const secret = crypto.randomBytes(32).toString('hex');
        const combined = `${tokenId}.${secret}`;
        const secretHash = await bcrypt.hash(secret, 12);
        const expires = new Date(Date.now() + 30 * 60 * 1000);
        await pool.query('INSERT INTO password_resets (user_id, token_id, secret_hash, expires_at) VALUES (?,?,?,?)', [user.id, tokenId, secretHash, expires]);
        const appBase = (process.env.APP_BASE_URL || req.headers.origin || '').replace(/\/$/, '') || 'http://localhost:3000';
        const link = `${appBase}/reset?token=${encodeURIComponent(combined)}`;
        try {
            await sendResetEmailWithEmailJS({ to: norm, name: user.display_name, link, appName: process.env.APP_NAME || 'Erebus Portal' });
        } catch (sendErr) {
            log.err('EmailJS send failed', { error: sendErr?.response?.data || sendErr?.message });
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

/* -------------------- Chat -------------------- */
// NOTE TO USER: You may need to add 'chat' to your logger configuration if it's a custom one.
// Get list of users to chat with (all except me)
app.get('/api/chat/users', authRequired, async (req, res) => {
  try {
    const [users] = await pool.query(
      // FIX: Added 'c.clan' to the SELECT statement
      `SELECT u.id, u.display_name, c.name as char_name, c.clan
       FROM users u
       LEFT JOIN characters c ON u.id = c.user_id
       WHERE u.id != ?
       ORDER BY u.display_name ASC`,
      [req.user.id]
    );
    res.json({ users });
  } catch (e) {
    log.err('Failed to get chat users', { message: e.message });
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
  const allowed = ['submitted', 'approved', 'rejected', 'resolved'];
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

app.use(expressErrorHandler());

/* -------------------- Start Server -------------------- */
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => log.start(`API server started`, { port: PORT, env: process.env.NODE_ENV || 'stable' }));

