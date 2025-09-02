// server.js (with emoji logs)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db'); // export pool.promise() from db.js
const { authRequired, requireAdmin } = require('./authMiddleware');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));

/* -------------------- Logger helpers -------------------- */
const log = {
  start: (msg, extra) => console.log(`🚀 ${msg}`, extra ?? ''),
  auth: (msg, extra) => console.log(`🔐 ${msg}`, extra ?? ''),
  char: (msg, extra) => console.log(`🧛 ${msg}`, extra ?? ''),
  xp:   (msg, extra) => console.log(`✨ ${msg}`, extra ?? ''),
  dt:   (msg, extra) => console.log(`🕰️ ${msg}`, extra ?? ''),
  dom:  (msg, extra) => console.log(`🏰 ${msg}`, extra ?? ''),
  adm:  (msg, extra) => console.log(`🛡️ ${msg}`, extra ?? ''),
  ok:   (msg, extra) => console.log(`✅ ${msg}`, extra ?? ''),
  warn: (msg, extra) => console.warn(`⚠️ ${msg}`, extra ?? ''),
  err:  (msg, extra) => console.error(`💥 ${msg}`, extra ?? '')
};

/* -------------------- Helpers -------------------- */
const issueToken = (user) =>
  jwt.sign(
    { id: user.id, email: user.email, role: user.role, display_name: user.display_name },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

function startOfMonth(d = new Date()) {
  return new Date(d.getFullYear(), d.getMonth(), 1);
}
function endOfMonth(d = new Date()) {
  return new Date(d.getFullYear(), d.getMonth() + 1, 1);
}

function feedingFromPredator(pred) {
  const map = {
    Alleycat: 'Violent Hunt',
    Sandman: 'Sleeping Prey',
    Siren: 'Seduction',
    Osiris: 'Cult Feeding',
    Farmer: 'Animal/Bagged',
    Bagger: 'Bagged Blood',
    'Scene Queen': 'Scene Influence',
    Consensualist: 'Consent Feeding',
    Extortionist: 'Blackmail Feeding',
    'Blood Leech': 'Vitae Theft',
  };
  return map[pred] || 'Standard Feeding';
}

// XP cost rules
function xpCost({ type, newLevel, ritualLevel, formulaLevel, dots = 1, disciplineKind }) {
  if (type === 'attribute') return newLevel * 5;
  if (type === 'skill') return newLevel * 3;
  if (type === 'specialty') return 3;
  if (type === 'discipline') {
    if (disciplineKind === 'clan') return newLevel * 5;
    if (disciplineKind === 'caitiff') return newLevel * 6;
    return newLevel * 7; // other/predator type
  }
  if (type === 'ritual') return (ritualLevel || 1) * 3;
  if (type === 'thin_blood_formula') return (formulaLevel || 1) * 3;
  if (type === 'advantage') return 3 * (dots || 1);
  if (type === 'blood_potency') return newLevel * 10;
  throw new Error('Unknown XP type');
}

/* -------------------- Auth -------------------- */
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
    const [r] = await pool.query(
      'INSERT INTO users (email, display_name, password_hash) VALUES (?,?,?)',
      [email, display_name, hash]
    );

    log.auth('User registered', { id: r.insertId, email });

    const [rows] = await pool.query('SELECT id, email, display_name, role FROM users WHERE id=?', [r.insertId]);
    res.json({ token: issueToken(rows[0]) });
  } catch (e) {
    log.err('Register failed', e);
    res.status(500).json({ error: 'Register failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM users WHERE email=?', [email]);
    const user = rows[0];
    if (!user) {
      log.warn('Login invalid email', { email });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      log.warn('Login wrong password', { email });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    log.auth('User logged in', { id: user.id, email });
    res.json({ token: issueToken(user) });
  } catch (e) {
    log.err('Login failed', e);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', authRequired, async (req, res) => {
  log.auth('Auth me', { id: req.user.id, email: req.user.email, role: req.user.role });
  res.json({ user: req.user });
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

/* -------------------- Start -------------------- */
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => log.start(`API on http://localhost:${PORT}`));
