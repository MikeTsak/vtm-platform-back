// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const { authRequired, requireAdmin } = require('./authMiddleware');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

/* ---------- Helpers ---------- */
const issueToken = (user) =>
  jwt.sign(
    { id: user.id, email: user.email, role: user.role, display_name: user.display_name },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

/* ---------- Auth ---------- */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, display_name, password } = req.body;
    if (!email || !display_name || !password) return res.status(400).json({ error: 'Missing fields' });
    const [exists] = await pool.query('SELECT id FROM users WHERE email=?', [email]);
    if (exists.length) return res.status(409).json({ error: 'Email already in use' });
    const hash = await bcrypt.hash(password, 12);
    const [r] = await pool.query(
      'INSERT INTO users (email, display_name, password_hash) VALUES (?,?,?)',
      [email, display_name, hash]
    );
    const [rows] = await pool.query('SELECT id, email, display_name, role FROM users WHERE id=?', [r.insertId]);
    return res.json({ token: issueToken(rows[0]) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Register failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM users WHERE email=?', [email]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ token: issueToken(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', authRequired, async (req, res) => {
  res.json({ user: req.user });
});

/* ---------- Characters ---------- */
// Get or create prompt state
app.get('/api/characters/me', authRequired, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
  res.json({ character: rows[0] || null });
});

app.post('/api/characters', authRequired, async (req, res) => {
  const { name, clan } = req.body;
  if (!name || !clan) return res.status(400).json({ error: 'Name and clan are required' });
  try {
    const [exists] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
    if (exists.length) return res.status(409).json({ error: 'Character already exists' });
    const [r] = await pool.query(
      'INSERT INTO characters (user_id, name, clan) VALUES (?,?,?)',
      [req.user.id, name, clan]
    );
    const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [r.insertId]);
    res.json({ character: rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to create character' });
  }
});

/* ---------- Downtimes ---------- */
app.get('/api/downtimes/mine', authRequired, async (req, res) => {
  const [[char]] = await Promise.all([
    pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]),
  ]);
  if (!char?.[0]) return res.json({ downtimes: [] });
  const [rows] = await pool.query('SELECT * FROM downtimes WHERE character_id=? ORDER BY created_at DESC', [char[0].id]);
  res.json({ downtimes: rows });
});

app.post('/api/downtimes', authRequired, async (req, res) => {
  const { title, body } = req.body;
  if (!title || !body) return res.status(400).json({ error: 'Title and body required' });
  const [chars] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
  const ch = chars[0];
  if (!ch) return res.status(400).json({ error: 'Create a character first' });
  const [r] = await pool.query(
    'INSERT INTO downtimes (character_id, title, body) VALUES (?,?,?)',
    [ch.id, title, body]
  );
  const [rows] = await pool.query('SELECT * FROM downtimes WHERE id=?', [r.insertId]);
  res.json({ downtime: rows[0] });
});

/* ---------- Admin ---------- */
app.get('/api/admin/users', authRequired, requireAdmin, async (_req, res) => {
  const [rows] = await pool.query(
    `SELECT u.id, u.email, u.display_name, u.role, c.name AS char_name, c.clan
     FROM users u
     LEFT JOIN characters c ON c.user_id=u.id
     ORDER BY u.created_at DESC`
  );
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
  res.json({ downtimes: rows });
});

app.patch('/api/admin/downtimes/:id', authRequired, requireAdmin, async (req, res) => {
  const { status, gm_notes } = req.body;
  const allowed = ['submitted','approved','rejected','resolved'];
  if (status && !allowed.includes(status)) return res.status(400).json({ error: 'Bad status' });
  const fields = [];
  const vals = [];
  if (status) { fields.push('status=?'); vals.push(status); }
  if (typeof gm_notes === 'string') { fields.push('gm_notes=?'); vals.push(gm_notes); }
  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });
  vals.push(req.params.id);
  await pool.query(`UPDATE downtimes SET ${fields.join(', ')} WHERE id=?`, vals);
  const [rows] = await pool.query('SELECT * FROM downtimes WHERE id=?', [req.params.id]);
  res.json({ downtime: rows[0] });
});

app.listen(process.env.PORT, () =>
  console.log(`API on http://localhost:${process.env.PORT}`)
);
