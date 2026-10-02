// routes/debugLogin.js
//
// Admin debug login ("log in as a player" to reproduce a bug they report).
//
// 1. An admin generates a code for one specific player:
//      POST /api/admin/users/:id/debug-login-code   -> { code, email, expires_in_minutes }
// 2. Anyone holding that code AND the player's email can redeem it once,
//    within 15 minutes (usually the same admin, often in a private window or
//    on a phone, so their own admin session stays untouched):
//      POST /api/auth/debug-login { email, code }   -> session cookie as the player
//
// The resulting session is a normal player JWT plus an `imp` claim (the
// generating admin's id) and a 2h lifetime. Every route therefore sees the
// player exactly as the player does. It never touches the player's password,
// their token_version, or their other sessions — the player keeps logging in
// normally and never needs (or sees) the code. Places that must behave
// differently for such a session check `req.user.imp`:
//   - /api/auth/refresh and /logout-all (adminUsers.js / auth.js)
//   - push subscription endpoints (push.js) — would bind the admin's device to the player
//   - activity heartbeat + socket presence — the player must not appear online
//
// Admin accounts can't be targeted: an admin-role debug session could mint
// further codes, and an admin has nothing to debug through another admin.

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { setAuthCookie } = require('../utils/authCookie');

const CODE_TTL_MINUTES = 15;
const SESSION_SECONDS = 2 * 60 * 60;
// No 0/O/1/I/L: the code is read off a screen and typed by hand.
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const CODE_LENGTH = 12; // 31^12 ≈ 2^59 — brute force is not a concern in a 15 min window

const hashCode = (code) => crypto.createHash('sha256').update(code).digest('hex');
const normalizeCode = (code) => String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

function generateCode() {
  let out = '';
  for (let i = 0; i < CODE_LENGTH; i++) out += ALPHABET[crypto.randomInt(ALPHABET.length)];
  return out;
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, authLimiter } = opts;

  fastify.post('/api/admin/users/:id/debug-login-code', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    if (req.user.imp) return reply.status(403).send({ error: 'Not available in a debug session' });
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return reply.status(400).send({ error: 'Invalid user id' });

    const [[target]] = await pool.query('SELECT id, email, role FROM users WHERE id = ?', [id]);
    if (!target) return reply.status(404).send({ error: 'User not found' });
    if (target.role === 'admin') return reply.status(400).send({ error: 'Admin accounts cannot be debug-logged into' });

    const code = generateCode();
    // One live code per player: a fresh one replaces any unused predecessor.
    await pool.query('DELETE FROM debug_login_codes WHERE user_id = ? AND used_at IS NULL', [id]);
    await pool.query(
      `INSERT INTO debug_login_codes (user_id, created_by, code_hash, expires_at)
       VALUES (?, ?, ?, NOW() + INTERVAL ${CODE_TTL_MINUTES} MINUTE)`,
      [id, req.user.id, hashCode(code)]
    );

    log.auth('Debug login code generated', { admin_id: req.user.id, user_id: id });
    reply.send({
      code: code.match(/.{4}/g).join('-'),
      email: target.email,
      expires_in_minutes: CODE_TTL_MINUTES,
    });
  });

  fastify.post('/api/auth/debug-login', {
    preHandler: [authLimiter],
    schema: {
      body: {
        type: 'object',
        required: ['email', 'code'],
        properties: { email: { type: 'string' }, code: { type: 'string', maxLength: 64 } },
      },
    },
  }, async (req, reply) => {
    const ip = req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] || req.ip || 'unknown';
    const email = String(req.body.email).trim(); // users.email is utf8mb4_general_ci: case-insensitive match
    const code = normalizeCode(req.body.code);
    const fail = () => reply.status(401).send({ error: 'Invalid or expired code' });
    if (code.length !== CODE_LENGTH) return fail();

    // The generating admin must still be an admin at redemption time.
    const [[row]] = await pool.query(
      `SELECT c.id, c.created_by, u.id AS user_id, u.email, u.role, u.display_name, u.token_version
         FROM debug_login_codes c
         JOIN users u ON u.id = c.user_id
         JOIN users a ON a.id = c.created_by AND a.role = 'admin'
        WHERE c.code_hash = ? AND u.email = ? AND c.used_at IS NULL AND c.expires_at > NOW()`,
      [hashCode(code), email]
    );
    if (!row || row.role === 'admin') {
      log.warn('Debug login rejected', { ip });
      return fail();
    }

    // Single use, race-safe: only one request can flip used_at.
    const [upd] = await pool.query(
      'UPDATE debug_login_codes SET used_at = NOW(), used_ip = ? WHERE id = ? AND used_at IS NULL',
      [String(ip).slice(0, 64), row.id]
    );
    if (upd.affectedRows !== 1) return fail();

    const token = jwt.sign(
      {
        id: row.user_id, email: row.email, role: row.role, display_name: row.display_name,
        tv: row.token_version || 0, imp: row.created_by,
      },
      process.env.JWT_SECRET,
      { expiresIn: SESSION_SECONDS }
    );
    setAuthCookie(req, reply, token, SESSION_SECONDS);
    log.auth('Debug login used', { admin_id: row.created_by, user_id: row.user_id, ip });
    reply.send({ ok: true });
  });
};
