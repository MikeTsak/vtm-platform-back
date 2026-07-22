const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const axios = require('axios');
const jwt = require('jsonwebtoken');

module.exports = async function (fastify, opts) {
  const { pool, log, maskEmail, authRequired, authLimiter, broadcastNtfyAlert, sendResetEmailWithEmailJS } = opts;

  const issueToken = (user) =>
    jwt.sign(
      { id: user.id, email: user.email, role: user.role, display_name: user.display_name },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

  // POST /api/auth/register
  fastify.post('/register', { 
    preHandler: [authLimiter],
    schema: {
      body: {
        type: 'object',
        required: ['email', 'display_name', 'password', 'recaptchaToken'],
        properties: {
          email: { type: 'string', format: 'email' },
          display_name: { type: 'string', minLength: 2, maxLength: 190 },
          password: { type: 'string', minLength: 8 },
          recaptchaToken: { type: 'string' }
        }
      }
    }
  }, async (req, reply) => {
    const { email, display_name, password, recaptchaToken } = req.body;

    // Verify reCAPTCHA
    const secretKey = process.env.RECAPTCHA_SITE_SECRET;
    if (secretKey) {
      const verifyRes = await axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaToken}`);
      if (!verifyRes.data.success || verifyRes.data.score < 0.5) {
        log.warn('Register invalid captcha or low score', { email, score: verifyRes.data.score });
        return reply.status(400).send({ error: 'Captcha validation failed. Are you a bot?' });
      }
    }

    const [exists] = await fastify.db.query('SELECT id FROM users WHERE email=?', [email]);
    if (exists.length) {
      log.warn('Register email in use', { email });
      return reply.status(409).send({ error: 'Email already in use' });
    }
    const hash = await bcrypt.hash(password, 12);
    const [r] = await fastify.db.query('INSERT INTO users (email, display_name, password_hash) VALUES (?,?,?)', [email, display_name, hash]);
    log.auth('User registered', { id: r.insertId, email });
    if (typeof broadcastNtfyAlert === 'function') {
      broadcastNtfyAlert(`**${display_name}** has just joined the platform.\nEmail: \`${email}\``, { title: 'New Registration', tags: 'bust_in_silhouette', priority: 'default' });
    }
    const [rows] = await fastify.db.query('SELECT id, email, display_name, role FROM users WHERE id=?', [r.insertId]);
    reply.send({ token: issueToken(rows[0]) });
  });

  // POST /api/auth/login
  fastify.post('/login', { 
    preHandler: [authLimiter],
    schema: {
      body: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string' }
        }
      }
    }
  }, async (req, reply) => {
    const ip = req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] || (req.headers['x-forwarded-for'] || '').split(',')[0]?.trim() || req.ip || req.socket?.remoteAddress || 'unknown';
    const ua = req.headers['user-agent'] || 'unknown';

    const { email, password } = req.body;

    const [rows] = await fastify.db.query('SELECT * FROM users WHERE email=?', [email]);
    const user = rows[0];

    if (!user) {
      log.warn('Login invalid email', { email, ip, ua, req_id: req.id });
      return reply.status(401).send({ error: 'Invalid credentials', req_id: req.id });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      log.warn('Login wrong password', { email, ip, ua, req_id: req.id });
      return reply.status(401).send({ error: 'Invalid credentials', req_id: req.id });
    }

    log.auth('User logged in', { user_id: user.id, email, ip, ua, req_id: req.id });
    reply.send({ token: issueToken(user) });
  });

  // GET /api/auth/me
  fastify.get('/me', { preHandler: [authRequired] }, async (req, reply) => {
    const [rows] = await fastify.db.query('SELECT ui_sounds_enabled FROM users WHERE id = ?', [req.user.id]);
    const ui_sounds_enabled = rows.length > 0 ? !!rows[0].ui_sounds_enabled : true;
    log.auth('Auth me', { id: req.user.id, email: req.user.email, role: req.user.role });
    reply.send({ user: { ...req.user, ui_sounds_enabled } });
  });

  // POST /api/auth/forgot
  fastify.post('/forgot', async (req, reply) => {
    const { email } = req.body || {};
    const norm = (email || '').trim().toLowerCase();
    const okResponse = () => reply.send({ ok: true, message: 'If the email exists, a reset link has been sent.' });

    const COOLDOWN_MIN = Number(process.env.RESET_COOLDOWN_MIN ?? 10);
    const IS_PROD = (process.env.NODE_ENV || '').toLowerCase() === 'production';

    const wantResend = (req.query?.resend === '1') || (req.headers['x-reset-resend'] === '1');
    const forceResend = wantResend && !IS_PROD;

    if (!norm) {
      log.warn('Forgot: missing email');
      return okResponse();
    }

    const [rows] = await fastify.db.query('SELECT id, display_name FROM users WHERE email = ? LIMIT 1', [norm]);
    const user = rows[0];
    if (!user) {
      if (log.mail) log.mail('Forgot: email not found (OK sent)', { email: maskEmail(norm) });
      return okResponse();
    }

    const [recentRows] = await fastify.db.query('SELECT id, created_at FROM password_resets WHERE user_id=? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1', [user.id]);
    if (recentRows.length) {
      const last = recentRows[0];
      const lastTs = new Date(last.created_at).getTime();
      const sinceMs = Date.now() - lastTs;
      const sinceMin = Math.floor(sinceMs / 60000);
      const remain = Math.max(0, COOLDOWN_MIN - sinceMin);

      if (remain > 0 && !forceResend) {
        if (log.mail) log.mail('Forgot: recent reset exists (cooldown active, OK sent)', {
          email: maskEmail(norm), cooldown_min: COOLDOWN_MIN, since_min: sinceMin, remaining_min: remain, note: 'use ?resend=1 in DEV to bypass',
        });
        return okResponse();
      }
    }

    const tokenId = crypto.randomUUID();
    const secret = crypto.randomBytes(32).toString('hex');
    const combined = `${tokenId}.${secret}`;
    const secretHash = await bcrypt.hash(secret, 12);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h expiry

    await fastify.db.query('INSERT INTO password_resets (user_id, token_id, secret_hash, expires_at) VALUES (?,?,?,?)', [user.id, tokenId, secretHash, expiresAt]);

    const appBase = (process.env.APP_BASE_URL || req.headers.origin || '').replace(/\/$/, '') || 'http://localhost:3000';
    const link = `${appBase}/reset?token=${encodeURIComponent(combined)}`;

    if (log.mail) log.mail('Reset token created', { email: maskEmail(norm), link_path: new URL(link).pathname, expires_min: 30, cooldown_min: COOLDOWN_MIN });

    try {
      if (typeof sendResetEmailWithEmailJS === 'function') {
        await sendResetEmailWithEmailJS({ to: norm, name: user.display_name || 'there', link, appName: process.env.APP_NAME || 'Erebus Portal' });
      }
    } catch (e) {
      log.err('EmailJS send failed', { error: e?.message || String(e) });
    }

    return okResponse();
  });

  // POST /api/auth/reset
  fastify.post('/reset', { preHandler: [authLimiter] }, async (req, reply) => {
    const { token, password } = req.body || {};
    if (typeof token !== 'string' || typeof password !== 'string' || password.length < 8) {
      return reply.status(400).send({ error: 'Bad request (password must be at least 8 chars).' });
    }
    const parts = token.split('.');
    if (parts.length !== 2) return reply.status(400).send({ error: 'Invalid token' });
    const [tokenId, secret] = parts;
    
    const [rows] = await fastify.db.query('SELECT * FROM password_resets WHERE token_id=? AND used_at IS NULL AND expires_at > NOW()', [tokenId]);
    const row = rows[0];
    if (!row) return reply.status(400).send({ error: 'Invalid or expired token' });
    const ok = await bcrypt.compare(secret, row.secret_hash);
    if (!ok) return reply.status(400).send({ error: 'Invalid or expired token' });
    const hash = await bcrypt.hash(password, 12);
    await fastify.db.query('UPDATE users SET password_hash=? WHERE id=?', [hash, row.user_id]);
    await fastify.db.query('UPDATE password_resets SET used_at=NOW() WHERE id=?', [row.id]);
    await fastify.db.query('UPDATE password_resets SET used_at=NOW() WHERE user_id=? AND used_at IS NULL', [row.user_id]);
    log.auth('Password reset complete', { user_id: row.user_id });
    return reply.send({ ok: true });
  });

  // PUT /api/auth/theme
  fastify.put('/theme', { preHandler: [authRequired] }, async (req, reply) => {
    const { theme } = req.body;
    if (!theme) return reply.status(400).send({ error: 'Theme is required' });

    await fastify.db.query('UPDATE users SET theme = ? WHERE id = ?', [theme, req.user.id]);
    reply.send({ success: true, theme });
  });
};
