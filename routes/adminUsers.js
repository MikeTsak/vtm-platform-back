// routes/adminUsers.js
//
// User administration, plus the session-refresh endpoint that re-issues a
// cookie after an admin changes the caller's own role or display name.
const { setAuthCookie } = require('../utils/authCookie');
const { issueToken } = require('../services/token');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  /* -------------------- Admin views -------------------- */
  fastify.get('/api/admin/users', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    // We added u.discord_id to the SELECT list here
    const [rows] = await pool.query(
      `SELECT u.id, u.email, u.display_name, u.role, u.discord_id,
            (u.avatar_url IS NOT NULL OR u.avatar_url_thumb IS NOT NULL) AS has_avatar,
            c.id AS character_id, c.name AS char_name, c.clan, c.sheet, c.xp
     FROM users u
     LEFT JOIN characters c ON c.user_id=u.id
     ORDER BY u.created_at DESC`
    );

    rows.forEach(r => {
      if (r.sheet && typeof r.sheet === 'string') {
        try { r.sheet = JSON.parse(r.sheet); } catch { }
      }
    });

    log.adm('Admin users list', { count: rows.length });
    reply.send({ users: rows });
  });


  // Update a user (admin only)

  fastify.patch('/api/admin/users/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) {
        return reply.status(400).json({ error: 'Invalid user id' });
      }

      const { display_name, email, role, discord_id } = req.body || {};
      const fields = [];
      const vals = [];

      // 1. Handle Role
      const validRoles = new Set(['user', 'courtuser', 'admin']);
      let roleChanged = false;
      if (role !== undefined) {
        const r = String(role);
        if (!validRoles.has(r)) {
          return reply.status(400).json({ error: 'Invalid role' });
        }
        fields.push('role=?'); // FIXED: Ensure this is single =
        vals.push(r);
        roleChanged = true;
      }

      // 2. Handle Display Name
      let nameChanged = false;
      if (display_name !== undefined) {
        const name = String(display_name).trim();
        if (!name) return reply.status(400).json({ error: 'Display name cannot be empty' });
        fields.push('display_name=?');
        vals.push(name);
        nameChanged = true;
      }

      // 3. Handle Email
      let emailChanged = false;
      if (email !== undefined) {
        const normEmail = String(email).trim().toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normEmail)) {
          return reply.status(400).json({ error: 'Invalid email' });
        }
        // Check for duplicates
        const [dup] = await pool.query('SELECT id FROM users WHERE email=? AND id<>?', [normEmail, id]);
        if (dup.length) return reply.status(409).json({ error: 'Email already in use' });

        fields.push('email=?');
        vals.push(normEmail);
        emailChanged = true;
      }

      // 4. Handle Discord ID (New Logic)
      if (discord_id !== undefined) {
        const did = String(discord_id).trim();
        fields.push('discord_id=?');
        vals.push(did);
      }

      if (!fields.length) return reply.status(400).json({ error: 'Nothing to update' });

      // Perform Update
      vals.push(id);
      await pool.query(`UPDATE users SET ${fields.join(', ')} WHERE id=?`, vals);

      // Return updated row (Include discord_id in select)
      const [[row]] = await pool.query(
        `SELECT u.id, u.email, u.display_name, u.role, u.discord_id, u.token_version,
              c.id AS character_id, c.name AS char_name, c.clan, c.xp
       FROM users u
       LEFT JOIN characters c ON c.user_id = u.id
       WHERE u.id=?`,
        [id]
      );

      if (!row) return reply.status(404).json({ error: 'User not found after update' });

      // Refresh token if self-edit — the admin's existing cookie still carries
      // the OLD role/name/email claims, so re-mint it with the new ones.
      const selfEdit = id === req.user.id;
      if (selfEdit && (roleChanged || nameChanged || emailChanged)) {
        const freshToken = issueToken({
          id: row.id,
          email: row.email,
          display_name: row.display_name,
          role: row.role,
          token_version: row.token_version,
        });
        setAuthCookie(req, reply, freshToken);
        return reply.send({ user: row });
      }

      log.adm('Admin updated user', { admin_id: req.user.id, user_id: id, fields });
      reply.send({ user: row });

    } catch (e) {
      log.err('Admin update user failed', { message: e.message, stack: e.stack });
      reply.status(500).json({ error: 'Failed to update user' });
    }
  });

  // 2) Auth: refresh current user's token from DB (useful beyond admin flow)
  fastify.post('/api/auth/refresh', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [[u]] = await pool.query(
        'SELECT id, email, display_name, role, token_version FROM users WHERE id=?',
        [req.user.id]
      );
      if (!u) return reply.status(404).json({ error: 'User not found' });
      const token = issueToken(u);
      setAuthCookie(req, reply, token);
      reply.send({ user: u });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to refresh token' });
    }
  });
};
