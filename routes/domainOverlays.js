// routes/domainOverlays.js
//
// Per-user access to the restricted map overlays (catacombs, necropoleis) and
// the admin grant directory.
const { DOMAIN_OVERLAY_KEYS, resolveOverlayAccess } = require('../services/domainOverlays');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired } = opts;

  fastify.get('/api/domain-overlays/me', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      reply.send(await resolveOverlayAccess(req.user.id, req.user.role));
    } catch (err) {
      log.err('GET /api/domain-overlays/me failed', { error: err.message });
      reply.status(500).send({ error: 'Database error resolving overlay access' });
    }
  });

  // Directory for the access-management modal. Any logged-in user can open it,
  // but a non-admin can only act on the overlays they themselves hold (they can
  // "spread" what they have). Shows the CHARACTER name, not the account name.
  fastify.get('/api/domain-overlays/directory', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const me = await resolveOverlayAccess(req.user.id, req.user.role);
      const grantable = me.admin ? DOMAIN_OVERLAY_KEYS : me.overlays;
      const [rows] = await pool.query(`
      SELECT u.id, u.email, u.display_name, u.role,
             ch.name AS character_name,
             ch.clan AS clan,
             g.granted,
             g.granted_by_me
      FROM users u
      LEFT JOIN (
        SELECT user_id, name, clan
        FROM (
          SELECT user_id, name, clan,
                 ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY id) as rn
          FROM characters
          WHERE COALESCE(is_deceased, 0) = 0 AND COALESCE(is_left, 0) = 0
        ) active_chars
        WHERE rn = 1
      ) ch ON ch.user_id = u.id
      LEFT JOIN (
        SELECT user_id,
               GROUP_CONCAT(overlay_key) AS granted,
               GROUP_CONCAT(CASE WHEN granted_by = ? THEN overlay_key END) AS granted_by_me
        FROM domain_overlay_grants
        GROUP BY user_id
      ) g ON g.user_id = u.id
      ORDER BY (character_name IS NULL), character_name, u.display_name, u.email
    `, [req.user.id]);
      const users = rows.map(r => {
        const granted = r.granted ? r.granted.split(',').filter(k => DOMAIN_OVERLAY_KEYS.includes(k)) : [];
        const grantedByMe = r.granted_by_me ? r.granted_by_me.split(',').filter(k => DOMAIN_OVERLAY_KEYS.includes(k)) : [];
        return {
          id: r.id,
          name: r.character_name || r.display_name || r.email,
          account: r.display_name || r.email,
          role: r.role,
          clan: r.clan || null,
          // a non-admin only sees grant status for overlays they can act on
          granted: me.admin ? granted : granted.filter(k => grantable.includes(k)),
          grantedByMe,
        };
      });
      reply.send({ me, keys: DOMAIN_OVERLAY_KEYS, grantable, users });
    } catch (err) {
      log.err('GET /api/domain-overlays/directory failed', { error: err.message });
      reply.status(500).send({ error: 'Database error loading overlay directory' });
    }
  });

  // Grant an overlay to another player. Admin can grant anything; anyone else
  // can only grant an overlay they themselves have (spreading access).
  fastify.post('/api/domain-overlays/grants', { preHandler: [authRequired] }, async (req, reply) => {
    const userId = Number(req.body?.user_id);
    const overlayKey = String(req.body?.overlay_key || '');
    if (!Number.isInteger(userId) || !DOMAIN_OVERLAY_KEYS.includes(overlayKey)) {
      return reply.status(400).send({ error: 'user_id (int) and a valid overlay_key are required' });
    }
    try {
      const me = await resolveOverlayAccess(req.user.id, req.user.role);
      if (!me.admin && !me.overlays.includes(overlayKey)) {
        return reply.status(403).send({ error: 'You can only share an overlay you have access to yourself' });
      }
      await pool.query(
        'INSERT IGNORE INTO domain_overlay_grants (user_id, overlay_key, granted_by) VALUES (?,?,?)',
        [userId, overlayKey, req.user.id],
      );
      log.dom('Domain overlay granted', { user_id: userId, overlay_key: overlayKey, by: req.user.id });
      reply.send({ ok: true });
    } catch (err) {
      log.err('POST /api/domain-overlays/grants failed', { error: err.message });
      reply.status(500).send({ error: 'Database error granting overlay' });
    }
  });

  // Revoke: admin can revoke anything; a non-admin can only revoke a grant they
  // personally made.
  fastify.delete('/api/domain-overlays/grants/:userId/:overlayKey', { preHandler: [authRequired] }, async (req, reply) => {
    const userId = Number(req.params.userId);
    const overlayKey = String(req.params.overlayKey || '');
    if (!Number.isInteger(userId) || !DOMAIN_OVERLAY_KEYS.includes(overlayKey)) {
      return reply.status(400).send({ error: 'bad parameters' });
    }
    try {
      if (req.user.role !== 'admin') {
        const [[row]] = await pool.query(
          'SELECT granted_by FROM domain_overlay_grants WHERE user_id=? AND overlay_key=?',
          [userId, overlayKey],
        );
        if (!row) return reply.send({ ok: true });
        if (row.granted_by !== req.user.id) {
          return reply.status(403).send({ error: 'Only an admin or whoever granted it can revoke this' });
        }
      }
      await pool.query('DELETE FROM domain_overlay_grants WHERE user_id=? AND overlay_key=?', [userId, overlayKey]);
      log.dom('Domain overlay revoked', { user_id: userId, overlay_key: overlayKey, by: req.user.id });
      reply.send({ ok: true });
    } catch (err) {
      log.err('DELETE /api/domain-overlays/grants failed', { error: err.message });
      reply.status(500).send({ error: 'Database error revoking overlay' });
    }
  });
};
