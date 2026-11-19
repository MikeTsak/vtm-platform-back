module.exports = async function (fastify, opts) {
  const { authRequired, moderateLimiter } = opts;
  const exportPreHandler = moderateLimiter ? [authRequired, moderateLimiter] : [authRequired];

  // GET /api/users/me/export - GDPR self-serve personal data export (JSON)
  fastify.get('/me/export', { preHandler: exportPreHandler }, async (req, reply) => {
    const uid = req.user.id;
    const [[user]] = await fastify.db.query(
      'SELECT id, email, display_name, role, theme, ui_sounds_enabled, created_at FROM users WHERE id = ?',
      [uid]
    );
    if (!user) return reply.status(404).send({ error: 'User not found' });

    const [characters] = await fastify.db.query(
      'SELECT id, name, clan, xp, sheet, created_at, retired_at FROM characters WHERE user_id = ? OR retired_user_id = ?',
      [uid, uid]
    );
    const [downtimes] = await fastify.db.query(
      `SELECT d.id, d.character_id, d.title, d.feeding_type, d.body, d.status, d.gm_resolution, d.resolved_at, d.created_at
         FROM downtimes d
         JOIN characters c ON c.id = d.character_id
        WHERE c.user_id = ? OR c.retired_user_id = ?
        ORDER BY d.created_at DESC`,
      [uid, uid]
    );
    const [premonitions] = await fastify.db.query(
      `SELECT p.id, p.content_type, p.content_text, p.created_at, pr.viewed_at
         FROM premonitions p
         JOIN premonition_recipients pr ON pr.premonition_id = p.id
        WHERE pr.user_id = ?
        ORDER BY p.created_at DESC`,
      [uid]
    );

    const payload = {
      exported_at: new Date().toISOString(),
      user,
      characters,
      downtimes,
      premonitions_received: premonitions,
    };

    reply
      .header('Content-Type', 'application/json; charset=utf-8')
      .header('Content-Disposition', 'attachment; filename="erebus-portal-data.json"')
      .header('Cache-Control', 'no-store')
      .send(JSON.stringify(payload, null, 2));
  });

  // PATCH /api/users/me/ui_sounds
  fastify.patch('/me/ui_sounds', { preHandler: [authRequired] }, async (req, reply) => {
    const { enabled } = req.body;
    await fastify.db.query('UPDATE users SET ui_sounds_enabled = ? WHERE id = ?', [enabled ? 1 : 0, req.user.id]);
    reply.send({ ok: true, ui_sounds_enabled: !!enabled });
  });

  // GET /api/users/search?q=query
  fastify.get('/search', { preHandler: [authRequired] }, async (req, reply) => {
    const { q } = req.query;
    if (!q || q.length < 2) return reply.send({ users: [] });
    
    const searchStr = `%${q}%`;
    const [rows] = await fastify.db.query(
      'SELECT id, display_name, email FROM users WHERE (email LIKE ? OR display_name LIKE ?) AND archived_character_id IS NULL LIMIT 10',
      [searchStr, searchStr]
    );
    reply.send({ users: rows });
  });

  // More user routes can be added here...
};
