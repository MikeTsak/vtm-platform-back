module.exports = async function (fastify, opts) {
  const { authRequired } = opts;

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
      'SELECT id, display_name, email FROM users WHERE email LIKE ? OR display_name LIKE ? LIMIT 10',
      [searchStr, searchStr]
    );
    reply.send({ users: rows });
  });

  // More user routes can be added here...
};
