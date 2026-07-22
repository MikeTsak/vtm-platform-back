module.exports = async function (fastify, opts) {
  const { authRequired } = opts;

  // PATCH /api/users/me/ui_sounds
  fastify.patch('/me/ui_sounds', { preHandler: [authRequired] }, async (req, reply) => {
    const { enabled } = req.body;
    await fastify.db.query('UPDATE users SET ui_sounds_enabled = ? WHERE id = ?', [enabled ? 1 : 0, req.user.id]);
    reply.send({ ok: true, ui_sounds_enabled: !!enabled });
  });

  // More user routes can be added here...
};
