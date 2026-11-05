// routes/adminStats.js
//
// GET /api/admin/stats?from=YYYY-MM-DD&to=YYYY-MM-DD — the admin Stats page
// (services/adminStats.js builds every card). Admin only.
const { buildStats } = require('../services/adminStats');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  fastify.get('/api/admin/stats', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      return reply.send(await buildStats(pool, req.query || {}));
    } catch (e) {
      log.err('Admin stats failed', { message: e.message, stack: e.stack });
      return reply.status(500).send({ error: 'Failed to build the stats' });
    }
  });
};
