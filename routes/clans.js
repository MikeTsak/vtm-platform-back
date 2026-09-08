// routes/clans.js
//
// Which clans are open for character creation this chronicle.
const { getSetting, setSetting } = require('../utils/settings');
const { DEFAULT_DISABLED_CLANS, isValidClanName } = require('../utils/clans');

module.exports = async function (fastify, opts) {
  const { log, authRequired, requireAdmin } = opts;

  // ==========================================
  // --- CLAN AVAILABILITY ROUTES ---
  // ==========================================

  // Any authenticated user: which clans are currently unavailable at character creation
  fastify.get('/api/clans/config', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const raw = await getSetting('disabled_clans', JSON.stringify(DEFAULT_DISABLED_CLANS));
      let disabledClans;
      try { disabledClans = JSON.parse(raw); } catch { disabledClans = DEFAULT_DISABLED_CLANS; }
      reply.send({ disabledClans });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch clan config' });
    }
  });

  // Admin: set which clans are disabled for character creation
  fastify.post('/api/admin/clans/config', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { disabledClans } = req.body;
      if (!Array.isArray(disabledClans) || !disabledClans.every(c => typeof c === 'string' && isValidClanName(c))) {
        return reply.status(400).json({ error: 'disabledClans must be an array of valid clan names' });
      }

      await setSetting('disabled_clans', JSON.stringify(disabledClans));
      log.adm('Clan availability updated', { admin_id: req.user.id, disabledClans });

      reply.send({ ok: true, disabledClans });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to update clan config' });
    }
  });
};
