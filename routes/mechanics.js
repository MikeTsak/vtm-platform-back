// routes/mechanics.js
//
// Server-authoritative V5 mechanics — rouse checks, willpower spends, damage.
// These must stay server-side: the client is not trusted to apply them.

module.exports = async function (fastify, opts) {
  const { pool, authRequired } = opts;

  /* -------------------- Secure Mechanic Endpoints -------------------- */
  fastify.post('/api/characters/:id/rouse', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const charId = req.params.id;
      const { advantage } = req.body;

      // Simple permission check: must own character or be admin
      const [rows] = await pool.query('SELECT user_id, sheet FROM characters WHERE id=?', [charId]);
      if (!rows.length) return reply.status(404).json({ error: 'Not found' });
      if (Number(rows[0].user_id) !== Number(req.user.id) && req.user.role !== 'admin') {
        return reply.status(403).json({ error: 'Forbidden' });
      }

      let sheet = rows[0].sheet;
      if (typeof sheet === 'string') {
        try {
          sheet = JSON.parse(sheet || '{}');
        } catch (e) {
          return reply.status(500).json({ error: 'Failed to parse existing character sheet data.' });
        }
      }
      if (!sheet) sheet = {};
      const currentHunger = Number(sheet.hunger) || 0;

      const die1 = Math.floor(Math.random() * 10) + 1;
      let die2 = null;
      let success = die1 >= 6;

      if (advantage) {
        die2 = Math.floor(Math.random() * 10) + 1;
        if (die2 >= 6) success = true;
      }

      let nextHunger = currentHunger;
      if (!success) {
        nextHunger = Math.min(5, currentHunger + 1);
        sheet.hunger = nextHunger;
        await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), charId]);
      }

      reply.send({
        success,
        die1,
        die2,
        nextHunger,
        sheet
      });
    } catch (e) {
      reply.status(500).json({ error: 'Rouse check failed' });
    }
  });

  fastify.post('/api/characters/:id/spend-wp', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const charId = req.params.id;

      const [rows] = await pool.query('SELECT user_id, sheet FROM characters WHERE id=?', [charId]);
      if (!rows.length) return reply.status(404).json({ error: 'Not found' });
      if (rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
        return reply.status(403).json({ error: 'Forbidden' });
      }

      let sheet = rows[0].sheet;
      if (typeof sheet === 'string') {
        try {
          sheet = JSON.parse(sheet || '{}');
        } catch (e) {
          return reply.status(500).json({ error: 'Failed to parse existing character sheet data.' });
        }
      }
      if (!sheet) sheet = {};
      if (!sheet.willpower) sheet.willpower = { superficial: 0, aggravated: 0 };

      const comp = Number(sheet.attributes?.Composure) || 1;
      const reso = Number(sheet.attributes?.Resolve) || 1;
      const max = comp + reso;
      const currentWp = (Number(sheet.willpower.superficial) || 0) + (Number(sheet.willpower.aggravated) || 0);

      if (currentWp >= max) {
        return reply.status(400).json({ error: 'Not enough Willpower' });
      }

      sheet.willpower.superficial = (Number(sheet.willpower.superficial) || 0) + 1;
      await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), charId]);

      reply.send({ ok: true, sheet });
    } catch (e) {
      reply.status(500).json({ error: 'WP spend failed' });
    }
  });

  fastify.post('/api/characters/:id/apply-damage', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const charId = req.params.id;
      const { amount, type } = req.body;

      const [rows] = await pool.query('SELECT user_id, sheet FROM characters WHERE id=?', [charId]);
      if (!rows.length) return reply.status(404).json({ error: 'Not found' });
      if (rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
        return reply.status(403).json({ error: 'Forbidden' });
      }

      let sheet = JSON.parse(rows[0].sheet || '{}');
      if (!sheet.health) sheet.health = { superficial: 0, aggravated: 0 };

      // Halve superficial damage if the character is a vampire (assuming it is)
      // We will just do it automatically. If it's aggravated, don't halve it.
      let appliedAmount = Number(amount) || 0;
      if (type === 'superficial') {
        appliedAmount = Math.ceil(appliedAmount / 2);
        sheet.health.superficial = (sheet.health.superficial || 0) + appliedAmount;
      } else {
        sheet.health.aggravated = (sheet.health.aggravated || 0) + appliedAmount;
      }

      await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), charId]);

      reply.send({ ok: true, sheet, appliedAmount });
    } catch (e) {
      reply.status(500).json({ error: 'Apply damage failed' });
    }
  });
};
