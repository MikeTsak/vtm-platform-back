const { xpCost } = require('../utils/xpCost');
const { idempotencyCheck, idempotencySave } = require('../utils/idempotency');

// Self-serve XP spend: always operates on the caller's OWN character
// (`WHERE user_id = req.user.id`), so there's no :id param and no IDOR
// surface here — unlike /api/characters/user/:id, /inventory, /retainers.
// Extracted out of server.fastify.js so it can be mounted in isolation for
// integration tests (see tests/setup/testApp.js).
module.exports = async function (fastify, opts) {
  const { pool, log, authRequired } = opts;

  fastify.post('/api/characters/xp/spend', {
    preHandler: [authRequired, idempotencyCheck],
    onSend: [idempotencySave],
  }, async (req, reply) => {
    const {
      type, target, currentLevel, newLevel,
      ritualLevel, formulaLevel, dots,
      disciplineKind, patchSheet
    } = req.body;

    const [rows] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
    const ch = rows[0];
    if (!ch) {
      log.warn('XP spend without character', { user_id: req.user.id });
      return reply.status(400).json({ error: 'Create a character first' });
    }

    // Determine cost (special-case free power assignment)
    let cost = 0;
    try {
      if (
        type === 'discipline' &&
        (
          disciplineKind === 'select' ||                           // explicit "assignment only"
          Number(newLevel) === Number(currentLevel)                // or no level change
        )
      ) {
        cost = 0; // assigning a specific power for an existing dot is free
      } else {
        cost = xpCost({ type, newLevel, ritualLevel, formulaLevel, dots, disciplineKind });
      }
    } catch (e) {
      log.warn('XP spend bad type', { type });
      return reply.status(400).json({ error: e.message });
    }

    // If this is a paid action, verify balance and deduct XP
    if (cost > 0) {
      if ((ch.xp || 0) < cost) {
        log.warn('XP spend insufficient', { user_id: req.user.id, have: ch.xp, need: cost });
        return reply.status(400).json({ error: `Not enough XP (need ${cost}, have ${ch.xp})` });
      }
      log.xp('XP spend request', { user_id: req.user.id, type, target, currentLevel, newLevel, cost });
      await pool.query('UPDATE characters SET xp = xp - ? WHERE id=?', [cost, ch.id]);
    } else {
      log.xp('Discipline power assignment (free)', { user_id: req.user.id, target, level: newLevel });
    }

    // Apply optional sheet patch for both paid and free actions
    if (patchSheet !== undefined) {
      await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(patchSheet), ch.id]);
      log.xp('Sheet patched after action', { user_id: req.user.id, character_id: ch.id });
    }

    // XP log (store 0-cost entries too)
    try {
      await pool.query(
        'INSERT INTO xp_log (character_id, action, target, from_level, to_level, cost, payload) VALUES (?,?,?,?,?,?,?)',
        [ch.id, type, target || null, currentLevel || null, newLevel || null, cost,
        JSON.stringify({ disciplineKind, ritualLevel, formulaLevel, dots })]
      );
      log.xp('XP logged', { character_id: ch.id, cost });
    } catch (_) { /* ignore if xp_log missing */ }

    const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [ch.id]);
    const outCh = out[0];
    if (outCh && outCh.sheet && typeof outCh.sheet === 'string') { try { outCh.sheet = JSON.parse(outCh.sheet); } catch { } }

    if (cost > 0) {
      log.ok('XP spend complete', { user_id: req.user.id, remaining_xp: outCh?.xp });
    } else {
      log.ok('Power assignment saved (no XP charged)', { user_id: req.user.id });
    }

    reply.send({ character: outCh, spent: cost });
  });
};
