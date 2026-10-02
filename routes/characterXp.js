const { idempotencyCheck, idempotencySave } = require('../utils/idempotency');
const { runPurchase, PurchaseError } = require('../utils/xpPurchase');

// Self-serve XP spend: always operates on the caller's OWN character
// (`WHERE user_id = req.user.id`), so there's no :id param and no IDOR
// surface here — unlike /api/characters/user/:id, /inventory, /retainers.
// Extracted out of server.fastify.js so it can be mounted in isolation for
// integration tests (see tests/setup/testApp.js).
//
// The server decides the level, price and sheet change (utils/xpPurchase.js);
// the request only names what to buy.
module.exports = async function (fastify, opts) {
  const { pool, log, authRequired } = opts;

  fastify.post('/api/characters/xp/spend', {
    preHandler: [authRequired, idempotencyCheck],
    onSend: [idempotencySave],
  }, async (req, reply) => {
    const [[ch]] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
    if (!ch) {
      log.warn('XP spend without character', { user_id: req.user.id });
      return reply.status(400).send({ error: 'Create a character first' });
    }

    // Out-of-clan disciplines are only purchasable up to the level an ST has
    // unlocked for this character (see routes/disciplineAccess.js).
    const unlockedTo = async (discipline) => {
      const [[access]] = await pool.query(
        'SELECT max_level FROM discipline_access WHERE character_id=? AND discipline=?',
        [ch.id, discipline]
      );
      return access ? Number(access.max_level) : null;
    };

    try {
      const { row, cost } = await runPurchase({ pool, table: 'characters', id: ch.id, body: req.body || {}, isAdmin: false, unlockedTo });
      log.xp('XP spend complete', { user_id: req.user.id, type: req.body?.type, target: req.body?.target, cost, remaining_xp: row?.xp });
      return reply.send({ character: row, spent: cost });
    } catch (e) {
      if (!(e instanceof PurchaseError)) throw e;
      log.warn('XP spend refused', { user_id: req.user.id, type: req.body?.type, target: req.body?.target, error: e.message });
      return reply.status(e.status).send({ error: e.message });
    }
  });
};
