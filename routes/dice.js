// routes/dice.js
//
// Standalone V5 dice roller and its Storyteller-facing log.
const { computeV5Outcome } = require('../services/dice');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  /* -------------------- Dice Rolls (V5) -------------------- */
  fastify.post('/api/dice/rolls', { preHandler: [authRequired] }, async (req, reply) => {
    try {

      const { pool: poolCount, hunger, sides = 10, results, difficulty, note } = req.body || {};

      if (!results || !Array.isArray(results.normal) || !Array.isArray(results.hunger)) {
        return reply.status(400).json({ error: 'Invalid results format' });
      }

      let charId = null;
      try {
        const [rows] = await pool.query('SELECT id FROM characters WHERE user_id=? LIMIT 1', [req.user.id]);
        if (rows && rows.length > 0) charId = rows[0].id;
      } catch { }

      const outcome = computeV5Outcome({
        normal: results.normal.map(Number),
        hunger: results.hunger.map(Number),
      });

      const payload = {
        normal: results.normal,
        hunger: results.hunger,
        difficulty: difficulty || null
      };

      const [ins] = await pool.query(
        `INSERT INTO dice_rolls 
       (user_id, character_id, pool, hunger, sides, results_json, successes, crit_pairs, messy_crit, bestial_failure, note)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        [
          req.user.id, charId,
          Number(poolCount) || (results.normal.length + results.hunger.length),
          Number(hunger) || results.hunger.length,
          sides,
          JSON.stringify(payload),
          outcome.successes,
          outcome.crit_pairs,
          outcome.messy_crit ? 1 : 0,
          outcome.bestial_failure ? 1 : 0,
          note ? String(note).slice(0, 255) : null
        ]
      );

      log.ok('Dice roll logged', { user_id: req.user.id, roll_id: ins.insertId });
      reply.status(201).json({ id: ins.insertId, ...outcome });
    } catch (e) {
      log.err('Save dice roll failed', { message: e.message, stack: e.stack });
      reply.status(500).json({ error: 'Failed to save roll' });
    }
  });

  /* -------------------- Fetch Dice Logs for Admin Panel -------------------- */
  fastify.get('/api/admin/dice/rolls', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {


      let limitClause = '';
      const vals = [];

      // Allow the Stats Engine to pull all data, otherwise enforce a safe limit for the Logs tab
      if (req.query.limit === 'all') {
        limitClause = '';
      } else {
        const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 1000);
        limitClause = `LIMIT ${limit}`;
      }

      const userId = Number(req.query.user_id) || null;
      const since = req.query.since ? new Date(req.query.since) : null;
      const where = [];

      if (userId) { where.push('r.user_id=?'); vals.push(userId); }
      if (since && !isNaN(since.getTime())) { where.push('r.created_at >= ?'); vals.push(since); }

      const sql = `
      SELECT
        r.id, r.user_id, r.character_id, r.pool, r.hunger, r.sides,
        r.results_json, r.successes, r.crit_pairs, r.messy_crit, r.bestial_failure,
        r.note, r.created_at,
        u.display_name AS user_name,
        c.name AS char_name, c.clan AS char_clan
      FROM dice_rolls r
      LEFT JOIN users u ON u.id = r.user_id
      LEFT JOIN characters c ON c.id = r.character_id
      ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      ORDER BY r.created_at DESC
      ${limitClause}
    `;

      const [rows] = await pool.query(sql, vals);
      reply.send({ rolls: rows });
    } catch (e) {
      console.error('Admin fetch dice rolls failed', e);
      reply.status(500).json({ error: 'Failed to fetch dice rolls' });
    }
  });

  // Admin: Clear All Dice Rolls
  fastify.delete('/api/admin/dice/rolls/all', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [result] = await pool.query("DELETE FROM dice_rolls");
      log.adm('Cleared all dice rolls', { admin_id: req.user.id, affectedRows: result.affectedRows });
      reply.send({ success: true, count: result.affectedRows });
    } catch (e) {
      log.err('Failed to clear dice rolls', { error: e.message });
      reply.status(500).json({ success: false, error: 'Internal Server Error' });
    }
  });
};
