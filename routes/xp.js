// routes/xp.js
//
// Storyteller-side XP: spend on a player's behalf, adjust balances (single and
// bulk), and read the audit log. The self-serve counterpart lives in
// routes/characterXp.js.
const { xpCost } = require('../utils/xpCost');
const { getSetting, setSetting } = require('../utils/settings');

// Validates a client-supplied list of character ids; returns a de-duplicated
// array of positive integers, or null if the input is malformed.
function parseIdList(value) {
  if (!Array.isArray(value) || value.length > 1000) return null;
  const ids = value.map(Number);
  if (!ids.every(n => Number.isInteger(n) && n > 0)) return null;
  return [...new Set(ids)];
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  fastify.post('/api/admin/characters/:id/xp/spend', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  const {
      type, target, currentLevel, newLevel,
      ritualLevel, formulaLevel, dots,
      disciplineKind, patchSheet
    } = req.body;

    const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [req.params.id]);
    const ch = rows[0];
    if (!ch) {
      log.warn('XP spend without character (admin)', { char_id: req.params.id });
      return reply.status(404).json({ error: 'Character not found' });
    }

    let cost = 0;
    try {
      if (
        type === 'discipline' &&
        (
          disciplineKind === 'select' ||
          Number(newLevel) === Number(currentLevel)
        )
      ) {
        cost = 0;
      } else {
        cost = xpCost({ type, newLevel, ritualLevel, formulaLevel, dots, disciplineKind });
      }
    } catch (e) {
      log.warn('XP spend bad type (admin)', { type });
      return reply.status(400).json({ error: e.message });
    }

    if (cost > 0) {
      if ((ch.xp || 0) < cost) {
        log.warn('XP spend insufficient (admin)', { char_id: ch.id, have: ch.xp, need: cost });
        return reply.status(400).json({ error: `Not enough XP (need ${cost}, have ${ch.xp})` });
      }
      log.xp('XP spend request (admin)', { char_id: ch.id, type, target, currentLevel, newLevel, cost });
      await pool.query('UPDATE characters SET xp = xp - ? WHERE id=?', [cost, ch.id]);
    } else {
      log.xp('Discipline power assignment free (admin)', { char_id: ch.id, target, level: newLevel });
    }

    if (patchSheet !== undefined) {
      await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(patchSheet), ch.id]);
      log.xp('Sheet patched after action (admin)', { character_id: ch.id });
    }

    try {
      await pool.query(
        'INSERT INTO xp_log (character_id, action, target, from_level, to_level, cost, payload) VALUES (?,?,?,?,?,?,?)',
        [ch.id, type, target || null, currentLevel || null, newLevel || null, cost,
        JSON.stringify({ disciplineKind, ritualLevel, formulaLevel, dots })]
      );
      log.xp('XP logged (admin)', { character_id: ch.id, cost });
    } catch (_) { }

    const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [ch.id]);
    const outCh = out[0];
    if (outCh && outCh.sheet && typeof outCh.sheet === 'string') { try { outCh.sheet = JSON.parse(outCh.sheet); } catch { } }

    if (cost > 0) {
      log.ok('XP spend complete (admin)', { char_id: ch.id, remaining_xp: outCh?.xp });
    } else {
      log.ok('Power assignment saved free (admin)', { char_id: ch.id });
    }

    reply.send({ character: outCh, spent: cost });
  });

  /* -------------------- Admin add/remove XP -------------------- */
  fastify.patch('/api/admin/characters/:id/xp', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  const { delta } = req.body;
    if (typeof delta !== 'number') return reply.status(400).json({ error: 'delta must be a number' });

    await pool.query('UPDATE characters SET xp = GREATEST(0, xp + ?) WHERE id=?', [delta, req.params.id]);
    const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [req.params.id]);

    // NEW: Log this admin grant to your existing xp_log table
    try {
      await pool.query(
        'INSERT INTO xp_log (character_id, action, target, cost, payload) VALUES (?, ?, ?, ?, ?)',
        [req.params.id, 'admin_grant', req.body.reason || 'Admin XP Adjustment', -delta, JSON.stringify({ admin_id: req.user.id })]
      );
    } catch (err) {
      console.error('Failed to save to xp_log:', err);
    }

    log.adm('Admin XP adjust', { character_id: req.params.id, delta, new_xp: out[0]?.xp });
    reply.send({ character: out[0] });
  });

  /* -------------------- Admin add/remove XP -------------------- */

  // Admin: Bulk XP to a selected set of characters at once
  fastify.patch('/api/admin/characters/xp/bulk', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const { delta, character_ids } = req.body || {};
    if (typeof delta !== 'number' || !Number.isInteger(delta) || delta === 0) {
      return reply.status(400).json({ error: 'delta must be a non-zero integer' });
    }
    const ids = parseIdList(character_ids);
    if (!ids || ids.length === 0) {
      return reply.status(400).json({ error: 'character_ids must be a non-empty array of character ids' });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [result] = await conn.query('UPDATE characters SET xp = GREATEST(0, xp + ?) WHERE id IN (?)', [delta, ids]);
      await conn.query(`
      INSERT INTO xp_log (character_id, action, target, cost, payload)
      SELECT id, 'admin_bulk_grant', 'Bulk Session XP', ?, ? FROM characters WHERE id IN (?)
    `, [-delta, JSON.stringify({ admin_id: req.user.id }), ids]);
      await conn.commit();

      log.adm('Admin bulk XP adjust', { admin_id: req.user.id, delta, count: result.affectedRows });
      reply.send({ ok: true, count: result.affectedRows });
    } catch (e) {
      await conn.rollback();
      log.err('Admin bulk XP adjust failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to adjust bulk XP' });
    } finally {
      conn.release();
    }
  });

  /* -------------------- Saved bulk-grant selection (per admin) -------------------- */
  const selectionKey = (userId) => `xp_bulk_selection:${userId}`;

  fastify.get('/api/admin/xp/bulk-selection', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    let ids = [];
    try { ids = parseIdList(JSON.parse(await getSetting(selectionKey(req.user.id), '[]'))) || []; } catch (_) { }
    reply.send({ character_ids: ids });
  });

  fastify.put('/api/admin/xp/bulk-selection', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const ids = parseIdList(req.body?.character_ids);
    if (!ids) return reply.status(400).json({ error: 'character_ids must be an array of character ids' });
    const ok = await setSetting(selectionKey(req.user.id), JSON.stringify(ids));
    if (!ok) return reply.status(500).json({ error: 'Failed to save selection' });
    reply.send({ character_ids: ids });
  });

  /* -------------------- Fetch XP Logs for Admin Panel -------------------- */
  fastify.get('/api/admin/xp-logs', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      // Allow the Stats Engine to bypass the 200 limit to calculate all-time flow
      const limitClause = req.query.limit === 'all' ? '' : 'LIMIT 200';
      const [logs] = await pool.query(`
      SELECT l.*, c.name as character_name, u.display_name as player_name 
      FROM xp_log l
      LEFT JOIN characters c ON l.character_id = c.id
      LEFT JOIN users u ON c.user_id = u.id
      ORDER BY l.id DESC
      ${limitClause}
    `);
      reply.send(logs);
    } catch (error) {
      console.error('Error fetching XP logs:', error);
      reply.status(500).json({ error: 'Failed to fetch XP logs' });
    }
  });
};
