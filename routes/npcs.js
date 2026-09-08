// routes/npcs.js
//
// NPC CRUD and NPC XP spending — Storyteller only.
const { xpCost } = require('../utils/xpCost');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  // List NPCs (admin) — single canonical route
  fastify.get('/api/admin/npcs', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const [rows] = await pool.query('SELECT id, name, clan, sheet, xp, created_at, updated_at, camarilla_titles, status, image_url, (avatar_url IS NOT NULL OR avatar_url_thumb IS NOT NULL) AS has_avatar, is_ex, is_deceased, is_hidden, is_left, is_called, is_missing, is_exiled, is_bloodhunted, is_disabled FROM npcs ORDER BY id DESC');

    // Parse JSON sheet if stored as string
    rows.forEach(r => {
      if (r.sheet && typeof r.sheet === 'string') {
        try { r.sheet = JSON.parse(r.sheet); } catch { }
      }
    });

    // DEBUG: confirm DB and count to diagnose “empty” responses
    try {
      const [[db]] = await pool.query('SELECT DATABASE() AS db');
      log.adm('NPC list', { db: db.db, count: rows.length });
    } catch { }

    reply.send({ npcs: rows });
  });




  /// Create NPC
  fastify.post('/api/admin/npcs', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  const { name, clan, sheet } = req.body;
    if (!name || !clan) return reply.status(400).json({ error: 'Name and clan are required' });

    const [r] = await pool.query(
      'INSERT INTO npcs (name, clan, sheet, xp) VALUES (?,?,?,?)',
      [name, clan, sheet ? JSON.stringify(sheet) : null, 10000]
    );

    const [rows] = await pool.query('SELECT id, name, clan, sheet, xp, created_at, updated_at, camarilla_titles, status, image_url, is_ex, is_deceased, is_hidden, is_left, is_called, is_missing, is_exiled, is_bloodhunted, is_disabled FROM npcs WHERE id=?', [r.insertId]);
    const npc = rows[0];
    if (npc?.sheet && typeof npc.sheet === 'string') { try { npc.sheet = JSON.parse(npc.sheet); } catch { } }
    reply.send({ npc });
  });

  // Get NPC by id
  fastify.get('/api/admin/npcs/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const [rows] = await pool.query('SELECT id, name, clan, sheet, xp, created_at, updated_at, camarilla_titles, status, image_url, is_ex, is_deceased, is_hidden, is_left, is_called, is_missing, is_exiled, is_bloodhunted, is_disabled FROM npcs WHERE id=?', [req.params.id]);
    if (!rows.length) return reply.status(404).json({ error: 'NPC not found' });
    const npc = rows[0];
    if (npc?.sheet && typeof npc.sheet === 'string') { try { npc.sheet = JSON.parse(npc.sheet); } catch { } }
    reply.send({ npc });
  });

  // Update NPC
  fastify.patch('/api/admin/npcs/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  const { name, clan, sheet, xp } = req.body;
    const fields = [], vals = [];
    if (name != null) { fields.push('name=?'); vals.push(name); }
    if (clan != null) { fields.push('clan=?'); vals.push(clan); }
    if (sheet !== undefined) { fields.push('sheet=?'); vals.push(sheet ? JSON.stringify(sheet) : null); }
    if (typeof xp === 'number') { fields.push('xp=?'); vals.push(xp); }
    if (!fields.length) return reply.status(400).json({ error: 'Nothing to update' });

    vals.push(req.params.id);
    await pool.query(`UPDATE npcs SET ${fields.join(', ')} WHERE id=?`, vals);

    const [rows] = await pool.query('SELECT id, name, clan, sheet, xp, created_at, updated_at, camarilla_titles, status, image_url, is_ex, is_deceased, is_hidden, is_left, is_called, is_missing, is_exiled, is_bloodhunted, is_disabled FROM npcs WHERE id=?', [req.params.id]);
    const npc = rows[0];
    if (npc?.sheet && typeof npc.sheet === 'string') { try { npc.sheet = JSON.parse(npc.sheet); } catch { } }
    reply.send({ npc });
  });

  // Delete NPC
  fastify.delete('/api/admin/npcs/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    await pool.query('DELETE FROM npcs WHERE id=?', [req.params.id]);
    reply.send({ ok: true });
  });

  // Disable NPC
  fastify.post('/api/admin/npcs/:id/disable', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    await pool.query('UPDATE npcs SET is_disabled = TRUE WHERE id=?', [req.params.id]);
    reply.send({ ok: true });
  });

  // Spend XP (NPC)
  fastify.post('/api/admin/npcs/:id/xp/spend', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  const { type, target, currentLevel, newLevel, ritualLevel, formulaLevel, dots, disciplineKind, patchSheet } = req.body;

    const [rows] = await pool.query('SELECT id, name, clan, sheet, xp, created_at, updated_at, camarilla_titles, status, image_url, is_ex, is_deceased, is_hidden, is_left, is_called, is_missing, is_exiled, is_bloodhunted, is_disabled FROM npcs WHERE id=?', [req.params.id]);
    const ch = rows[0];
    if (!ch) return reply.status(404).json({ error: 'NPC not found' });

    // cost calc same as before
    let cost = 0;
    try {
      if (type === 'discipline' && (disciplineKind === 'select' || Number(newLevel) === Number(currentLevel))) {
        cost = 0;
      } else {
        cost = xpCost({ type, newLevel, ritualLevel, formulaLevel, dots, disciplineKind });
      }
    } catch (e) {
      return reply.status(400).json({ error: e.message });
    }

    if ((ch.xp || 0) < cost) {
      return reply.status(400).json({ error: `Not enough XP (need ${cost}, have ${ch.xp})` });
    }

    if (cost > 0) {
      await pool.query('UPDATE npcs SET xp = xp - ? WHERE id=?', [cost, ch.id]);
    }
    if (patchSheet !== undefined) {
      await pool.query('UPDATE npcs SET sheet=? WHERE id=?', [JSON.stringify(patchSheet), ch.id]);
    }

    // optional: log to xp_log if you want, but use character_id=null or a separate npc_id column if your schema supports it

    const [out] = await pool.query('SELECT id, name, clan, sheet, xp, created_at, updated_at, camarilla_titles, status, image_url, is_ex, is_deceased, is_hidden, is_left, is_called, is_missing, is_exiled, is_bloodhunted, is_disabled FROM npcs WHERE id=?', [ch.id]);
    const outCh = out[0];
    if (outCh?.sheet && typeof outCh.sheet === 'string') { try { outCh.sheet = JSON.parse(outCh.sheet); } catch { } }
    reply.send({ character: outCh, spent: cost });
  });
};
