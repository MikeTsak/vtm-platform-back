// routes/adminCharacters.js
//
// Storyteller character administration: roster, ghouls, edit, delete.

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  // Admin: add/remove XP to single character
  // DUP: fastify.patch('/api/admin/characters/:id/xp', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  // DUP:   const { delta } = req.body;
  // DUP:   if (typeof delta !== 'number') return reply.status(400).json({ error: 'delta must be a number' });
  // DUP: 
  // DUP:   await pool.query('UPDATE characters SET xp = GREATEST(0, xp + ?) WHERE id=?', [delta, req.params.id]);
  // DUP:   const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [req.params.id]);
  // DUP:   log.adm('Admin XP adjust', { character_id: req.params.id, delta, new_xp: out[0]?.xp });
  // DUP:   reply.send({ character: out[0] });
  // DUP: });

  // ADMIN: Get all characters (for stats and admin views)
  fastify.get('/api/admin/characters', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [characters] = await pool.query('SELECT * FROM characters ORDER BY created_at DESC');
      reply.send({ characters });
    } catch (e) {
      console.error('Failed to fetch all characters:', e);
      reply.status(500).json({ error: 'Failed to fetch characters' });
    }
  });

  // --- Admin: fetch all ghouls ---
  fastify.get('/api/admin/ghouls', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [ghouls] = await pool.query(`
      SELECT 
        r.id, r.name as retainer_name, r.tier, r.sheet, r.created_at, 
        c.id as domitor_id, c.name as domitor_name, c.clan as domitor_clan, c.xp as domitor_xp, c.image_url as domitor_image_url,
        u.display_name as player_name, u.id as user_id
      FROM retainers r
      JOIN characters c ON r.character_id = c.id
      JOIN users u ON c.user_id = u.id
      WHERE JSON_EXTRACT(r.sheet, '$.isGhoul') = true
      ORDER BY r.created_at DESC
    `);
      reply.send({ ghouls });
    } catch (e) {
      console.error('Failed to fetch all ghouls:', e);
      reply.status(500).json({ error: 'Failed to fetch ghouls' });
    }
  });

  // --- Admin: edit character ---
  fastify.patch('/api/admin/characters/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const id = Number(req.params.id);
  const { name, clan, sheet } = req.body;

    const fields = [];
    const vals = [];

    if (typeof name === 'string') { fields.push('name=?'); vals.push(name.trim()); }
    if (typeof clan === 'string') { fields.push('clan=?'); vals.push(clan.trim()); }

    if (sheet !== undefined) {
      let jsonStr = null;
      try {
        const obj = (typeof sheet === 'string') ? JSON.parse(sheet) : sheet;
        jsonStr = JSON.stringify(obj ?? {});
      } catch {
        return reply.status(400).json({ error: 'sheet must be valid JSON (object or stringified object)' });
      }
      fields.push('sheet=?'); vals.push(jsonStr);
    }

    if (!fields.length) return reply.status(400).json({ error: 'Nothing to update' });

    vals.push(id);
    await pool.query(`UPDATE characters SET ${fields.join(', ')} WHERE id=?`, vals);

    const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [id]);
    const ch = rows[0];
    if (ch && ch.sheet && typeof ch.sheet === 'string') { try { ch.sheet = JSON.parse(ch.sheet); } catch { } }
    log.adm('Character updated', { id, fields });
    reply.send({ character: ch });
  });

  // Delete Character (admin)
  fastify.delete('/api/admin/characters/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return reply.status(400).json({ error: 'Invalid character id' });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Remove/neutralize references to this character
      await conn.query('DELETE FROM domain_members WHERE character_id=?', [id]);
      await conn.query('DELETE FROM downtimes WHERE character_id=?', [id]);
      try { await conn.query('DELETE FROM xp_log WHERE character_id=?', [id]); } catch (_) { /* xp_log may not exist */ }
      await conn.query('UPDATE domain_claims SET owner_character_id=NULL WHERE owner_character_id=?', [id]);

      // Finally delete the character
      const [result] = await conn.query('DELETE FROM characters WHERE id=?', [id]);
      await conn.commit();

      if (result.affectedRows === 0) return reply.status(404).json({ error: 'Character not found' });

      log.adm('Character deleted', { id, by_user_id: req.user.id });
      reply.send({ ok: true });
    } catch (e) {
      await conn.rollback();
      log.err('Delete character failed', { message: e.message, stack: e.stack, id });
      reply.status(500).json({ error: 'Failed to delete character' });
    } finally {
      conn.release();
    }
  });
};
