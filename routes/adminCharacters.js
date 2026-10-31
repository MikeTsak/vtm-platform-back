// routes/adminCharacters.js
//
// Storyteller character administration: roster, ghouls, edit, delete.

const { parseSheet } = require('../utils/sheet');
const { attachFeeding } = require('../services/ghoulFeeding');
const { ghoulTrackers } = require('../services/ghoulTrackers');
const { retireCharacter, restoreCharacter } = require('../services/characterRetirement');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  // Admin: add/remove XP to single character
  // DUP: fastify.patch('/api/admin/characters/:id/xp', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  // DUP:   const { delta } = req.body;
  // DUP:   if (typeof delta !== 'number') return reply.status(400).send({ error: 'delta must be a number' });
  // DUP: 
  // DUP:   await pool.query('UPDATE characters SET xp = GREATEST(0, xp + ?) WHERE id=?', [delta, req.params.id]);
  // DUP:   const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [req.params.id]);
  // DUP:   log.adm('Admin XP adjust', { character_id: req.params.id, delta, new_xp: out[0]?.xp });
  // DUP:   reply.send({ character: out[0] });
  // DUP: });

  // ADMIN: Get all current characters (for stats and admin views).
  // ?retired=1 lists retired ones instead, with their player.
  fastify.get('/api/admin/characters', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [characters] = req.query.retired === '1'
        ? await pool.query(
          `SELECT c.id, c.name, c.clan, c.xp, c.is_deceased, c.created_at, c.retired_at, c.retired_user_id,
                  u.display_name, u.email
             FROM characters c JOIN users u ON u.id = c.retired_user_id
            ORDER BY c.retired_at DESC`)
        : await pool.query('SELECT * FROM characters WHERE user_id IS NOT NULL ORDER BY created_at DESC');
      reply.send({ characters });
    } catch (e) {
      console.error('Failed to fetch all characters:', e);
      reply.status(500).send({ error: 'Failed to fetch characters' });
    }
  });

  // Retire / restore (services/characterRetirement.js). Retiring frees the
  // player to create a new character; restoring makes a retired one current
  // again and retires whoever is current.
  const inTransaction = async (fn) => {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const out = await fn(conn);
      await conn.commit();
      return out;
    } catch (e) {
      await conn.rollback().catch(() => {});
      throw e;
    } finally {
      conn.release();
    }
  };

  fastify.post('/api/admin/characters/:id/retire', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const id = Number(req.params.id);
    if (!(await inTransaction(conn => retireCharacter(conn, id)))) {
      return reply.status(404).send({ error: 'No current character with that id' });
    }
    log.adm('Character retired', { id, by_user_id: req.user.id });
    reply.send({ ok: true });
  });

  fastify.post('/api/admin/characters/:id/restore', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const id = Number(req.params.id);
    const userId = await inTransaction(conn => restoreCharacter(conn, id));
    if (!userId) return reply.status(404).send({ error: 'No retired character with that id' });
    log.adm('Character restored', { id, user_id: userId, by_user_id: req.user.id });
    reply.send({ ok: true });
  });

  // --- Admin: every retainer — personal mortals, ghouls, and coterie-owned ---
  // `manage_*` is the character the Retainers page is opened as: the owner of
  // a personal retainer, else a coterie retainer's domitor, else the
  // coterie's first member. `blood_from` names the members whose blood gives
  // a coterie ghoul its extra Disciplines (sheet.bloodSources).
  fastify.get('/api/admin/retainers', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
        SELECT r.id, r.name, r.tier, r.sheet, r.created_at,
               r.character_id, r.coterie_id, r.domitor_character_id,
               oc.name AS owner_name, oc.clan AS owner_clan, ou.display_name AS owner_player, oc.user_id AS owner_user_id,
               co.name AS coterie_name,
               dc.name AS domitor_name, dc.clan AS domitor_clan, du.display_name AS domitor_player, dc.user_id AS domitor_user_id,
               mc.id AS manage_id, mc.name AS manage_name, mc.clan AS manage_clan, mc.xp AS manage_xp
          FROM retainers r
          LEFT JOIN characters oc ON oc.id = r.character_id
          LEFT JOIN users ou ON ou.id = oc.user_id
          LEFT JOIN coteries co ON co.id = r.coterie_id
          LEFT JOIN characters dc ON dc.id = r.domitor_character_id
          LEFT JOIN users du ON du.id = dc.user_id
          LEFT JOIN characters mc ON mc.id = COALESCE(
            r.character_id, r.domitor_character_id,
            (SELECT m.character_id FROM coterie_members m
              WHERE m.coterie_id = r.coterie_id AND m.character_id IS NOT NULL
              ORDER BY m.id LIMIT 1))
         ORDER BY r.created_at DESC
      `);

      const sourceIds = new Set();
      for (const r of rows) {
        r.sheet = parseSheet(r.sheet);
        for (const id of Object.values((r.sheet && r.sheet.bloodSources) || {})) sourceIds.add(Number(id));
      }
      const names = new Map();
      if (sourceIds.size) {
        const [chars] = await pool.query('SELECT id, name FROM characters WHERE id IN (?)', [[...sourceIds]]);
        for (const c of chars) names.set(Number(c.id), c.name);
      }
      for (const r of rows) {
        r.blood_from = Object.fromEntries(Object.entries((r.sheet && r.sheet.bloodSources) || {})
          .map(([disc, id]) => [disc, names.get(Number(id)) || 'a former member']));
      }
      await attachFeeding(pool, rows);
      for (const r of rows) r.trackers = ghoulTrackers(r.sheet || {});
      reply.send({ retainers: rows });
    } catch (e) {
      log.err('Failed to fetch all retainers', { message: e.message });
      reply.status(500).send({ error: 'Failed to fetch retainers' });
    }
  });

  // --- Admin: edit character ---
  // `sheet` replaces the whole sheet (the full editor). `sheetPatch` sets only
  // its top-level keys on the STORED sheet: trackers and flags must go through
  // it, or a sheet cached in the browser undoes everything saved since it was
  // loaded (a player's XP purchase was lost that way).
  fastify.patch('/api/admin/characters/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const id = Number(req.params.id);
    const { name, clan, sheet, sheetPatch, sheetUnset } = req.body;

    const fields = [];
    const vals = [];

    if (typeof name === 'string') { fields.push('name=?'); vals.push(name.trim()); }
    if (typeof clan === 'string') { fields.push('clan=?'); vals.push(clan.trim()); }

    let jsonStr = null;
    if (sheet !== undefined) {
      try {
        const obj = (typeof sheet === 'string') ? JSON.parse(sheet) : sheet;
        jsonStr = JSON.stringify(obj ?? {});
      } catch {
        return reply.status(400).send({ error: 'sheet must be valid JSON (object or stringified object)' });
      }
      fields.push('sheet=?'); vals.push(jsonStr);
    } else if (sheetPatch !== undefined) {
      if (!sheetPatch || typeof sheetPatch !== 'object' || Array.isArray(sheetPatch)) {
        return reply.status(400).send({ error: 'sheetPatch must be an object' });
      }
    }

    if (!fields.length && sheetPatch === undefined) return reply.status(400).send({ error: 'Nothing to update' });

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      if (jsonStr === null && sheetPatch !== undefined) {
        const [[row]] = await conn.query('SELECT sheet FROM characters WHERE id=? FOR UPDATE', [id]);
        if (!row) { await conn.rollback(); return reply.status(404).send({ error: 'Character not found' }); }
        const merged = { ...parseSheet(row.sheet), ...sheetPatch };
        // Keys the editor removed (a patch can't express a delete; null is a real value).
        if (Array.isArray(sheetUnset)) for (const k of sheetUnset) if (typeof k === 'string' && !(k in sheetPatch)) delete merged[k];
        jsonStr = JSON.stringify(merged);
        fields.push('sheet=?'); vals.push(jsonStr);
      }
      await conn.query(`UPDATE characters SET ${fields.join(', ')} WHERE id=?`, [...vals, id]);
      await conn.commit();
    } catch (e) {
      await conn.rollback().catch(() => {});
      throw e;
    } finally {
      conn.release();
    }

    if (jsonStr !== null) {
      try {
        await pool.query(
          'INSERT INTO character_sheet_versions (character_id, editor_id, sheet, change_summary) VALUES (?, ?, ?, ?)',
          [id, req.user?.id || null, jsonStr, 'Admin character sheet update']
        );
      } catch (err) {
        // Non-fatal
      }
    }

    const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [id]);
    const ch = rows[0];
    if (ch) ch.sheet = parseSheet(ch.sheet);
    log.adm('Character updated', { id, fields });
    reply.send({ character: ch });
  });

  // Delete Character (admin)
  fastify.delete('/api/admin/characters/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return reply.status(400).send({ error: 'Invalid character id' });
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

      if (result.affectedRows === 0) return reply.status(404).send({ error: 'Character not found' });

      log.adm('Character deleted', { id, by_user_id: req.user.id });
      reply.send({ ok: true });
    } catch (e) {
      await conn.rollback();
      log.err('Delete character failed', { message: e.message, stack: e.stack, id });
      reply.status(500).send({ error: 'Failed to delete character' });
    } finally {
      conn.release();
    }
  });
};
