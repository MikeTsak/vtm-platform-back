// back/routes/wishlist.js
//
// Wishlist routes: allows players to save powers and rituals for quick reference
// and provides Storytellers with an administrative overview of player wishlists.

function cleanString(val, maxLen) {
  if (val === undefined || val === null) return '';
  const s = String(val).trim();
  return maxLen ? s.slice(0, maxLen) : s;
}

function cleanLevel(val) {
  const n = parseInt(val, 10);
  if (isNaN(n) || n < 1) return 1;
  if (n > 5) return 5;
  return n;
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  /* ==================================================================
     Player-facing
     ================================================================== */

  // Get current player's wishlist
  fastify.get('/api/characters/me/wishlist', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [[ch]] = await pool.query('SELECT id FROM characters WHERE user_id = ?', [req.user.id]);
      if (!ch) {
        return reply.send({ wishlist: [] });
      }

      const [rows] = await pool.query(
        `SELECT id, character_id, item_type, item_id, name, discipline, level, note, created_at
         FROM character_wishlists
         WHERE character_id = ?
         ORDER BY item_type, discipline, level, name`,
        [ch.id]
      );

      return reply.send({ wishlist: rows });
    } catch (err) {
      log.err('GET /api/characters/me/wishlist failed', { error: err.message });
      return reply.status(500).send({ error: 'Database error fetching wishlist' });
    }
  });

  // Add or update an item on the current player's wishlist
  fastify.post('/api/characters/me/wishlist', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [[ch]] = await pool.query('SELECT id FROM characters WHERE user_id = ?', [req.user.id]);
      if (!ch) {
        return reply.status(400).send({ error: 'Create a character first' });
      }

      const itemType = cleanString(req.body?.item_type, 20).toLowerCase();
      if (itemType !== 'power' && itemType !== 'ritual') {
        return reply.status(400).send({ error: 'item_type must be power or ritual' });
      }

      const itemId = cleanString(req.body?.item_id, 100);
      const name = cleanString(req.body?.name, 150);
      const discipline = cleanString(req.body?.discipline, 60);
      const level = cleanLevel(req.body?.level);
      const note = cleanString(req.body?.note, 500) || null;

      if (!itemId || !name || !discipline) {
        return reply.status(400).send({ error: 'item_id, name, and discipline are required' });
      }

      await pool.query(
        `INSERT INTO character_wishlists (character_id, item_type, item_id, name, discipline, level, note)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           name = VALUES(name),
           discipline = VALUES(discipline),
           level = VALUES(level),
           note = VALUES(note)`,
        [ch.id, itemType, itemId, name, discipline, level, note]
      );

      const [[saved]] = await pool.query(
        'SELECT * FROM character_wishlists WHERE character_id = ? AND item_type = ? AND item_id = ?',
        [ch.id, itemType, itemId]
      );

      return reply.send({ ok: true, item: saved });
    } catch (err) {
      log.err('POST /api/characters/me/wishlist failed', { error: err.message });
      return reply.status(500).send({ error: 'Database error updating wishlist' });
    }
  });

  // Toggle item on wishlist (add if absent, remove if present)
  fastify.post('/api/characters/me/wishlist/toggle', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [[ch]] = await pool.query('SELECT id FROM characters WHERE user_id = ?', [req.user.id]);
      if (!ch) {
        return reply.status(400).send({ error: 'Create a character first' });
      }

      const itemType = cleanString(req.body?.item_type, 20).toLowerCase();
      if (itemType !== 'power' && itemType !== 'ritual') {
        return reply.status(400).send({ error: 'item_type must be power or ritual' });
      }

      const itemId = cleanString(req.body?.item_id, 100);
      const name = cleanString(req.body?.name, 150);
      const discipline = cleanString(req.body?.discipline, 60);
      const level = cleanLevel(req.body?.level);
      const note = cleanString(req.body?.note, 500) || null;

      if (!itemId) {
        return reply.status(400).send({ error: 'item_id is required' });
      }

      const [[existing]] = await pool.query(
        'SELECT id FROM character_wishlists WHERE character_id = ? AND item_type = ? AND item_id = ?',
        [ch.id, itemType, itemId]
      );

      if (existing) {
        await pool.query('DELETE FROM character_wishlists WHERE id = ?', [existing.id]);
        return reply.send({ ok: true, action: 'removed', item_id: itemId, item_type: itemType });
      } else {
        if (!name || !discipline) {
          return reply.status(400).send({ error: 'name and discipline are required to add to wishlist' });
        }
        await pool.query(
          `INSERT INTO character_wishlists (character_id, item_type, item_id, name, discipline, level, note)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [ch.id, itemType, itemId, name, discipline, level, note]
        );
        const [[created]] = await pool.query(
          'SELECT * FROM character_wishlists WHERE character_id = ? AND item_type = ? AND item_id = ?',
          [ch.id, itemType, itemId]
        );
        return reply.send({ ok: true, action: 'added', item: created });
      }
    } catch (err) {
      log.err('POST /api/characters/me/wishlist/toggle failed', { error: err.message });
      return reply.status(500).send({ error: 'Database error toggling wishlist item' });
    }
  });

  // Remove by ID
  fastify.delete('/api/characters/me/wishlist/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [[ch]] = await pool.query('SELECT id FROM characters WHERE user_id = ?', [req.user.id]);
      if (!ch) {
        return reply.status(404).send({ error: 'Character not found' });
      }

      const id = parseInt(req.params.id, 10);
      await pool.query('DELETE FROM character_wishlists WHERE id = ? AND character_id = ?', [id, ch.id]);

      return reply.send({ ok: true });
    } catch (err) {
      log.err('DELETE /api/characters/me/wishlist/:id failed', { error: err.message });
      return reply.status(500).send({ error: 'Database error deleting wishlist item' });
    }
  });

  // Remove by item_type and item_id
  fastify.delete('/api/characters/me/wishlist/item/:itemType/:itemId', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [[ch]] = await pool.query('SELECT id FROM characters WHERE user_id = ?', [req.user.id]);
      if (!ch) {
        return reply.status(404).send({ error: 'Character not found' });
      }

      const itemType = cleanString(req.params.itemType, 20).toLowerCase();
      const itemId = cleanString(req.params.itemId, 100);

      await pool.query(
        'DELETE FROM character_wishlists WHERE character_id = ? AND item_type = ? AND item_id = ?',
        [ch.id, itemType, itemId]
      );

      return reply.send({ ok: true });
    } catch (err) {
      log.err('DELETE /api/characters/me/wishlist/item failed', { error: err.message });
      return reply.status(500).send({ error: 'Database error deleting wishlist item' });
    }
  });

  /* ==================================================================
     Admin-facing
     ================================================================== */

  // Get all wishlists across characters
  fastify.get('/api/admin/wishlists', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
        SELECT
          cw.id,
          cw.character_id,
          cw.item_type,
          cw.item_id,
          cw.name,
          cw.discipline,
          cw.level,
          cw.note,
          cw.created_at,
          c.name AS character_name,
          c.clan,
          c.xp AS current_xp,
          c.user_id,
          u.email,
          u.display_name
        FROM character_wishlists cw
        JOIN characters c ON cw.character_id = c.id
        LEFT JOIN users u ON c.user_id = u.id
        ORDER BY c.name ASC, cw.item_type ASC, cw.discipline ASC, cw.level ASC
      `);

      return reply.send({ wishlists: rows });
    } catch (err) {
      log.err('GET /api/admin/wishlists failed', { error: err.message });
      return reply.status(500).send({ error: 'Database error fetching admin wishlists' });
    }
  });

  // Admin delete a wishlist item
  fastify.delete('/api/admin/wishlists/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const id = parseInt(req.params.id, 10);
      await pool.query('DELETE FROM character_wishlists WHERE id = ?', [id]);
      return reply.send({ ok: true });
    } catch (err) {
      log.err('DELETE /api/admin/wishlists/:id failed', { error: err.message });
      return reply.status(500).send({ error: 'Database error deleting wishlist item (admin)' });
    }
  });
};
