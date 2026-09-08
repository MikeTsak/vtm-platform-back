// routes/boons.js
//
// The boon ledger: who owes what to whom. Court officers write, everyone reads.

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, requireCourt } = opts;

  /* -------------------- Boons (FIXED) -------------------- */

  // GET /api/boons/entities (All logged-in users need this to resolve avatars)
  fastify.get('/api/boons/entities', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [characters] = await pool.query('SELECT id, user_id, name, clan FROM characters ORDER BY name ASC');
      const [npcs] = await pool.query('SELECT id, name, clan FROM npcs ORDER BY name ASC');

      // Using user_id for players because avatars are tied to users, not characters
      const players = characters.map(c => ({ type: 'player', id: c.user_id, name: `${c.name} (${c.clan || 'Unknown'})` }));
      const nonPlayers = npcs.map(n => ({ type: 'npc', id: n.id, name: `${n.name} (NPC)` }));

      reply.send({ entities: [...players, ...nonPlayers] });
    } catch (e) {
      log.err('Failed to get boon entities', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch entities' });
    }
  });

  // GET /api/boons (All logged-in users)
  fastify.get('/api/boons', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      // Αποτροπή caching για να βλέπουν οι χρήστες τα edits κατευθείαν
      reply.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');

      // Assuming a 'boons' table exists
      const [boons] = await pool.query(
        `SELECT * FROM boons ORDER BY created_at DESC`
      );
      reply.send({ boons });
    } catch (e) {
      log.err('Failed to get boons', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch boons' });
    }
  });

  // POST /api/boons (Court/Admin only)
  fastify.post('/api/boons', { preHandler: [authRequired, requireCourt] }, async (req, reply) => {
    try {
      const { from_name, to_name, level, status, description } = req.body;

      if (!from_name || !to_name || !level || !status) {
        return reply.status(400).json({ error: 'From, To, Level, and Status are required' });
      }

      const [r] = await pool.query(
        `INSERT INTO boons (from_name, to_name, level, status, description, created_at, date_incurred) 
    VALUES (?, ?, ?, ?, ?, NOW(), NOW())`,
        [from_name, to_name, level, status, description || null]
      );

      const [[boon]] = await pool.query('SELECT * FROM boons WHERE id=?', [r.insertId]);
      log.adm('Boon created', { id: r.insertId, by_user_id: req.user.id });
      reply.status(201).json({ boon });

    } catch (e) {
      log.err('Failed to create boon', { message: e.message, stack: e.stack });

      // Make the error explanatory for the frontend
      let errorMessage = 'Failed to create boon.';
      if (e.code === 'ER_NO_SUCH_TABLE') {
        errorMessage = 'Database error: The "boons" table does not exist yet.';
      } else if (e.code === 'ER_DATA_TOO_LONG') {
        errorMessage = 'Input error: One of the names or descriptions is too long.';
      } else {
        // Pass the raw database error message so you can see exactly what failed
        errorMessage = `Server Error: ${e.message}`;
      }

      reply.status(500).json({ error: errorMessage });
    }
  });

  // PATCH /api/boons/:id (Court/Admin only)
  fastify.patch('/api/boons/:id', { preHandler: [authRequired, requireCourt] }, async (req, reply) => {
    try {
      const { id } = req.params;
      const { from_name, to_name, level, status, description } = req.body;

      const fields = [], vals = [];
      if (from_name !== undefined) { fields.push('from_name=?'); vals.push(from_name); }
      if (to_name !== undefined) { fields.push('to_name=?'); vals.push(to_name); }
      if (level !== undefined) { fields.push('level=?'); vals.push(level); }
      if (status !== undefined) { fields.push('status=?'); vals.push(status); }
      if (description !== undefined) { fields.push('description=?'); vals.push(description); }

      if (!fields.length) {
        return reply.status(400).json({ error: 'Nothing to update' });
      }

      vals.push(id);
      await pool.query(`UPDATE boons SET ${fields.join(', ')} WHERE id=?`, vals);

      const [[boon]] = await pool.query('SELECT * FROM boons WHERE id=?', [id]);
      log.adm('Boon updated', { id, by_user_id: req.user.id });
      reply.send({ boon });

    } catch (e) {
      log.err('Failed to update boon', { message: e.message });
      reply.status(500).json({ error: `Failed to update boon: ${e.message}` });
    }
  });

  // DELETE /api/boons/:id (Court/Admin only)
  fastify.delete('/api/boons/:id', { preHandler: [authRequired, requireCourt] }, async (req, reply) => {
    try {
      const { id } = req.params;
      await pool.query('DELETE FROM boons WHERE id=?', [id]);
      log.adm('Boon deleted', { id, by_user_id: req.user.id });
      reply.send({ ok: true });
    } catch (e) {
      log.err('Failed to delete boon', { message: e.message });
      reply.status(500).json({ error: 'Failed to delete boon' });
    }
  });

  // --- ADMIN NEW FEATURES ---
  fastify.get('/api/admin/boons', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [boons] = await pool.query('SELECT * FROM boons ORDER BY created_at DESC');
      reply.send({ boons });
    } catch (e) {
      log.err('Admin boons fetch failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch boons' });
    }
  });
};
