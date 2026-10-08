// routes/boons.js
//
// The boon ledger: who owes what to whom. Court officers write, everyone reads.

const BOON_SELECT_SQL = `
  SELECT b.*,
    CASE 
      WHEN u_rec.id = 3 OR LOWER(TRIM(u_rec.display_name)) = 'admin' THEN 'Mike'
      WHEN u_rec.id = 5 OR LOWER(TRIM(u_rec.display_name)) = 'st kikos' THEN 'Kikos'
      WHEN c_rec.id IS NOT NULL THEN
        CONCAT_WS(' ', 
          CASE 
            WHEN JSON_VALID(c_rec.camarilla_titles) = 1 AND JSON_LENGTH(c_rec.camarilla_titles) > 0 
            THEN JSON_UNQUOTE(JSON_EXTRACT(c_rec.camarilla_titles, '$[0]'))
            ELSE NULL
          END,
          c_rec.name
        )
      ELSE u_rec.display_name 
    END AS recorded_by_name,
    CASE 
      WHEN u_res.id = 3 OR LOWER(TRIM(u_res.display_name)) = 'admin' THEN 'Mike'
      WHEN u_res.id = 5 OR LOWER(TRIM(u_res.display_name)) = 'st kikos' THEN 'Kikos'
      WHEN c_res.id IS NOT NULL THEN
        CONCAT_WS(' ', 
          CASE 
            WHEN JSON_VALID(c_res.camarilla_titles) = 1 AND JSON_LENGTH(c_res.camarilla_titles) > 0 
            THEN JSON_UNQUOTE(JSON_EXTRACT(c_res.camarilla_titles, '$[0]'))
            ELSE NULL
          END,
          c_res.name
        )
      ELSE u_res.display_name 
    END AS resolved_by_name
  FROM boons b
  LEFT JOIN users u_rec ON u_rec.id = b.recorded_by
  LEFT JOIN users u_res ON u_res.id = b.resolved_by
  LEFT JOIN characters c_rec ON c_rec.user_id = u_rec.id
  LEFT JOIN characters c_res ON c_res.user_id = u_res.id
`;

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
        `${BOON_SELECT_SQL} ORDER BY b.created_at DESC`
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
        `INSERT INTO boons (from_name, to_name, level, status, description, created_at, date_incurred, recorded_by) 
    VALUES (?, ?, ?, ?, ?, NOW(), NOW(), ?)`,
        [from_name, to_name, level, status, description || null, req.user?.id || null]
      );

      const [[boon]] = await pool.query(`${BOON_SELECT_SQL} WHERE b.id=?`, [r.insertId]);
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
      if (status !== undefined) {
        fields.push('status=?');
        vals.push(status);
        if (String(status).toLowerCase() !== 'owed') {
          fields.push('resolved_by=?');
          vals.push(req.user?.id || null);
          fields.push('resolved_at=NOW()');
        } else {
          fields.push('resolved_by=NULL');
          fields.push('resolved_at=NULL');
        }
      }
      if (description !== undefined) { fields.push('description=?'); vals.push(description); }

      if (!fields.length) {
        return reply.status(400).json({ error: 'Nothing to update' });
      }

      vals.push(id);
      await pool.query(`UPDATE boons SET ${fields.join(', ')} WHERE id=?`, vals);

      const [[boon]] = await pool.query(`${BOON_SELECT_SQL} WHERE b.id=?`, [id]);
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
      const [boons] = await pool.query(`${BOON_SELECT_SQL} ORDER BY b.created_at DESC`);
      reply.send({ boons });
    } catch (e) {
      log.err('Admin boons fetch failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch boons' });
    }
  });
};
