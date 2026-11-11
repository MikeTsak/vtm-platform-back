// routes/boons.js
//
// The boon ledger: who owes what to whom. Court officers write, everyone reads.

const { characterAtSql } = require('../services/characterRetirement');

// Standing bodies of the city that can owe or hold a boon.
const INSTITUTIONS = [
  'The Court of Athens', 'The Primogen Council', "The Sheriff's Office", 'The Harpies', 'Elysium', 'The Camarilla',
];

const LEVEL_NAME = { trivial: 'Trivial', minor: 'Minor', major: 'Major', life: 'Life' };
const levelName = (level) => LEVEL_NAME[String(level || '').toLowerCase()] || 'Trivial';

// A side "is dead" when it names a character or NPC marked deceased. Parties
// are stored by name, so this is a name match. An open boon with a dead side
// is orphaned: neither paid nor passed on until the court transfers it.
const deadPartySql = (col) => `(
    EXISTS(SELECT 1 FROM characters dc WHERE dc.name = ${col} AND dc.is_deceased = 1)
    OR EXISTS(SELECT 1 FROM npcs dn WHERE dn.name = ${col} AND dn.is_deceased = 1))`;

const BOON_SELECT_SQL = `
  SELECT b.*,
    ${deadPartySql('b.from_name')} AS from_dead,
    ${deadPartySql('b.to_name')} AS to_dead,
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
  LEFT JOIN characters c_rec ON c_rec.id = ${characterAtSql('u_rec.id', 'b.created_at')}
  LEFT JOIN characters c_res ON c_res.id = ${characterAtSql('u_res.id', 'b.resolved_at')}
`;

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, requireCourt, sendPushNotification } = opts;

  // Accounts that answer for these parties: the player of a living character,
  // or every living member of a coterie. Courts, clans and NPCs have no one to ping.
  const partyUserIds = async (names) => {
    if (!names.length) return [];
    const [rows] = await pool.query(
      `SELECT c.user_id FROM characters c
        WHERE c.name IN (?) AND c.user_id IS NOT NULL AND COALESCE(c.is_deceased, 0) = 0
       UNION
       SELECT m.user_id FROM coteries co
         JOIN coterie_members m ON m.coterie_id = co.id
         JOIN characters c ON c.user_id = m.user_id AND COALESCE(c.is_deceased, 0) = 0
        WHERE co.name IN (?)`,
      [names, names]
    );
    // The UNION mixes signed and unsigned ids, which comes back as strings.
    return rows.map(r => Number(r.user_id));
  };

  // Fire-and-forget: a failed push must never fail the ledger write. The court
  // member who made the change already knows.
  const notifyParties = (names, exceptUserId, title, body) => {
    partyUserIds([...new Set(names.filter(Boolean))])
      .then(ids => Promise.all(ids.filter(id => id !== exceptUserId)
        .map(id => sendPushNotification(id, title, body, { url: '/boons' }, 'court'))))
      .catch(e => log.err('Boon push failed', { message: e.message }));
  };

  /* -------------------- Boons (FIXED) -------------------- */

  // GET /api/boons/entities (All logged-in users need this to resolve avatars)
  fastify.get('/api/boons/entities', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [characters] = await pool.query('SELECT id, user_id, name, clan, avatar_url, avatar_url_thumb FROM characters ORDER BY name ASC');
      const [npcs] = await pool.query('SELECT id, name, clan FROM npcs ORDER BY name ASC');

      // Using user_id for players because avatars are tied to users, not characters.
      // A retired character has no account: it carries the portrait saved at retirement.
      const players = characters.map(c => ({
        type: 'player', id: c.user_id, name: `${c.name} (${c.clan || 'Unknown'})`,
        ...(c.user_id ? {} : { avatar_url: c.avatar_url_thumb || c.avatar_url || null }),
      }));
      const nonPlayers = npcs.map(n => ({ type: 'npc', id: n.id, name: `${n.name} (NPC)` }));

      // Boons can be owed by or to a body, not just a person. Parties are stored
      // by name, so these only feed the picker and how the ledger shows them.
      const [coteries] = await pool.query(
        `SELECT c.id, c.name, EXISTS(SELECT 1 FROM coterie_members m WHERE m.coterie_id = c.id AND m.user_id = ?) AS mine
           FROM coteries c WHERE c.status <> 'dissolved' ORDER BY c.name ASC`,
        [req.user.id]
      );
      const clans = [...new Set([...characters.filter(c => c.user_id), ...npcs].map(c => c.clan).filter(Boolean))].sort();
      const bodies = [
        ...INSTITUTIONS.map(name => ({ type: 'institution', id: name, name: `${name} (Institution)` })),
        ...coteries.map(c => ({ type: 'coterie', id: c.id, name: `${c.name} (Coterie)`, ...(c.mine ? { mine: true } : {}) })),
        ...clans.map(clan => ({ type: 'clan', id: clan, name: `Clan ${clan} (Clan)` })),
      ];

      reply.send({ entities: [...bodies, ...players, ...nonPlayers] });
    } catch (e) {
      log.err('Failed to get boon entities', { message: e.message });
      reply.status(500).send({ error: 'Failed to fetch entities' });
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
      reply.status(500).send({ error: 'Failed to fetch boons' });
    }
  });

  // POST /api/boons (Court/Admin only)
  fastify.post('/api/boons', { preHandler: [authRequired, requireCourt] }, async (req, reply) => {
    try {
      const { from_name, to_name, level, status, description } = req.body;

      if (!from_name || !to_name || !level || !status) {
        return reply.status(400).send({ error: 'From, To, Level, and Status are required' });
      }

      const [r] = await pool.query(
        `INSERT INTO boons (from_name, to_name, level, status, description, created_at, date_incurred, recorded_by) 
    VALUES (?, ?, ?, ?, ?, NOW(), NOW(), ?)`,
        [from_name, to_name, level, status, description || null, req.user?.id || null]
      );

      const [[boon]] = await pool.query(`${BOON_SELECT_SQL} WHERE b.id=?`, [r.insertId]);
      log.adm('Boon created', { id: r.insertId, by_user_id: req.user.id });
      notifyParties([from_name, to_name], req.user.id, 'A boon is recorded',
        `${from_name} owes ${to_name} a ${levelName(level)} boon.`);
      reply.status(201).send({ boon });

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

      reply.status(500).send({ error: errorMessage });
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
        return reply.status(400).send({ error: 'Nothing to update' });
      }

      vals.push(id);
      await pool.query(`UPDATE boons SET ${fields.join(', ')} WHERE id=?`, vals);

      const [[boon]] = await pool.query(`${BOON_SELECT_SQL} WHERE b.id=?`, [id]);
      log.adm('Boon updated', { id, by_user_id: req.user.id });
      reply.send({ boon });

    } catch (e) {
      log.err('Failed to update boon', { message: e.message });
      reply.status(500).send({ error: `Failed to update boon: ${e.message}` });
    }
  });

  // POST /api/boons/:id/transfer (Court/Admin only): an open boon changes hands.
  // side 'to': the holder passes it to someone else. side 'from': someone else
  // takes on the debt (an heir after Final Death, a sire, a clan).
  fastify.post('/api/boons/:id/transfer', { preHandler: [authRequired, requireCourt] }, async (req, reply) => {
    const { side, name } = req.body || {};
    const party = typeof name === 'string' ? name.trim() : '';
    if (!['from', 'to'].includes(side) || !party) {
      return reply.status(400).send({ error: 'Choose who the boon passes to.' });
    }
    if (party.length > 255) return reply.status(400).send({ error: 'That name is too long.' });

    try {
      const [[old]] = await pool.query('SELECT from_name, to_name, level, status FROM boons WHERE id=?', [req.params.id]);
      if (!old) return reply.status(404).send({ error: 'Boon not found' });
      const col = side === 'from' ? 'from_name' : 'to_name';
      const other = side === 'from' ? old.to_name : old.from_name;
      if (old[col].trim().toLowerCase() === party.toLowerCase()) {
        return reply.status(400).send({ error: `${party} already ${side === 'from' ? 'owes' : 'holds'} this boon.` });
      }
      if (other.trim().toLowerCase() === party.toLowerCase()) {
        return reply.status(400).send({ error: 'No one can owe a boon to themselves.' });
      }

      // The status guard makes a transfer racing a settlement a no-op.
      const [r] = await pool.query(`UPDATE boons SET ${col}=? WHERE id=? AND status='owed'`, [party, req.params.id]);
      if (!r.affectedRows) return reply.status(409).send({ error: 'Only an open boon can change hands.' });

      const [[boon]] = await pool.query(`${BOON_SELECT_SQL} WHERE b.id=?`, [req.params.id]);
      log.adm('Boon transferred', { id: req.params.id, side, from: old[col], to: party, by_user_id: req.user.id });
      const level = levelName(old.level);
      notifyParties([old[col], party, other], req.user.id, 'A boon changes hands', side === 'to'
        ? `${old.to_name} passed the ${level} boon owed by ${old.from_name} to ${party}.`
        : `The ${level} boon ${old.from_name} owed ${old.to_name} now falls on ${party}.`);
      reply.send({ boon });
    } catch (e) {
      log.err('Failed to transfer boon', { message: e.message });
      reply.status(500).send({ error: 'Failed to transfer boon' });
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
      reply.status(500).send({ error: 'Failed to delete boon' });
    }
  });

  // --- ADMIN NEW FEATURES ---
  fastify.get('/api/admin/boons', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [boons] = await pool.query(`${BOON_SELECT_SQL} ORDER BY b.created_at DESC`);
      reply.send({ boons });
    } catch (e) {
      log.err('Admin boons fetch failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to fetch boons' });
    }
  });
};
