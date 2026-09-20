// routes/domainResidents.js
//
// Temporary resident bookkeeping for UNCLAIMED divisions.
// A resident is a character or NPC physically operating from a division that
// nobody owns yet — not a domain claim, not a guest in someone's territory.
//
// Write access: Domain Stewards and admins only.
// Read access: any logged-in user.
//
// Transition on claim: when a division that has residents gets claimed,
// call `transitionResidentsOnClaim(pool, division, newOwnerId)` from the
// claim/assign paths in domainClaims.js. It converts remaining residents
// to domain_guests and deletes the resident records.

const { requireDomainManager } = require('../services/domainManagers');

// Helper exported for use in domainClaims.js so claim paths can trigger the
// resident→guest conversion without duplicating the query logic here.
async function transitionResidentsOnClaim(pool, division, newOwnerCharacterId, newOwnerNpcId) {
  // 1. Fetch all current residents of this division
  const [residents] = await pool.query(
    'SELECT id, character_id, npc_id, note, added_by FROM domain_residents WHERE division = ?',
    [division]
  );
  if (!residents.length) return;

  // 2. The new owner's own character/npc record is not a "guest" — just remove it.
  const ownIds = [];
  if (newOwnerCharacterId) ownIds.push(newOwnerCharacterId);
  if (newOwnerNpcId) ownIds.push(newOwnerNpcId);

  // 3. Ensure the domain_claims row exists before inserting guests
  //    (the claim row is always written before this function is called, so safe).
  for (const r of residents) {
    const isNewOwner =
      (newOwnerCharacterId && r.character_id === newOwnerCharacterId) ||
      (newOwnerNpcId && r.npc_id === newOwnerNpcId);

    if (!isNewOwner) {
      // Avoid duplicate guest if they somehow already appear there
      const [[dupe]] = await pool.query(
        'SELECT id FROM domain_guests WHERE division = ? AND character_id <=> ? AND npc_id <=> ?',
        [division, r.character_id ?? null, r.npc_id ?? null]
      );
      if (!dupe) {
        await pool.query(
          'INSERT INTO domain_guests (division, character_id, npc_id, note, added_by) VALUES (?,?,?,?,?)',
          [division, r.character_id ?? null, r.npc_id ?? null, r.note ?? null, r.added_by ?? null]
        );
      }
    }
  }

  // 4. Delete all resident records for this division (owner + converted guests)
  await pool.query('DELETE FROM domain_residents WHERE division = ?', [division]);
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  // The same guard used in domainClaims.js for guest management.
  // Residents are a Steward/admin-only feature so we skip the "domain owner
  // can manage their own guests" path entirely — unclaimed divisions have no
  // owner to grant that to.
  async function requireStewardOrAdmin(req, reply) {
    await requireDomainManager(req, reply);
  }

  /* ── GET /api/domain-claims/residents
     All residents, every division — the map loads this once on mount,
     same bulk pattern as /api/domain-claims/guests. */
  fastify.get('/api/domain-claims/residents', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
        SELECT r.id, r.division, r.note, r.character_id, r.npc_id,
               c.name  AS character_name, c.clan AS character_clan, c.user_id AS character_user_id,
               ((cu.avatar_url IS NOT NULL OR cu.avatar_url_thumb IS NOT NULL)) AS char_has_avatar,
               n.name  AS npc_name, n.clan AS npc_clan,
               ((n.avatar_url IS NOT NULL OR n.avatar_url_thumb IS NOT NULL)) AS npc_has_avatar
        FROM domain_residents r
        LEFT JOIN characters c  ON c.id  = r.character_id
        LEFT JOIN users      cu ON cu.id = c.user_id
        LEFT JOIN npcs       n  ON n.id  = r.npc_id
        ORDER BY r.division, r.created_at ASC
      `);
      const residents = rows.map(r => ({
        id:         r.id,
        division:   r.division,
        note:       r.note,
        character_id: r.character_id,
        npc_id:     r.npc_id,
        user_id:    r.character_user_id || null,
        name:       r.character_name || r.npc_name || 'Unknown',
        clan:       r.character_clan  || r.npc_clan  || null,
        isNpc:      !!r.npc_id,
        has_avatar: !!(r.char_has_avatar || r.npc_has_avatar),
      }));
      reply.send({ residents });
    } catch (err) {
      log.err('GET /api/domain-claims/residents failed', { error: err.message });
      reply.status(500).send({ error: 'Database error fetching residents' });
    }
  });

  /* ── GET /api/domain-claims/:division/residents
     Residents of a single division — loaded when the dossier opens. */
  fastify.get('/api/domain-claims/:division/residents', { preHandler: [authRequired] }, async (req, reply) => {
    const division = Number(req.params.division);
    if (!Number.isInteger(division)) return reply.status(400).send({ error: 'division must be an integer' });
    try {
      const [rows] = await pool.query(`
        SELECT r.id, r.division, r.note, r.created_at, r.character_id, r.npc_id,
               c.name  AS character_name, c.clan AS character_clan, cu.id AS character_user_id,
               n.name  AS npc_name, n.clan AS npc_clan
        FROM domain_residents r
        LEFT JOIN characters c  ON c.id  = r.character_id
        LEFT JOIN users      cu ON cu.id = c.user_id
        LEFT JOIN npcs       n  ON n.id  = r.npc_id
        WHERE r.division = ?
        ORDER BY r.created_at ASC
      `, [division]);
      const residents = rows.map(r => ({
        id:           r.id,
        division:     r.division,
        note:         r.note,
        created_at:   r.created_at,
        character_id: r.character_id,
        npc_id:       r.npc_id,
        name:         r.character_name || r.npc_name || 'Unknown',
        clan:         r.character_clan || r.npc_clan || null,
        isNpc:        !!r.npc_id,
      }));
      reply.send({ residents });
    } catch (err) {
      log.err('GET /api/domain-claims/:division/residents failed', { error: err.message });
      reply.status(500).send({ error: 'Database error fetching residents' });
    }
  });

  /* ── POST /api/domain-claims/:division/residents
     Add a resident. Division must be unclaimed. */
  fastify.post('/api/domain-claims/:division/residents', { preHandler: [authRequired, requireStewardOrAdmin] }, async (req, reply) => {
    const division = Number(req.params.division);
    if (!Number.isInteger(division)) return reply.status(400).send({ error: 'division must be an integer' });

    const { character_id, npc_id, note } = req.body || {};
    if (character_id != null && npc_id != null) {
      return reply.status(400).send({ error: 'Provide character_id OR npc_id, not both' });
    }
    if (character_id == null && npc_id == null) {
      return reply.status(400).send({ error: 'Provide character_id or npc_id' });
    }
    if (typeof note === 'string' && note.length > 255) {
      return reply.status(400).send({ error: 'note must be 255 characters or fewer' });
    }

    try {
      // Division must not be owned
      const [[claim]] = await pool.query(
        'SELECT owner_character_id, owner_npc_id, is_abaton, owner_name FROM domain_claims WHERE division = ?',
        [division]
      );
      const isClaimed = !!(claim && (
        claim.owner_character_id || claim.owner_npc_id || claim.is_abaton ||
        (claim.owner_name && claim.owner_name.trim())
      ));
      if (isClaimed) {
        return reply.status(409).send({ error: 'This division is claimed — use guest management instead' });
      }

      let charId = null, npcId = null;
      if (character_id != null) {
        const cid = Number(character_id);
        if (!Number.isInteger(cid)) return reply.status(400).send({ error: 'character_id must be an integer' });
        const [[ch]] = await pool.query('SELECT id FROM characters WHERE id = ?', [cid]);
        if (!ch) return reply.status(404).send({ error: 'Character not found' });
        charId = cid;
      } else {
        const nid = Number(npc_id);
        if (!Number.isInteger(nid)) return reply.status(400).send({ error: 'npc_id must be an integer' });
        const [[npc]] = await pool.query('SELECT id FROM npcs WHERE id = ?', [nid]);
        if (!npc) return reply.status(404).send({ error: 'NPC not found' });
        npcId = nid;
      }

      // Duplicate check across all domains
      const [[dupeResident]] = await pool.query(
        'SELECT id, division FROM domain_residents WHERE character_id <=> ? AND npc_id <=> ?',
        [charId, npcId]
      );
      if (dupeResident) {
        return reply.status(409).send({ error: (charId != null ? 'This character' : 'This NPC') + ` is already a resident in domain #${dupeResident.division}` });
      }

      const [[dupeGuest]] = await pool.query(
        'SELECT id, division FROM domain_guests WHERE character_id <=> ? AND npc_id <=> ?',
        [charId, npcId]
      );
      if (dupeGuest) {
        return reply.status(409).send({ error: (charId != null ? 'This character' : 'This NPC') + ` is already a guest in domain #${dupeGuest.division}` });
      }

      const [[ownsDivision]] = await pool.query(
        charId != null
          ? 'SELECT division FROM domain_claims WHERE owner_character_id = ?'
          : 'SELECT division FROM domain_claims WHERE owner_npc_id = ?',
        [charId != null ? charId : npcId]
      );
      if (ownsDivision) {
        return reply.status(409).send({ error: (charId != null ? 'This character' : 'This NPC') + ` already owns domain #${ownsDivision.division}` });
      }

      await pool.query(
        'INSERT INTO domain_residents (division, character_id, npc_id, note, added_by) VALUES (?,?,?,?,?)',
        [division, charId, npcId, (typeof note === 'string' && note.trim()) ? note.trim() : null, req.user.id]
      );
      log.dom('Domain resident added', { division, character_id: charId, npc_id: npcId, by: req.user.id });
      reply.send({ ok: true });
    } catch (err) {
      log.err('POST /api/domain-claims/:division/residents failed', { error: err.message });
      reply.status(500).send({ error: 'Database error adding resident' });
    }
  });

  /* ── DELETE /api/domain-claims/:division/residents/:residentId
     Remove a resident. Steward/admin only. */
  fastify.delete('/api/domain-claims/:division/residents/:residentId', { preHandler: [authRequired, requireStewardOrAdmin] }, async (req, reply) => {
    const division   = Number(req.params.division);
    const residentId = Number(req.params.residentId);
    if (!Number.isInteger(division) || !Number.isInteger(residentId)) {
      return reply.status(400).send({ error: 'bad parameters' });
    }
    try {
      const [[row]] = await pool.query('SELECT id FROM domain_residents WHERE id = ? AND division = ?', [residentId, division]);
      if (!row) return reply.status(404).send({ error: 'Resident record not found' });
      await pool.query('DELETE FROM domain_residents WHERE id = ?', [residentId]);
      log.dom('Domain resident removed', { division, resident_id: residentId, by: req.user.id });
      reply.send({ ok: true });
    } catch (err) {
      log.err('DELETE /api/domain-claims/:division/residents/:residentId failed', { error: err.message });
      reply.status(500).send({ error: 'Database error removing resident' });
    }
  });
};

module.exports.transitionResidentsOnClaim = transitionResidentsOnClaim;
