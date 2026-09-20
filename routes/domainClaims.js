// routes/domainClaims.js
//
// Domain claims on the Athens map: player requests, Court adjudication,
// safety ratings, and the player-contributed codex.

const { isDomainManager, requireDomainManager, listDomainManagers } = require('../services/domainManagers');

// Falls back to this whenever a division is first given an owner without an
// explicit colour (a bare petition approval, or a Steward assign with the
// colour field left untouched) -- a plain, readable blue rather than the old
// fully-random hex, which could land on anything from a muddy brown to a
// colour indistinguishable from another division already on the map.
const DEFAULT_CLAIM_COLOR = '#3b82f6';

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, sendPushNotification } = opts;

  /* -------------------- Domain Claims -------------------- */
  /** List all claims (public for logged-in users) */
  fastify.get('/api/domain-claims', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
      SELECT d.division, d.owner_name, d.color, d.owner_character_id, d.owner_npc_id, d.is_abaton, d.claimed_at, d.safety_rating,
             d.previous_owner_name, d.previous_owner_character_id, d.previous_claimed_at, c.user_id,
             c.name AS character_name, c.clan AS character_clan, c.camarilla_titles AS character_titles,
             n.name AS npc_name, n.clan AS npc_clan, n.camarilla_titles AS npc_titles,
             ((u.avatar_url IS NOT NULL OR u.avatar_url_thumb IS NOT NULL) OR (n.avatar_url IS NOT NULL OR n.avatar_url_thumb IS NOT NULL)) AS has_avatar
      FROM domain_claims d
      LEFT JOIN characters c ON d.owner_character_id = c.id
      LEFT JOIN users u ON c.user_id = u.id
      LEFT JOIN npcs n ON d.owner_npc_id = n.id
    `);
      // owner_name is a legacy free-text snapshot that can drift from the linked
      // character/npc's real (possibly renamed) name — always prefer the live
      // joined name so the UI never shows two different names for one owner.
      const claims = rows.map(r => {
        let titles = r.character_titles || r.npc_titles || null;
        if (typeof titles === 'string') { try { titles = JSON.parse(titles); } catch { titles = null; } }
        return {
          ...r,
          live_name: r.character_name || r.npc_name || null,
          clan: r.character_clan || r.npc_clan || null,
          titles: Array.isArray(titles) ? titles : [],
          has_avatar: !!r.has_avatar,
        };
      });
      reply.send({ claims });
    } catch (err) {
      console.error('[Error] GET /api/domain-claims:', err);
      reply.status(500).json({ error: 'Database error fetching claims', details: err.message });
    }
  });

  /** Claim a division by number with a hex color (first come first served) */
  fastify.post('/api/domain-claims/claim', { preHandler: [authRequired] }, async (req, reply) => {
  const { division, color } = req.body;
    const hex = (color || '').trim();
    if (!Number.isInteger(division)) {
      return reply.status(400).json({ error: 'division must be an integer' });
    }
    if (!/^#([0-9a-fA-F]{6})$/.test(hex)) {
      return reply.status(400).json({ error: 'color must be a 6-digit hex like #ff0066' });
    }

    // find caller’s character (optional owner_character_id)
    const [chars] = await pool.query('SELECT id, name FROM characters WHERE user_id=?', [req.user.id]);
    const myChar = chars[0] || null;
    const ownerName = myChar?.name || req.user.display_name || req.user.email;

    // is it already claimed?
    const [exists] = await pool.query('SELECT division FROM domain_claims WHERE division=?', [division]);
    if (exists.length) {
      return reply.status(409).json({ error: 'This division is already claimed.' });
    }

    await pool.query(
      'INSERT INTO domain_claims (division, owner_character_id, owner_name, color) VALUES (?,?,?,?)',
      [division, myChar?.id || null, ownerName, hex]
    );

    const [row] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [division]);
    reply.send({ claim: row[0] });
  });

  /** Domain owner (their linked character), or a Domain Steward/admin: change
   *  a CLAIMED division's own colour. Uses the identical permission check as
   *  guest management (resolveDomainManager, defined below) — both are the
   *  same "day-to-day control of my territory" authority, just for different
   *  fields. An NPC-owned division has no logged-in owner to grant this to,
   *  so only a Steward/admin can recolour those. */
  fastify.patch('/api/domain-claims/:division/color', { preHandler: [authRequired] }, async (req, reply) => {
    const division = Number(req.params.division);
    if (!Number.isInteger(division)) return reply.status(400).json({ error: 'division must be an integer' });

    const hex = (req.body?.color || '').trim();
    if (!/^#([0-9a-fA-F]{6})$/.test(hex)) {
      return reply.status(400).json({ error: 'color must be a 6-digit hex like #ff0066' });
    }

    try {
      const [[claim]] = await pool.query(
        'SELECT owner_character_id, owner_npc_id FROM domain_claims WHERE division=?',
        [division]
      );
      if (!claim || (!claim.owner_character_id && !claim.owner_npc_id)) {
        return reply.status(409).json({ error: 'Only a claimed domain has a colour to change' });
      }
      if (!(await resolveDomainManager(req, division))) {
        return reply.status(403).json({ error: 'Only the domain\'s owner or a Domain Steward can change its colour' });
      }

      await pool.query('UPDATE domain_claims SET color=? WHERE division=?', [hex, division]);
      const [updated] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [division]);
      log.dom('Domain colour changed', { division, color: hex, by: req.user.id });
      reply.send({ claim: updated[0] });
    } catch (err) {
      log.err('PATCH /api/domain-claims/:division/color failed', { error: err.message });
      reply.status(500).json({ error: 'Database error updating colour' });
    }
  });

  // --- Admin: override/transfer a claim (safe upsert) ---
  fastify.patch('/api/admin/domain-claims/:division', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const division = Number(req.params.division);
  const { owner_name, color, owner_character_id, owner_npc_id, is_abaton } = req.body;

    const fields = [];
    const vals = [];

    if (typeof owner_name === 'string' && owner_name.trim()) { fields.push('owner_name=?'); vals.push(owner_name.trim()); }
    if (typeof color === 'string') {
      if (!/^#([0-9a-fA-F]{6})$/.test(color)) return reply.status(400).json({ error: 'color must be #RRGGBB' });
      fields.push('color=?'); vals.push(color);
    }
    if (owner_character_id === null) {
      fields.push('owner_character_id=NULL');
    } else if (owner_character_id !== undefined) {
      if (!Number.isInteger(owner_character_id)) return reply.status(400).json({ error: 'owner_character_id must be integer or null' });
      fields.push('owner_character_id=?'); vals.push(owner_character_id);
      fields.push('owner_npc_id=NULL'); // mutual exclusivity
    }
    if (owner_npc_id === null) {
      fields.push('owner_npc_id=NULL');
    } else if (owner_npc_id !== undefined) {
      if (!Number.isInteger(owner_npc_id)) return reply.status(400).json({ error: 'owner_npc_id must be integer or null' });
      fields.push('owner_npc_id=?'); vals.push(owner_npc_id);
      fields.push('owner_character_id=NULL'); // mutual exclusivity
    }
    if (is_abaton !== undefined) {
      fields.push('is_abaton=?'); vals.push(is_abaton ? 1 : 0);
    }

    if (!fields.length) return reply.status(400).json({ error: 'Nothing to update' });

    // 1) Try update existing
    vals.push(division);
    const [upd] = await pool.query(`UPDATE domain_claims SET ${fields.join(', ')} WHERE division=?`, vals);

    if (upd.affectedRows === 0) {
      // 2) Insert new with provided fields merged onto sensible defaults
      const base = {
        owner_name: (typeof owner_name === 'string' && owner_name.trim()) ? owner_name.trim() : 'Admin Set',
        color: (typeof color === 'string') ? color : '#888888',
        owner_character_id: (owner_character_id === null || owner_character_id === undefined) ? null : Number(owner_character_id),
        owner_npc_id: (owner_npc_id === null || owner_npc_id === undefined) ? null : Number(owner_npc_id),
        is_abaton: is_abaton ? 1 : 0
      };
      await pool.query(
        'INSERT INTO domain_claims (division, owner_name, color, owner_character_id, owner_npc_id, is_abaton) VALUES (?,?,?,?,?,?)',
        [division, base.owner_name, base.color, base.owner_character_id, base.owner_npc_id, base.is_abaton]
      );
    }

    const [row] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [division]);
    log.adm('Domain claim upsert', { division });
    reply.send({ claim: row[0] });
  });


  /** Admin: unclaim (delete) */
  fastify.delete('/api/admin/domain-claims/:division', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const division = Number(req.params.division);
    await pool.query('DELETE FROM domain_claims WHERE division=?', [division]);
    reply.send({ ok: true });
  });

  /* -------------------- Domain Stewards (who may run the map) -------------------- */

  /** Any logged-in user: the roster of Domain Stewards, and whether *I* am one.
   *  The dossier "Requests" tab shows this list read-only. */
  fastify.get('/api/domain-claims/managers', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const managers = await listDomainManagers();
      reply.send({
        managers,
        me: {
          isAdmin: req.user.role === 'admin',
          canManageDomains: await isDomainManager(req.user.id, req.user.role),
        },
      });
    } catch (err) {
      log.err('GET /api/domain-claims/managers failed', { error: err.message });
      reply.status(500).json({ error: 'Database error fetching Domain Stewards' });
    }
  });

  /** Admin only: add a Domain Steward. */
  fastify.post('/api/domain-claims/managers', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const userId = Number(req.body?.user_id);
    if (!Number.isInteger(userId)) return reply.status(400).json({ error: 'user_id (int) is required' });
    try {
      const [[u]] = await pool.query('SELECT id FROM users WHERE id=?', [userId]);
      if (!u) return reply.status(404).json({ error: 'User not found' });
      await pool.query(
        'INSERT IGNORE INTO domain_manager_grants (user_id, granted_by) VALUES (?,?)',
        [userId, req.user.id],
      );
      log.adm('Domain Steward added', { user_id: userId, by: req.user.id });
      reply.send({ ok: true, managers: await listDomainManagers() });
    } catch (err) {
      log.err('POST /api/domain-claims/managers failed', { error: err.message });
      reply.status(500).json({ error: 'Database error adding Domain Steward' });
    }
  });

  /** Admin only: remove a Domain Steward. */
  fastify.delete('/api/domain-claims/managers/:userId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const userId = Number(req.params.userId);
    if (!Number.isInteger(userId)) return reply.status(400).json({ error: 'bad user id' });
    try {
      await pool.query('DELETE FROM domain_manager_grants WHERE user_id=?', [userId]);
      log.adm('Domain Steward removed', { user_id: userId, by: req.user.id });
      reply.send({ ok: true, managers: await listDomainManagers() });
    } catch (err) {
      log.err('DELETE /api/domain-claims/managers/:userId failed', { error: err.message });
      reply.status(500).json({ error: 'Database error removing Domain Steward' });
    }
  });

  /* -------------------- Domain Claim Requests -------------------- */

  /** Public (any logged-in user): pending + recently-resolved requests across all divisions */
  fastify.get('/api/domain-claims/requests', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
      SELECT r.id, r.division, r.status, r.message, r.color, r.created_at, r.resolved_at,
             r.user_id, u.display_name AS requester_name,
             r.character_id, c.name AS character_name
      FROM domain_claim_requests r
      JOIN users u ON u.id = r.user_id
      JOIN characters c ON c.id = r.character_id
      WHERE r.status = 'pending' OR r.resolved_at >= (NOW() - INTERVAL 7 DAY)
      ORDER BY r.created_at DESC
    `);
      reply.send({ requests: rows });
    } catch (err) {
      log.err('GET /api/domain-claims/requests failed', { error: err.message });
      reply.status(500).json({ error: 'Database error fetching requests' });
    }
  });

  /** Player: request an unclaimed division */
  fastify.post('/api/domain-claims/:division/request', { preHandler: [authRequired] }, async (req, reply) => {
    const division = Number(req.params.division);
    if (!Number.isInteger(division)) {
      return reply.status(400).json({ error: 'division must be an integer' });
    }

  const { message, color } = req.body || {};
    let hex = null;
    if (typeof color === 'string' && color.trim()) {
      if (!/^#([0-9a-fA-F]{6})$/.test(color.trim())) {
        return reply.status(400).json({ error: 'color must be a 6-digit hex like #ff0066' });
      }
      hex = color.trim();
    }
    if (typeof message === 'string' && message.length > 500) {
      return reply.status(400).json({ error: 'message must be 500 characters or fewer' });
    }

    try {
      const [chars] = await pool.query('SELECT id, name FROM characters WHERE user_id=?', [req.user.id]);
      const myChar = chars[0];
      if (!myChar) return reply.status(400).json({ error: 'Create a character first' });

      const [[existingClaim]] = await pool.query(
        'SELECT owner_character_id, owner_npc_id, owner_name, is_abaton FROM domain_claims WHERE division=?',
        [division]
      );
      // owner_name can be set on its own (staff assigning an informal NPC
      // owner with no linked characters/npcs row) — that still counts as
      // claimed, same as owner_character_id/owner_npc_id/is_abaton.
      if (existingClaim && (existingClaim.owner_character_id || existingClaim.owner_npc_id || existingClaim.is_abaton || (existingClaim.owner_name && existingClaim.owner_name.trim()))) {
        return reply.status(409).json({ error: 'This division is already claimed.' });
      }

      const [[dupe]] = await pool.query(
        "SELECT id FROM domain_claim_requests WHERE division=? AND user_id=? AND status='pending'",
        [division, req.user.id]
      );
      if (dupe) return reply.status(409).json({ error: 'You already have a pending request for this division.' });

      const [ins] = await pool.query(
        'INSERT INTO domain_claim_requests (division, user_id, character_id, message, color) VALUES (?,?,?,?,?)',
        [division, req.user.id, myChar.id, (typeof message === 'string' && message.trim()) ? message.trim() : null, hex]
      );

      const [row] = await pool.query('SELECT * FROM domain_claim_requests WHERE id=?', [ins.insertId]);
      log.dom('Domain claim requested', { division, user_id: req.user.id, request_id: ins.insertId });
      reply.send({ request: row[0] });
    } catch (err) {
      log.err('POST /api/domain-claims/:division/request failed', { error: err.message });
      reply.status(500).json({ error: 'Database error creating request' });
    }
  });

  /** Domain Steward / admin: approve or reject a pending request */
  fastify.post('/api/domain-claims/requests/:requestId/:action', { preHandler: [authRequired, requireDomainManager] }, async (req, reply) => {
  const { requestId, action } = req.params;
    if (action !== 'approve' && action !== 'reject') {
      return reply.status(400).json({ error: 'action must be approve or reject' });
    }

    try {
      const [[request]] = await pool.query('SELECT * FROM domain_claim_requests WHERE id=?', [requestId]);
      if (!request) return reply.status(404).json({ error: 'Request not found' });
      if (request.status !== 'pending') return reply.status(409).json({ error: `Request already ${request.status}` });

      if (action === 'reject') {
        await pool.query(
          "UPDATE domain_claim_requests SET status='rejected', resolved_at=NOW(), resolved_by=? WHERE id=?",
          [req.user.id, requestId]
        );
        await sendPushNotification(
          request.user_id,
          '❌ Domain Request Denied',
          'The Court has denied your request for this territory.',
          {}, 'court'
        ).catch(() => { });
        log.adm('Domain claim request rejected', { admin: req.user.id, request_id: request.id, division: request.division });
        return reply.send({ success: true });
      }

      // approve — re-check the division is still free (race guard)
      const [[stillOpen]] = await pool.query(
        "SELECT division FROM domain_claims WHERE division=? AND (owner_character_id IS NOT NULL OR owner_npc_id IS NOT NULL OR is_abaton=1 OR (owner_name IS NOT NULL AND TRIM(owner_name) <> ''))",
        [request.division]
      );
      if (stillOpen) {
        await pool.query(
          "UPDATE domain_claim_requests SET status='rejected', resolved_at=NOW(), resolved_by=? WHERE id=?",
          [req.user.id, requestId]
        );
        return reply.status(409).json({ error: 'This division was claimed before the request could be approved.' });
      }

      const [chars] = await pool.query('SELECT name FROM characters WHERE id=?', [request.character_id]);
      const ownerName = chars[0]?.name || 'Unknown';
      const color = request.color || DEFAULT_CLAIM_COLOR;

      const [existingRow] = await pool.query('SELECT division FROM domain_claims WHERE division=?', [request.division]);
      if (existingRow.length) {
        await pool.query(
          'UPDATE domain_claims SET owner_character_id=?, owner_npc_id=NULL, owner_name=?, color=?, claimed_at=NOW(), is_abaton=0 WHERE division=?',
          [request.character_id, ownerName, color, request.division]
        );
      } else {
        // safety_rating starts NULL (Unknown) rather than the column's default
        // of 10 — a brand-new claim on virgin territory hasn't been vetted by
        // the Court yet, so it shouldn't silently read as "Secure".
        await pool.query(
          'INSERT INTO domain_claims (division, owner_character_id, owner_name, color, safety_rating) VALUES (?,?,?,?,NULL)',
          [request.division, request.character_id, ownerName, color]
        );
      }

      await pool.query(
        "UPDATE domain_claim_requests SET status='approved', resolved_at=NOW(), resolved_by=? WHERE id=?",
        [req.user.id, requestId]
      );

      const [others] = await pool.query(
        "SELECT id, user_id FROM domain_claim_requests WHERE division=? AND status='pending' AND id<>?",
        [request.division, requestId]
      );
      if (others.length) {
        await pool.query(
          "UPDATE domain_claim_requests SET status='rejected', resolved_at=NOW(), resolved_by=? WHERE division=? AND status='pending' AND id<>?",
          [req.user.id, request.division, requestId]
        );
      }

      await sendPushNotification(
        request.user_id,
        '🏰 Domain Request Approved',
        `The Court has granted you dominion over Division ${request.division}.`,
        {}, 'court'
      ).catch(() => { });
      for (const other of others) {
        await sendPushNotification(
          other.user_id,
          '❌ Domain Request Denied',
          'Another Kindred was granted this territory before your request could be approved.',
          {}, 'court'
        ).catch(() => { });
      }

      const [row] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [request.division]);
      log.adm('Domain claim request approved', { admin: req.user.id, request_id: request.id, division: request.division });
      reply.send({ success: true, claim: row[0] });
    } catch (err) {
      log.err('POST /api/domain-claims/requests/:requestId/:action failed', { error: err.message });
      reply.status(500).json({ error: 'Database error resolving request' });
    }
  });

  /* -------------------- Steward-Level Domain Assignment -------------------- */

  /** Domain Steward / admin: list active characters + non-disabled NPCs for the assign dropdowns */
  fastify.get('/api/court/characters-and-npcs', { preHandler: [authRequired, requireDomainManager] }, async (req, reply) => {
    try {
      const [characters] = await pool.query(
        `SELECT c.id, c.name, c.clan, u.display_name AS player_name
       FROM characters c
       JOIN users u ON u.id = c.user_id
       ORDER BY c.name ASC`
      );
      const [npcs] = await pool.query(
        `SELECT id, name, clan
       FROM npcs
       WHERE (is_disabled IS NULL OR is_disabled = 0)
         AND (is_deceased IS NULL OR is_deceased = 0)
       ORDER BY name ASC`
      );
      reply.send({ characters, npcs });
    } catch (err) {
      log.err('GET /api/court/characters-and-npcs failed', { error: err.message });
      reply.status(500).send({ error: 'Database error fetching assignables' });
    }
  });

  /** Domain Steward / admin: directly assign a division to a character or NPC, or unassign it */
  fastify.post('/api/court/domain-claims/:division/assign', { preHandler: [authRequired, requireDomainManager] }, async (req, reply) => {
    const division = Number(req.params.division);
    if (!Number.isInteger(division)) {
      return reply.status(400).send({ error: 'division must be an integer' });
    }

  const { character_id, npc_id, color, unassign } = req.body || {};

    try {
      if (unassign) {
        // ── Unassign: preserve previous owner history, same as vacate ──
        const [[row]] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [division]);
        if (!row) return reply.status(404).send({ error: 'Division has no claim to unassign' });
        if (!row.owner_character_id && !row.owner_npc_id && !row.is_abaton && !(row.owner_name && row.owner_name.trim())) {
          return reply.status(409).send({ error: 'Division is already unclaimed' });
        }
        await pool.query(
          `UPDATE domain_claims
         SET previous_owner_name=?, previous_owner_character_id=?, previous_claimed_at=?,
             owner_character_id=NULL, owner_npc_id=NULL, owner_name=NULL, color='#888888', is_abaton=0
         WHERE division=?`,
          [row.owner_name, row.owner_character_id, row.claimed_at, division]
        );
        const [updated] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [division]);
        log.adm('Court unassigned domain', { court_user: req.user.id, division });
        return reply.send({ claim: updated[0] });
      }

      // ── Assign ──
      if (character_id != null && npc_id != null) {
        return reply.status(400).send({ error: 'Provide character_id OR npc_id, not both' });
      }
      if (character_id == null && npc_id == null) {
        return reply.status(400).send({ error: 'Provide character_id or npc_id, or set unassign: true' });
      }

      let ownerName = null;
      let assignCharId = null;
      let assignNpcId = null;

      if (character_id != null) {
        const cid = Number(character_id);
        if (!Number.isInteger(cid)) return reply.status(400).send({ error: 'character_id must be an integer' });
        const [[ch]] = await pool.query('SELECT id, name FROM characters WHERE id=?', [cid]);
        if (!ch) return reply.status(404).send({ error: 'Character not found' });
        assignCharId = cid;
        ownerName = ch.name;
      } else {
        const nid = Number(npc_id);
        if (!Number.isInteger(nid)) return reply.status(400).send({ error: 'npc_id must be an integer' });
        const [[npc]] = await pool.query('SELECT id, name FROM npcs WHERE id=?', [nid]);
        if (!npc) return reply.status(404).send({ error: 'NPC not found' });
        assignNpcId = nid;
        ownerName = npc.name;
      }

      let hex = color;
      if (typeof hex !== 'string' || !/^#([0-9a-fA-F]{6})$/.test(hex.trim())) {
        hex = DEFAULT_CLAIM_COLOR;
      }

      const [existingRow] = await pool.query('SELECT division FROM domain_claims WHERE division=?', [division]);
      if (existingRow.length) {
        await pool.query(
          `UPDATE domain_claims
         SET owner_character_id=?, owner_npc_id=?, owner_name=?, color=?, claimed_at=NOW(), is_abaton=0
         WHERE division=?`,
          [assignCharId, assignNpcId, ownerName, hex, division]
        );
      } else {
        await pool.query(
          'INSERT INTO domain_claims (division, owner_character_id, owner_npc_id, owner_name, color, safety_rating) VALUES (?,?,?,?,?,NULL)',
          [division, assignCharId, assignNpcId, ownerName, hex]
        );
      }

      const [row] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [division]);
      log.adm('Court assigned domain', { court_user: req.user.id, division, ownerName });
      reply.send({ claim: row[0] });
    } catch (err) {
      log.err('POST /api/court/domain-claims/:division/assign failed', { error: err.message });
      reply.status(500).send({ error: 'Database error assigning domain' });
    }
  });

  /** Domain Steward / admin: release a claimed division back to Unclaimed, preserving the previous owner */
  fastify.post('/api/admin/domain-claims/:division/vacate', { preHandler: [authRequired, requireDomainManager] }, async (req, reply) => {
    const division = Number(req.params.division);
    try {
      const [[row]] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [division]);
      if (!row) return reply.status(404).json({ error: 'Division has no claim to vacate' });
      if (!row.owner_character_id && !row.owner_npc_id && !row.is_abaton && !(row.owner_name && row.owner_name.trim())) {
        return reply.status(409).json({ error: 'Division is already unclaimed' });
      }

      await pool.query(
        `UPDATE domain_claims
       SET previous_owner_name=?, previous_owner_character_id=?, previous_claimed_at=?,
           owner_character_id=NULL, owner_npc_id=NULL, owner_name=NULL, color='#888888', is_abaton=0
       WHERE division=?`,
        [row.owner_name, row.owner_character_id, row.claimed_at, division]
      );

      const [updated] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [division]);
      log.adm('Domain vacated', { admin: req.user.id, division });
      reply.send({ claim: updated[0] });
    } catch (err) {
      log.err('POST /api/admin/domain-claims/:division/vacate failed', { error: err.message });
      reply.status(500).json({ error: 'Database error vacating division' });
    }
  });

  /** Domain Steward / admin: incident log for a division (Storyteller-facing) */
  fastify.get('/api/domain-claims/:division/problems', { preHandler: [authRequired, requireDomainManager] }, async (req, reply) => {
    const division = Number(req.params.division);
    try {
      const [problems] = await pool.query(
        'SELECT * FROM domain_problems WHERE domain_id=? ORDER BY created_at DESC',
        [division]
      );
      reply.send({ problems });
    } catch (err) {
      log.err('GET /api/domain-claims/:division/problems failed', { error: err.message });
      reply.status(500).json({ error: 'Database error fetching incident log' });
    }
  });

  /** Court/admin: set (or clear, via null) a division's Masquerade safety rating */
  fastify.patch('/api/domain-claims/:division/safety', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const division = Number(req.params.division);
    if (!Number.isInteger(division)) return reply.status(400).json({ error: 'division must be an integer' });

  const { safety_rating } = req.body || {};
    if (safety_rating !== null && (!Number.isInteger(safety_rating) || safety_rating < 0 || safety_rating > 10)) {
      return reply.status(400).json({ error: 'safety_rating must be an integer 0-10, or null for Unknown' });
    }

    try {
      const [existing] = await pool.query('SELECT division FROM domain_claims WHERE division=?', [division]);
      if (existing.length) {
        await pool.query('UPDATE domain_claims SET safety_rating=? WHERE division=?', [safety_rating, division]);
      } else {
        // No claim history yet for this division — create a bare row just to
        // hold the Court's assessment. owner fields stay NULL, so every
        // "is this claimed?" check (which looks at owner_character_id /
        // owner_npc_id / is_abaton, never row existence) still reads it as
        // unclaimed and requestable.
        await pool.query(
          'INSERT INTO domain_claims (division, owner_name, color, safety_rating) VALUES (?, NULL, ?, ?)',
          [division, '#888888', safety_rating]
        );
      }
      const [row] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [division]);
      log.adm('Domain safety rating changed', { user: req.user.id, division, safety_rating });
      reply.send({ claim: row[0] });
    } catch (err) {
      log.err('PATCH /api/domain-claims/:division/safety failed', { error: err.message });
      reply.status(500).json({ error: 'Database error updating safety rating' });
    }
  });

  /* -------------------- Domain Guests (hospitality, beyond the owner) -------------------- */

  /** Any logged-in user: characters + non-disabled NPCs for the guest picker.
   *  Same shape as /api/court/characters-and-npcs but open to every player —
   *  extending hospitality is the domain owner's call, not a Steward power.
   *  Excludes anyone who already owns a division: a guest slot is for someone
   *  WITHOUT their own territory, not a second address for an existing owner. */
  fastify.get('/api/domain-claims/roster', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [characters] = await pool.query(
        `SELECT c.id, c.name, c.clan, u.display_name AS player_name
       FROM characters c
       JOIN users u ON u.id = c.user_id
       WHERE c.id NOT IN (SELECT owner_character_id FROM domain_claims WHERE owner_character_id IS NOT NULL)
       ORDER BY c.name ASC`
      );
      const [npcs] = await pool.query(
        `SELECT id, name, clan
       FROM npcs
       WHERE (is_disabled IS NULL OR is_disabled = 0)
         AND (is_deceased IS NULL OR is_deceased = 0)
         AND id NOT IN (SELECT owner_npc_id FROM domain_claims WHERE owner_npc_id IS NOT NULL)
       ORDER BY name ASC`
      );
      reply.send({ characters, npcs });
    } catch (err) {
      log.err('GET /api/domain-claims/roster failed', { error: err.message });
      reply.status(500).send({ error: 'Database error fetching roster' });
    }
  });

  /** Any logged-in user: every guest across every division in one query — the
   *  map needs this for all claimed divisions at once, not just the one
   *  currently open in the dossier, so it can't reuse the per-division route. */
  fastify.get('/api/domain-claims/guests', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
        SELECT g.id, g.division, g.note, g.character_id, g.npc_id,
               c.name AS character_name, c.clan AS character_clan, c.user_id AS character_user_id,
               ((cu.avatar_url IS NOT NULL OR cu.avatar_url_thumb IS NOT NULL)) AS char_has_avatar,
               n.name AS npc_name, n.clan AS npc_clan,
               ((n.avatar_url IS NOT NULL OR n.avatar_url_thumb IS NOT NULL)) AS npc_has_avatar
        FROM domain_guests g
        LEFT JOIN characters c ON c.id = g.character_id
        LEFT JOIN users cu ON cu.id = c.user_id
        LEFT JOIN npcs n ON n.id = g.npc_id
        ORDER BY g.division, g.created_at ASC
      `);
      const guests = rows.map(r => ({
        id: r.id,
        division: r.division,
        note: r.note,
        character_id: r.character_id,
        npc_id: r.npc_id,
        user_id: r.character_user_id || null,
        name: r.character_name || r.npc_name || 'Unknown',
        clan: r.character_clan || r.npc_clan || null,
        isNpc: !!r.npc_id,
        has_avatar: !!(r.char_has_avatar || r.npc_has_avatar),
      }));
      reply.send({ guests });
    } catch (err) {
      log.err('GET /api/domain-claims/guests failed', { error: err.message });
      reply.status(500).json({ error: 'Database error fetching guests' });
    }
  });

  // Domain owner (their linked character) OR a Domain Steward/admin: the same
  // check gates both who's hosted in a division AND the division's own colour,
  // so it's centralised here rather than duplicated per feature.
  async function resolveDomainManager(req, division) {
    if (await isDomainManager(req.user.id, req.user.role)) return true;
    const [[claim]] = await pool.query('SELECT owner_character_id FROM domain_claims WHERE division=?', [division]);
    if (!claim || !claim.owner_character_id) return false;
    const [[owner]] = await pool.query('SELECT user_id FROM characters WHERE id=?', [claim.owner_character_id]);
    return !!owner && owner.user_id === req.user.id;
  }

  /** Anyone logged in can see who's being hosted in a division. */
  fastify.get('/api/domain-claims/:division/guests', { preHandler: [authRequired] }, async (req, reply) => {
    const division = Number(req.params.division);
    if (!Number.isInteger(division)) return reply.status(400).json({ error: 'division must be an integer' });
    try {
      const [rows] = await pool.query(`
        SELECT g.id, g.division, g.note, g.created_at, g.character_id, g.npc_id,
               c.name AS character_name, c.clan AS character_clan, cu.id AS character_user_id,
               n.name AS npc_name, n.clan AS npc_clan
        FROM domain_guests g
        LEFT JOIN characters c ON c.id = g.character_id
        LEFT JOIN users cu ON cu.id = c.user_id
        LEFT JOIN npcs n ON n.id = g.npc_id
        WHERE g.division = ?
        ORDER BY g.created_at ASC
      `, [division]);
      const guests = rows.map(r => ({
        id: r.id,
        division: r.division,
        note: r.note,
        created_at: r.created_at,
        character_id: r.character_id,
        npc_id: r.npc_id,
        name: r.character_name || r.npc_name || 'Unknown',
        clan: r.character_clan || r.npc_clan || null,
        isNpc: !!r.npc_id,
        // lets a guest recognise (and later remove) their own entry
        isSelf: !!(r.character_user_id && r.character_user_id === req.user.id),
      }));
      const canManage = await resolveDomainManager(req, division);
      reply.send({ guests, me: { canManage } });
    } catch (err) {
      log.err('GET /api/domain-claims/:division/guests failed', { error: err.message });
      reply.status(500).json({ error: 'Database error fetching guests' });
    }
  });

  /** Domain owner or Steward/admin: declare a character or NPC as hosted here. */
  fastify.post('/api/domain-claims/:division/guests', { preHandler: [authRequired] }, async (req, reply) => {
    const division = Number(req.params.division);
    if (!Number.isInteger(division)) return reply.status(400).json({ error: 'division must be an integer' });

    const { character_id, npc_id, note } = req.body || {};
    if (character_id != null && npc_id != null) {
      return reply.status(400).json({ error: 'Provide character_id OR npc_id, not both' });
    }
    if (character_id == null && npc_id == null) {
      return reply.status(400).json({ error: 'Provide character_id or npc_id' });
    }
    if (typeof note === 'string' && note.length > 255) {
      return reply.status(400).json({ error: 'note must be 255 characters or fewer' });
    }

    try {
      const [[claim]] = await pool.query(
        'SELECT owner_character_id, owner_npc_id, is_abaton FROM domain_claims WHERE division=?',
        [division]
      );
      if (!claim || (!claim.owner_character_id && !claim.owner_npc_id && !claim.is_abaton)) {
        return reply.status(409).json({ error: 'Only a claimed domain can host guests' });
      }
      if (!(await resolveDomainManager(req, division))) {
        return reply.status(403).json({ error: 'Only the domain\'s owner or a Domain Steward can add guests' });
      }

      let charId = null, npcId = null;
      if (character_id != null) {
        const cid = Number(character_id);
        if (!Number.isInteger(cid)) return reply.status(400).json({ error: 'character_id must be an integer' });
        const [[ch]] = await pool.query('SELECT id FROM characters WHERE id=?', [cid]);
        if (!ch) return reply.status(404).json({ error: 'Character not found' });
        charId = cid;
      } else {
        const nid = Number(npc_id);
        if (!Number.isInteger(nid)) return reply.status(400).json({ error: 'npc_id must be an integer' });
        const [[npc]] = await pool.query('SELECT id FROM npcs WHERE id=?', [nid]);
        if (!npc) return reply.status(404).json({ error: 'NPC not found' });
        npcId = nid;
      }

      // Re-checked here, not just filtered out of the roster: the roster is a
      // snapshot the client can hold onto for a while, so a character/NPC could
      // have claimed a division of their own between the picker loading and
      // this submit landing. A guest slot is for someone without a territory.
      const [[ownsDivision]] = await pool.query(
        charId != null
          ? 'SELECT division FROM domain_claims WHERE owner_character_id=?'
          : 'SELECT division FROM domain_claims WHERE owner_npc_id=?',
        [charId != null ? charId : npcId]
      );
      if (ownsDivision) {
        return reply.status(409).json({ error: (charId != null ? 'This character' : 'This NPC') + ' already owns a domain and cannot be added as a guest' });
      }

      const [[dupe]] = await pool.query(
        'SELECT id FROM domain_guests WHERE division=? AND character_id <=> ? AND npc_id <=> ?',
        [division, charId, npcId]
      );
      if (dupe) return reply.status(409).json({ error: 'Already listed as a guest of this domain' });

      await pool.query(
        'INSERT INTO domain_guests (division, character_id, npc_id, note, added_by) VALUES (?,?,?,?,?)',
        [division, charId, npcId, (typeof note === 'string' && note.trim()) ? note.trim() : null, req.user.id]
      );
      log.dom('Domain guest added', { division, character_id: charId, npc_id: npcId, by: req.user.id });
      reply.send({ ok: true });
    } catch (err) {
      log.err('POST /api/domain-claims/:division/guests failed', { error: err.message });
      reply.status(500).json({ error: 'Database error adding guest' });
    }
  });

  /** Domain owner, Steward/admin, or the guest themself: remove a guest entry. */
  fastify.delete('/api/domain-claims/:division/guests/:guestId', { preHandler: [authRequired] }, async (req, reply) => {
    const division = Number(req.params.division);
    const guestId = Number(req.params.guestId);
    if (!Number.isInteger(division) || !Number.isInteger(guestId)) {
      return reply.status(400).json({ error: 'bad parameters' });
    }
    try {
      const [[guest]] = await pool.query(
        `SELECT g.id, g.character_id, c.user_id AS character_user_id
         FROM domain_guests g LEFT JOIN characters c ON c.id = g.character_id
         WHERE g.id=? AND g.division=?`,
        [guestId, division]
      );
      if (!guest) return reply.status(404).json({ error: 'Guest entry not found' });

      const isSelf = guest.character_user_id != null && guest.character_user_id === req.user.id;
      if (!isSelf && !(await resolveDomainManager(req, division))) {
        return reply.status(403).json({ error: 'Only the domain\'s owner, a Domain Steward, or the guest themself can remove this' });
      }

      await pool.query('DELETE FROM domain_guests WHERE id=?', [guestId]);
      log.dom('Domain guest removed', { division, guest_id: guestId, by: req.user.id });
      reply.send({ ok: true });
    } catch (err) {
      log.err('DELETE /api/domain-claims/:division/guests/:guestId failed', { error: err.message });
      reply.status(500).json({ error: 'Database error removing guest' });
    }
  });

  /* -------------------- Domain Codex (player-contributed lore) -------------------- */

  /** Anyone logged in can read a division's codex entries */
  fastify.get('/api/domain-claims/:division/codex', { preHandler: [authRequired] }, async (req, reply) => {
    const division = Number(req.params.division);
    try {
      const [entries] = await pool.query(`
      SELECT e.id, e.division, e.text, e.created_at, e.user_id, u.display_name AS author_name,
             e.character_id, c.name AS character_name
      FROM domain_codex_entries e
      JOIN users u ON u.id = e.user_id
      LEFT JOIN characters c ON c.id = e.character_id
      WHERE e.division=?
      ORDER BY e.created_at DESC
    `, [division]);
      reply.send({ entries });
    } catch (err) {
      log.err('GET /api/domain-claims/:division/codex failed', { error: err.message });
      reply.status(500).json({ error: 'Database error fetching codex' });
    }
  });

  /** Anyone logged in can add a codex entry — community lore, not Court-gated */
  fastify.post('/api/domain-claims/:division/codex', { preHandler: [authRequired] }, async (req, reply) => {
    const division = Number(req.params.division);
  const { text } = req.body || {};
    if (!Number.isInteger(division)) return reply.status(400).json({ error: 'division must be an integer' });
    if (typeof text !== 'string' || !text.trim()) return reply.status(400).json({ error: 'text is required' });
    if (text.length > 1000) return reply.status(400).json({ error: 'text must be 1000 characters or fewer' });

    try {
      const [chars] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
      const characterId = chars[0]?.id || null;

      const [ins] = await pool.query(
        'INSERT INTO domain_codex_entries (division, user_id, character_id, text) VALUES (?,?,?,?)',
        [division, req.user.id, characterId, text.trim()]
      );
      const [row] = await pool.query(`
      SELECT e.id, e.division, e.text, e.created_at, e.user_id, u.display_name AS author_name,
             e.character_id, c.name AS character_name
      FROM domain_codex_entries e
      JOIN users u ON u.id = e.user_id
      LEFT JOIN characters c ON c.id = e.character_id
      WHERE e.id=?
    `, [ins.insertId]);
      log.dom('Domain codex entry added', { division, user_id: req.user.id, entry_id: ins.insertId });
      reply.send({ entry: row[0] });
    } catch (err) {
      log.err('POST /api/domain-claims/:division/codex failed', { error: err.message });
      reply.status(500).json({ error: 'Database error adding codex entry' });
    }
  });

  /** Author, Domain Steward, or admin can remove a codex entry */
  fastify.delete('/api/domain-claims/codex/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [[entry]] = await pool.query('SELECT * FROM domain_codex_entries WHERE id=?', [req.params.id]);
      if (!entry) return reply.status(404).json({ error: 'Entry not found' });

      const isAuthor = entry.user_id === req.user.id;
      const canModerate = await isDomainManager(req.user.id, req.user.role);
      if (!isAuthor && !canModerate) return reply.status(403).json({ error: 'Not allowed to delete this entry' });

      await pool.query('DELETE FROM domain_codex_entries WHERE id=?', [req.params.id]);
      log.dom('Domain codex entry deleted', { entry_id: req.params.id, by: req.user.id });
      reply.send({ ok: true });
    } catch (err) {
      log.err('DELETE /api/domain-claims/codex/:id failed', { error: err.message });
      reply.status(500).json({ error: 'Database error deleting codex entry' });
    }
  });
};
