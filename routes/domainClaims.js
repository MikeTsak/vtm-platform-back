// routes/domainClaims.js
//
// Domain claims on the Athens map: player requests, Court adjudication,
// safety ratings, and the player-contributed codex.

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, requireCourt, sendPushNotification } = opts;

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

  /** Court/admin: approve or reject a pending request */
  fastify.post('/api/domain-claims/requests/:requestId/:action', { preHandler: [authRequired, requireCourt] }, async (req, reply) => {
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
      const color = request.color || '#' + Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, '0');

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

  /* -------------------- Court-Level Domain Assignment -------------------- */

  /** Court/admin: list active characters + non-disabled NPCs for the assign dropdowns */
  fastify.get('/api/court/characters-and-npcs', { preHandler: [authRequired, requireCourt] }, async (req, reply) => {
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

  /** Court/admin: directly assign a division to a character or NPC, or unassign it */
  fastify.post('/api/court/domain-claims/:division/assign', { preHandler: [authRequired, requireCourt] }, async (req, reply) => {
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
        hex = '#' + Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, '0');
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

  /** Court/admin: release a claimed division back to Unclaimed, preserving the previous owner */
  fastify.post('/api/admin/domain-claims/:division/vacate', { preHandler: [authRequired, requireCourt] }, async (req, reply) => {
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

  /** Court/admin: incident log for a division (Storyteller-facing) */
  fastify.get('/api/domain-claims/:division/problems', { preHandler: [authRequired, requireCourt] }, async (req, reply) => {
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

  /** Author or Court/admin can remove a codex entry */
  fastify.delete('/api/domain-claims/codex/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [[entry]] = await pool.query('SELECT * FROM domain_codex_entries WHERE id=?', [req.params.id]);
      if (!entry) return reply.status(404).json({ error: 'Entry not found' });

      const isAuthor = entry.user_id === req.user.id;
      const isCourt = req.user.role === 'admin' || req.user.role === 'courtuser';
      if (!isAuthor && !isCourt) return reply.status(403).json({ error: 'Not allowed to delete this entry' });

      await pool.query('DELETE FROM domain_codex_entries WHERE id=?', [req.params.id]);
      log.dom('Domain codex entry deleted', { entry_id: req.params.id, by: req.user.id });
      reply.send({ ok: true });
    } catch (err) {
      log.err('DELETE /api/domain-claims/codex/:id failed', { error: err.message });
      reply.status(500).json({ error: 'Database error deleting codex entry' });
    }
  });
};
