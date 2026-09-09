// routes/disciplineAccess.js
//
// Out-of-clan discipline access. A character can only spend XP on a
// discipline outside their clan (see characterXp.js) once a row exists here
// granting them a level cap for it — either an admin unlocks it directly, or
// a player requests it and an admin approves the request. Mirrors the
// domain_claim_requests workflow in domainClaims.js.

const DISCIPLINE_NAME_MAX = 60;
const MESSAGE_MAX = 500;
const MAX_DISCIPLINE_LEVEL = 5;

function cleanDiscipline(v) {
  const s = String(v || '').trim();
  if (!s || s.length > DISCIPLINE_NAME_MAX) return null;
  return s;
}

function cleanLevel(v) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > MAX_DISCIPLINE_LEVEL) return null;
  return n;
}

function cleanMessage(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  if (!s) return null;
  if (s.length > MESSAGE_MAX) return null;
  return s;
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, sendPushNotification, broadcastNtfyAlert } = opts;

  /* ==================================================================
     Player-facing
     ================================================================== */

  // What this player's own character has been granted, if anything.
  fastify.get('/api/characters/discipline-access', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [[ch]] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
      if (!ch) return reply.send({ access: [] });

      const [rows] = await pool.query(
        'SELECT discipline, max_level, note, granted_at FROM discipline_access WHERE character_id=? ORDER BY discipline',
        [ch.id]
      );
      reply.send({ access: rows });
    } catch (err) {
      log.err('GET /api/characters/discipline-access failed', { error: err.message });
      reply.status(500).json({ error: 'Database error fetching discipline access' });
    }
  });

  // This player's own request history (pending + recently resolved).
  fastify.get('/api/characters/discipline-requests', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(
        `SELECT id, discipline, requested_level, message, status, granted_level, admin_note, created_at, resolved_at
         FROM discipline_requests
         WHERE user_id=? AND (status='pending' OR resolved_at >= (NOW() - INTERVAL 30 DAY))
         ORDER BY created_at DESC`,
        [req.user.id]
      );
      reply.send({ requests: rows });
    } catch (err) {
      log.err('GET /api/characters/discipline-requests failed', { error: err.message });
      reply.status(500).json({ error: 'Database error fetching requests' });
    }
  });

  // Ask an ST for access to a discipline outside the character's clan.
  fastify.post('/api/characters/discipline-requests', { preHandler: [authRequired] }, async (req, reply) => {
    const discipline = cleanDiscipline(req.body?.discipline);
    const requestedLevel = cleanLevel(req.body?.requestedLevel);
    const message = cleanMessage(req.body?.message);

    if (!discipline) return reply.status(400).json({ error: 'discipline is required' });
    if (!requestedLevel) return reply.status(400).json({ error: `requestedLevel must be 1-${MAX_DISCIPLINE_LEVEL}` });

    try {
      const [[ch]] = await pool.query('SELECT id, name FROM characters WHERE user_id=?', [req.user.id]);
      if (!ch) return reply.status(400).json({ error: 'Create a character first' });

      const [[dupe]] = await pool.query(
        "SELECT id FROM discipline_requests WHERE character_id=? AND discipline=? AND status='pending'",
        [ch.id, discipline]
      );
      if (dupe) return reply.status(409).json({ error: `You already have a pending request for ${discipline}.` });

      const [[existing]] = await pool.query(
        'SELECT max_level FROM discipline_access WHERE character_id=? AND discipline=?',
        [ch.id, discipline]
      );
      if (existing && existing.max_level >= requestedLevel) {
        return reply.status(409).json({ error: `You already have access to ${discipline} up to level ${existing.max_level}.` });
      }

      const [ins] = await pool.query(
        'INSERT INTO discipline_requests (character_id, user_id, discipline, requested_level, message) VALUES (?,?,?,?,?)',
        [ch.id, req.user.id, discipline, requestedLevel, message]
      );

      const [[row]] = await pool.query('SELECT * FROM discipline_requests WHERE id=?', [ins.insertId]);
      log.char('Discipline access requested', { user_id: req.user.id, character_id: ch.id, discipline, requestedLevel });
      broadcastNtfyAlert?.(
        `**${ch.name}** is requesting **${discipline}** (up to level ${requestedLevel}).${message ? `\n\n> *${message}*` : ''}`,
        { title: 'Discipline Access Requested', tags: 'sparkles', priority: 'default' }
      );
      reply.send({ request: row });
    } catch (err) {
      log.err('POST /api/characters/discipline-requests failed', { error: err.message });
      reply.status(500).json({ error: 'Database error creating request' });
    }
  });

  /* ==================================================================
     Admin-facing
     ================================================================== */

  // The review queue: every character's grants and every request, joined
  // with names so the admin tab needs exactly one round trip.
  fastify.get('/api/admin/discipline-access', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [access] = await pool.query(`
        SELECT a.id, a.character_id, a.discipline, a.max_level, a.note, a.granted_at, a.updated_at,
               c.name AS character_name, c.clan AS character_clan, c.user_id,
               u.display_name AS player_name,
               gu.display_name AS granted_by_name
        FROM discipline_access a
        JOIN characters c ON c.id = a.character_id
        JOIN users u ON u.id = c.user_id
        LEFT JOIN users gu ON gu.id = a.granted_by
        ORDER BY c.name, a.discipline
      `);

      const [requests] = await pool.query(`
        SELECT r.id, r.character_id, r.discipline, r.requested_level, r.message, r.status,
               r.granted_level, r.admin_note, r.created_at, r.resolved_at,
               c.name AS character_name, c.clan AS character_clan, c.user_id,
               u.display_name AS player_name,
               ru.display_name AS resolved_by_name
        FROM discipline_requests r
        JOIN characters c ON c.id = r.character_id
        JOIN users u ON u.id = c.user_id
        LEFT JOIN users ru ON ru.id = r.resolved_by
        WHERE r.status = 'pending' OR r.resolved_at >= (NOW() - INTERVAL 30 DAY)
        ORDER BY (r.status = 'pending') DESC, r.created_at DESC
      `);

      reply.send({ access, requests });
    } catch (err) {
      log.err('GET /api/admin/discipline-access failed', { error: err.message });
      reply.status(500).json({ error: 'Database error fetching discipline access' });
    }
  });

  // Direct grant/adjust, bypassing the request queue entirely.
  fastify.post('/api/admin/characters/:id/discipline-access', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const characterId = Number(req.params.id);
    const discipline = cleanDiscipline(req.body?.discipline);
    const maxLevel = cleanLevel(req.body?.maxLevel);
    const note = cleanMessage(req.body?.note);

    if (!Number.isInteger(characterId) || characterId <= 0) return reply.status(400).json({ error: 'Invalid character id' });
    if (!discipline) return reply.status(400).json({ error: 'discipline is required' });
    if (!maxLevel) return reply.status(400).json({ error: `maxLevel must be 1-${MAX_DISCIPLINE_LEVEL}` });

    try {
      const [[ch]] = await pool.query('SELECT id, name, user_id FROM characters WHERE id=?', [characterId]);
      if (!ch) return reply.status(404).json({ error: 'Character not found' });

      await pool.query(
        `INSERT INTO discipline_access (character_id, discipline, max_level, note, granted_by)
         VALUES (?,?,?,?,?)
         ON DUPLICATE KEY UPDATE max_level=VALUES(max_level), note=VALUES(note), granted_by=VALUES(granted_by), granted_at=NOW()`,
        [ch.id, discipline, maxLevel, note, req.user.id]
      );

      const [[row]] = await pool.query(
        'SELECT * FROM discipline_access WHERE character_id=? AND discipline=?',
        [ch.id, discipline]
      );

      log.adm('Discipline access granted', { admin: req.user.id, character_id: ch.id, discipline, maxLevel });
      sendPushNotification?.(
        ch.user_id,
        '🩸 Discipline Unlocked',
        `Your Storyteller has granted ${ch.name} access to ${discipline}, up to level ${maxLevel}.`,
        {}, 'system'
      ).catch(() => { });

      reply.send({ access: row });
    } catch (err) {
      log.err('POST /api/admin/characters/:id/discipline-access failed', { error: err.message });
      reply.status(500).json({ error: 'Database error granting discipline access' });
    }
  });

  // Revoke a direct or request-granted access.
  fastify.delete('/api/admin/characters/:id/discipline-access/:discipline', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const characterId = Number(req.params.id);
    const discipline = decodeURIComponent(req.params.discipline || '');

    if (!Number.isInteger(characterId) || characterId <= 0) return reply.status(400).json({ error: 'Invalid character id' });
    if (!discipline) return reply.status(400).json({ error: 'discipline is required' });

    try {
      const [result] = await pool.query(
        'DELETE FROM discipline_access WHERE character_id=? AND discipline=?',
        [characterId, discipline]
      );
      if (!result.affectedRows) return reply.status(404).json({ error: 'No such grant' });

      log.adm('Discipline access revoked', { admin: req.user.id, character_id: characterId, discipline });
      reply.send({ ok: true });
    } catch (err) {
      log.err('DELETE /api/admin/characters/:id/discipline-access/:discipline failed', { error: err.message });
      reply.status(500).json({ error: 'Database error revoking discipline access' });
    }
  });

  // Approve or reject a pending request.
  fastify.post('/api/admin/discipline-requests/:requestId/:action', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const { requestId, action } = req.params;
    if (action !== 'approve' && action !== 'reject') {
      return reply.status(400).json({ error: 'action must be approve or reject' });
    }
    const adminNote = cleanMessage(req.body?.adminNote);

    try {
      const [[request]] = await pool.query('SELECT * FROM discipline_requests WHERE id=?', [requestId]);
      if (!request) return reply.status(404).json({ error: 'Request not found' });
      if (request.status !== 'pending') return reply.status(409).json({ error: `Request already ${request.status}` });

      const [[ch]] = await pool.query('SELECT id, name, user_id FROM characters WHERE id=?', [request.character_id]);

      if (action === 'reject') {
        await pool.query(
          "UPDATE discipline_requests SET status='rejected', resolved_at=NOW(), resolved_by=?, admin_note=? WHERE id=?",
          [req.user.id, adminNote, requestId]
        );
        sendPushNotification?.(
          request.user_id,
          '❌ Discipline Request Denied',
          `Your Storyteller denied the request for ${request.discipline}${adminNote ? `: ${adminNote}` : '.'}`,
          {}, 'system'
        ).catch(() => { });
        log.adm('Discipline request rejected', { admin: req.user.id, request_id: request.id, discipline: request.discipline });
        return reply.send({ ok: true });
      }

      const grantedLevel = cleanLevel(req.body?.grantedLevel) || request.requested_level;

      await pool.query(
        `INSERT INTO discipline_access (character_id, discipline, max_level, note, granted_by)
         VALUES (?,?,?,?,?)
         ON DUPLICATE KEY UPDATE max_level=GREATEST(max_level, VALUES(max_level)), note=VALUES(note), granted_by=VALUES(granted_by), granted_at=NOW()`,
        [request.character_id, request.discipline, grantedLevel, adminNote, req.user.id]
      );

      await pool.query(
        "UPDATE discipline_requests SET status='approved', granted_level=?, resolved_at=NOW(), resolved_by=?, admin_note=? WHERE id=?",
        [grantedLevel, req.user.id, adminNote, requestId]
      );

      const [[access]] = await pool.query(
        'SELECT * FROM discipline_access WHERE character_id=? AND discipline=?',
        [request.character_id, request.discipline]
      );

      sendPushNotification?.(
        request.user_id,
        '🩸 Discipline Request Approved',
        `Your Storyteller granted ${ch?.name || 'your character'} access to ${request.discipline}, up to level ${grantedLevel}.`,
        {}, 'system'
      ).catch(() => { });
      log.adm('Discipline request approved', { admin: req.user.id, request_id: request.id, discipline: request.discipline, grantedLevel });

      reply.send({ ok: true, access });
    } catch (err) {
      log.err('POST /api/admin/discipline-requests/:requestId/:action failed', { error: err.message });
      reply.status(500).json({ error: 'Database error resolving request' });
    }
  });
};
