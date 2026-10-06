// routes/liveSessions.js
//
// Live tabletop sessions: lifecycle, participants, dice rolls, and the
// Storyteller broadcast channel. Realtime nudges go through fastify.io.
const { insertRoll, formatRoll } = require('../services/rolls');
const { rollD10 } = require('../services/dice');
const { getSessionInternalId, getSessionRow, emitSessionRefresh, closeSession, onlineUserIds, removeUserSockets } = require('../services/liveSession');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, moderateLimiter } = opts;

  // Same staff notion as the socket join_session handler.
  const isStaff = (u) => u?.role === 'admin' || u?.role === 'courtuser';

  // Everything a session exposes is for its participants and staff only: the
  // 8-character code (DDMMYY##) is guessable, so it is not an access secret.
  // Once a session has ended only staff can still read it; a player's screen
  // just learns it ended (GET /:id) and leaves.
  async function isParticipant(req, internalId) {
    const [rows] = await pool.query(
      'SELECT 1 FROM live_session_participants WHERE session_id=? AND user_id=? LIMIT 1',
      [internalId, req.user.id]
    );
    return rows.length > 0;
  }
  async function canRead(req, session) {
    if (isStaff(req.user)) return true;
    return !!session && session.status !== 'ended' && isParticipant(req, session.id);
  }

  // Create a new live session (Generates an 8-character Code) - CHANGED TO requireAdmin
  fastify.post('/api/live-session', { preHandler: [authRequired, requireAdmin, moderateLimiter] }, async (req, reply) => {
    try {
      const { name } = req.body;

      // Generate an 8-letter DDMMYY + Number code
      const now = new Date();
      const dd = String(now.getDate()).padStart(2, '0');
      const mm = String(now.getMonth() + 1).padStart(2, '0');
      const yy = String(now.getFullYear()).slice(-2);
      const prefix = `${dd}${mm}${yy}`;

      const [countRows] = await pool.query("SELECT COUNT(*) as c FROM live_sessions WHERE session_code LIKE ?", [`${prefix}%`]);
      const nextNum = String((countRows[0].c || 0) + 1).padStart(2, '0');
      const sessionCode = `${prefix}${nextNum}`;

      const [r] = await pool.query(
        "INSERT INTO live_sessions (name, admin_id, session_code, status) VALUES (?, ?, ?, 'active')",
        [name || 'Live Session', req.user.id, sessionCode]
      );

      log.adm('Started new Live Session', { code: sessionCode, admin: req.user.id });
      reply.send({ id: sessionCode, internal_id: r.insertId, name, session_code: sessionCode });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to create session' });
    }
  });

  // End an active live session - CHANGED TO requireAdmin
  fastify.post('/api/live-session/:id/end', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT id, session_code, created_at, status FROM live_sessions WHERE session_code=? OR id=?', [req.params.id, req.params.id]);
      if (!rows.length) return reply.status(404).json({ error: 'Session not found' });
      if (rows[0].status === 'ended') return reply.send({ ok: true, message: 'Already ended' });

      const duration = await closeSession(fastify.io, rows[0], req.user?.id || null);
      log.adm('Live Session Ended', { session: req.params.id, duration_seconds: duration });
      reply.send({ ok: true, duration_seconds: duration });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to end session' });
    }
  });

  // Admin/ST: List all historical sessions - CHANGED TO requireAdmin
  fastify.get('/api/admin/live-sessions', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [sessions] = await pool.query(`
      SELECT s.*, u.display_name as st_name,
             COALESCE(p.player_count, 0) as player_count
      FROM live_sessions s
      LEFT JOIN users u ON s.admin_id = u.id
      LEFT JOIN (
        SELECT session_id, COUNT(DISTINCT user_id) as player_count
        FROM live_session_participants
        GROUP BY session_id
      ) p ON p.session_id = s.id
      ORDER BY s.created_at DESC
    `);
      reply.send({ sessions });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch sessions' });
    }
  });

  // Sessions running right now, so a player can tap "join" instead of typing a
  // code. Name and code only: nothing else about a session is shown until joined.
  fastify.get('/api/live-session/active', { preHandler: [authRequired] }, async (req, reply) => {
    const [sessions] = await pool.query(
      `SELECT s.session_code, s.name, u.display_name AS admin_name
       FROM live_sessions s LEFT JOIN users u ON s.admin_id = u.id
       WHERE s.status='active' ORDER BY s.created_at DESC LIMIT 5`
    );
    reply.send({ sessions });
  });

  // Get session details (Calculates running timer if active)
  fastify.get('/api/live-session/:id', { preHandler: [authRequired] }, async (req, reply) => {
    const [rows] = await pool.query(
      'SELECT s.*, u.display_name as admin_name FROM live_sessions s LEFT JOIN users u ON s.admin_id = u.id WHERE s.session_code=? OR s.id=?',
      [req.params.id, req.params.id]
    );
    if (!rows.length) return reply.status(404).json({ error: 'Session not found' });
    const s = rows[0];
    if (!isStaff(req.user)) {
      if (!(await isParticipant(req, s.id))) return reply.status(403).json({ error: 'Not a participant in this session' });
      if (s.status === 'ended') return reply.send({ session: { id: s.id, session_code: s.session_code, status: 'ended' } });
    }
    try { s.metadata = typeof s.metadata === 'string' ? JSON.parse(s.metadata) : (s.metadata || {}); } catch (e) { s.metadata = {}; }
    if (!isStaff(req.user)) {
      // Players get an allowlist, not the whole blob: metadata also holds the
      // ST's private notes, NPC roster and every player's effects/requests,
      // and any key added later stays private until listed here.
      const m = s.metadata;
      const [mine] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
      const ids = new Set(mine.map((c) => String(c.id)));
      s.metadata = {
        scene: m.scene, ambient: m.ambient, clocks: m.clocks, initiative: m.initiative,
        turnActorId: m.turnActorId, round: m.round,
        activeEffects: Object.fromEntries(Object.entries(m.activeEffects || {}).filter(([id]) => ids.has(id))),
        rollRequests: (m.rollRequests || []).filter((r) => ids.has(String(r.targetId))),
      };
    }
    if (s.status === 'active') {
      s.duration_seconds = Math.max(0, Math.floor((Date.now() - new Date(s.created_at).getTime()) / 1000));
    }
    s.server_time = Date.now();
    reply.send({ session: s });
  });

  // Join a session
  fastify.post('/api/live-session/:id/join', { preHandler: [authRequired] }, async (req, reply) => {
    const session = await getSessionRow(req.params.id);
    if (!session) return reply.status(404).json({ error: 'Session not found' });
    if (session.status === 'ended') return reply.status(400).json({ error: 'That session has ended.' });
    const internalId = session.id;

    let { characterId } = req.body || {};
    if (!characterId) {
      const [cRows] = await pool.query('SELECT id FROM characters WHERE user_id=? ORDER BY id DESC LIMIT 1', [req.user.id]);
      if (cRows.length) characterId = cRows[0].id;
    }

    await pool.query(
      `INSERT INTO live_session_participants (session_id, user_id, character_id)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
         character_id = COALESCE(VALUES(character_id), character_id),
         joined_at = CURRENT_TIMESTAMP`,
      [internalId, req.user.id, characterId || null]
    );

    await emitSessionRefresh(fastify.io, internalId);
    reply.send({ ok: true });
  });

  // The session feed: every roll made in this session, from dice_rolls (the
  // one table all dice go to; see routes/dice.js), plus dice-less events.
  fastify.get('/api/live-session/:id/rolls', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const session = await getSessionRow(req.params.id);
      if (!(await canRead(req, session))) return reply.status(403).json({ error: 'Not a participant in this session' });
      const internalId = session.id;
      const [rows] = await pool.query(
        `SELECT r.*, COALESCE(r.character_name, c.name) AS character_name
         FROM dice_rolls r
         LEFT JOIN characters c ON r.character_id = c.id
         LEFT JOIN live_sessions ls ON r.session_id = ls.id
         WHERE r.session_id=?
           AND (r.is_hidden = FALSE OR c.user_id = ? OR ls.admin_id = ? OR ? = 'admin')
         ORDER BY r.created_at DESC, r.id DESC LIMIT 50`,
        [internalId, req.user.id, req.user.id, req.user.role]
      );
      reply.send({ rolls: rows.map(formatRoll) });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch rolls' });
    }
  });

  // Dice-less feed events (a discipline switched on or off). Dice are only
  // ever thrown by the server (POST /api/dice/roll), so this refuses results.
  const FEED_EVENTS = new Set(['discipline_activation', 'discipline_deactivation']);
  fastify.post('/api/live-session/:id/rolls', { preHandler: [authRequired] }, async (req, reply) => {
    const session = await getSessionRow(req.params.id);
    if (!session) return reply.status(404).json({ error: 'Session not found' });
    const internalId = session.id;
    const { roll_type, note, is_hidden, disc, power_name } = req.body || {};
    if (!FEED_EVENTS.has(roll_type)) return reply.status(400).json({ error: 'Dice are rolled by the server: use POST /api/dice/roll.' });
    if (session.status === 'ended') return reply.status(400).json({ error: 'That session has ended.' });
    if (!(await canRead(req, session))) return reply.status(403).json({ error: 'Not a participant in this session' });

    try {
      const [[ch]] = await pool.query('SELECT id, name FROM characters WHERE user_id=? LIMIT 1', [req.user.id]);
      await insertRoll(pool, {
        userId: req.user.id, characterId: ch?.id ?? null, characterName: ch?.name, sessionId: internalId,
        rollType: roll_type, note, isHidden: !!is_hidden,
        extra: { ...(disc ? { disc: String(disc).slice(0, 60) } : {}), ...(power_name ? { power_name: String(power_name).slice(0, 120) } : {}) },
      });
      await emitSessionRefresh(fastify.io, internalId);
      reply.send({ ok: true });
    } catch (e) {
      log.err('Failed to log live session event', { message: e.message });
      reply.status(500).json({ error: 'Failed to log event' });
    }
  });

  fastify.get('/api/live-session/:id/players', { preHandler: [authRequired] }, async (req, reply) => {
    const session = await getSessionRow(req.params.id);
    if (!session) return reply.status(404).json({ error: 'Session not found' });
    if (!(await canRead(req, session))) return reply.status(403).json({ error: 'Not a participant in this session' });
    const internalId = session.id;
    const [players] = await pool.query(`
      SELECT 
        lsp.session_id,
        lsp.user_id,
        COALESCE(lsp.character_id, c.id) AS character_id,
        COALESCE(c.id, lsp.character_id, lsp.user_id) AS id,
        COALESCE(c.name, u.display_name, 'Player') AS name,
        COALESCE(c.clan, 'Mortal') AS clan,
        c.sheet,
        u.display_name AS user_name
      FROM live_session_participants lsp
      LEFT JOIN characters c ON lsp.character_id = c.id
      LEFT JOIN users u ON lsp.user_id = u.id
      WHERE lsp.session_id = ?
      ORDER BY lsp.joined_at ASC
    `, [internalId]);
    // Other players' sheets (health, willpower, hunger, ...) and account names
    // are ST data; players only get the table roster.
    const online = await onlineUserIds(fastify.io, internalId);
    const roster = players.map((p) => ({ ...p, online: online.has(Number(p.user_id)) }));
    reply.send({ players: isStaff(req.user) ? roster : roster.map(({ sheet, user_name, ...pub }) => pub) });
  });

  // ST removes a player from the session: seat, live connection and all. Their
  // screen sees it is no longer a participant and leaves; they can rejoin with
  // the code if the removal was a mistake.
  fastify.delete('/api/live-session/:id/participants/:userId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const session = await getSessionRow(req.params.id);
    if (!session) return reply.status(404).json({ error: 'Session not found' });
    await pool.query('DELETE FROM live_session_participants WHERE session_id=? AND user_id=?', [session.id, req.params.userId]);
    await removeUserSockets(fastify.io, session, req.params.userId);
    await emitSessionRefresh(fastify.io, session.id);
    fastify.io?.to(`user_${Number(req.params.userId)}`).emit('refresh_session'); // they just left the room
    log.adm('Removed player from Live Session', { session: req.params.id, user: req.params.userId });
    reply.send({ ok: true });
  });

  // Update Session Metadata
  fastify.patch('/api/live-session/:id/metadata', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const internalId = await getSessionInternalId(req.params.id);
      const { metadata } = req.body;
      await pool.query('UPDATE live_sessions SET metadata = ? WHERE id = ?', [JSON.stringify(metadata || {}), internalId]);
      await emitSessionRefresh(fastify.io, internalId);
      reply.send({ ok: true });
    } catch (e) {
      console.error(e);
      reply.status(500).json({ error: 'Failed to update metadata' });
    }
  });

  // Player -> Storyteller signals. Unlike /broadcast (admin-only) this is open to
  // any authenticated participant, but locked to a fixed vocabulary so it can't be
  // used as a free-text spam channel.
  const SIGNAL_MESSAGES = {
    hand:      (n) => `[Hand] ${n} raised their hand for the Storyteller.`,
    rules:     (n) => `[Rules] ${n} has a rules question.`,
    afk:       (n) => `[AFK] ${n} stepped away from the table.`,
    back:      (n) => `[AFK] ${n} is back at the table.`,
    blush_on:  (n) => `[Status] ${n} activated Blush of Life.`,
    blush_off: (n) => `[Status] ${n} deactivated Blush of Life.`,
  };

  fastify.post('/api/live-session/:id/signal', { preHandler: [authRequired, moderateLimiter] }, async (req, reply) => {
    try {
      const session = await getSessionRow(req.params.id);
      if (!session) return reply.status(404).json({ error: 'Session not found' });
      if (session.status === 'ended') return reply.status(400).json({ error: 'That session has ended.' });
      const internalId = session.id;

      const type = String(req.body?.type || '');
      const builder = SIGNAL_MESSAGES[type];
      if (!builder) return reply.status(400).json({ error: 'Unknown signal type' });

      // Only participants (or the running ST) may signal into a session.
      const [seat] = await pool.query(
        `SELECT 1 FROM live_session_participants WHERE session_id=? AND user_id=?
         UNION SELECT 1 FROM live_sessions WHERE id=? AND admin_id=?`,
        [internalId, req.user.id, internalId, req.user.id]
      );
      if (!seat.length) return reply.status(403).json({ error: 'Not a participant in this session' });

      const rawName = typeof req.body?.characterName === 'string' ? req.body.characterName.trim() : '';
      const name = (rawName || req.user.display_name || 'A player').slice(0, 60);

      await pool.query('INSERT INTO live_session_broadcasts (session_id, message) VALUES (?, ?)',
        [internalId, builder(name)]);

      await emitSessionRefresh(fastify.io, internalId);

      reply.send({ ok: true });
    } catch (e) {
      log.err('Live session signal failed', { error: e.message });
      reply.status(500).json({ error: 'Failed to send signal' });
    }
  });

  // Broadcast a message (ST/Admin) - CHANGED TO requireAdmin
  fastify.post('/api/live-session/:id/broadcast', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const internalId = await getSessionInternalId(req.params.id);
    await pool.query('INSERT INTO live_session_broadcasts (session_id, message, target_character_id) VALUES (?, ?, ?)',
      [internalId, req.body.message, req.body.target_character_id || null]);

    await emitSessionRefresh(fastify.io, internalId);

    reply.send({ ok: true });
  });

  fastify.get('/api/live-session/:id/broadcast', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const session = await getSessionRow(req.params.id);
      if (!(await canRead(req, session))) return reply.status(403).json({ error: 'Not a participant in this session' });
      const internalId = session.id;
      const [rows] = await pool.query(
        `SELECT b.*
       FROM live_session_broadcasts b
       LEFT JOIN characters c ON b.target_character_id = c.id
       LEFT JOIN live_sessions ls ON b.session_id = ls.id
       WHERE b.session_id=?
         AND (
           b.target_character_id IS NULL
           OR c.user_id = ?
           OR ls.admin_id = ?
           OR ? = 'admin'
         )
       ORDER BY b.created_at DESC LIMIT 20`,
        [internalId, req.user.id, req.user.id, req.user.role]
      );
      reply.send({ broadcasts: rows });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch broadcasts' });
    }
  });

  // Update a live player's trackers as ST - CHANGED TO requireAdmin
  fastify.patch('/api/live-session/:id/players/:charId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const charId = req.params.charId;
      const { hungerDelta, healthSupDelta, healthAggDelta, wpSupDelta, wpAggDelta, humanityDelta, stainsDelta, frenzyState, forceRouseCheck, damage, bloodPotencyDelta, bloodPotency } = req.body;

      const [rows] = await pool.query('SELECT sheet FROM characters WHERE id=?', [charId]);
      if (!rows.length) return reply.status(404).json({ error: 'Char not found' });

      let sheet = {};
      try {
        sheet = typeof rows[0].sheet === 'string' ? JSON.parse(rows[0].sheet || '{}') : (rows[0].sheet || {});
      } catch (e) {
        return reply.status(500).json({ error: 'Failed to parse existing character sheet data.' });
      }

      if (hungerDelta !== undefined) sheet.hunger = Math.max(0, Math.min(5, Number(sheet.hunger || 0) + Number(hungerDelta)));
      if (humanityDelta !== undefined) {
        const currentHum = Number(sheet.morality?.humanity ?? sheet.humanity ?? 7);
        const nextHum = Math.max(0, Math.min(10, currentHum + Number(humanityDelta)));
        sheet.humanity = nextHum;
        if (!sheet.morality) sheet.morality = {};
        sheet.morality.humanity = nextHum;
      }
      if (healthSupDelta !== undefined) {
        if (!sheet.health) sheet.health = { superficial: 0, aggravated: 0 };
        sheet.health.superficial = Math.max(0, Number(sheet.health.superficial || 0) + Number(healthSupDelta));
      }
      if (healthAggDelta !== undefined) {
        if (!sheet.health) sheet.health = { superficial: 0, aggravated: 0 };
        sheet.health.aggravated = Math.max(0, Number(sheet.health.aggravated || 0) + Number(healthAggDelta));
      }
      if (wpSupDelta !== undefined) {
        if (!sheet.willpower) sheet.willpower = { superficial: 0, aggravated: 0 };
        sheet.willpower.superficial = Math.max(0, Number(sheet.willpower.superficial || 0) + Number(wpSupDelta));
      }
      if (wpAggDelta !== undefined) {
        if (!sheet.willpower) sheet.willpower = { superficial: 0, aggravated: 0 };
        sheet.willpower.aggravated = Math.max(0, Number(sheet.willpower.aggravated || 0) + Number(wpAggDelta));
      }
      if (stainsDelta !== undefined) {
        sheet.stains = Math.max(0, Math.min(10, Number(sheet.stains || 0) + Number(stainsDelta)));
      }
      if (frenzyState !== undefined) {
        sheet.frenzyState = frenzyState;
      }
      if (bloodPotencyDelta !== undefined) {
        const currentBP = Number(sheet.blood_potency ?? sheet.bloodPotency ?? 1);
        const nextBP = Math.max(0, Math.min(10, currentBP + Number(bloodPotencyDelta)));
        sheet.blood_potency = nextBP;
        sheet.bloodPotency = nextBP;
      }
      if (bloodPotency !== undefined) {
        const nextBP = Math.max(0, Math.min(10, Number(bloodPotency)));
        sheet.blood_potency = nextBP;
        sheet.bloodPotency = nextBP;
      }

      // Structured damage: halves Superficial (round up) and converts to
      // Aggravated 1-to-1 once the Health track is full (V5 core).
      if (damage && Number(damage.amount) > 0) {
        const stamina = Number(sheet.attributes?.Stamina) || 1;
        const fortDots = Number(sheet.disciplines?.Fortitude) || 0;
        const fortPowers = sheet.disciplinePowers?.Fortitude;
        const hasResilience = !Array.isArray(fortPowers) || fortPowers.length === 0
          || fortPowers.some((p) => /resilien/i.test(String((p && (p.id || p.name)) || p)));
        const max = Math.max(1, stamina + 3 + (hasResilience ? fortDots : 0));

        if (!sheet.health) sheet.health = { superficial: 0, aggravated: 0 };
        let sup = Math.max(0, Math.min(max, Number(sheet.health.superficial) || 0));
        let agg = Math.max(0, Math.min(max, Number(sheet.health.aggravated) || 0));
        const soak = Math.max(0, Number(damage.soak) || 0);
        let amt = Math.max(0, Math.round(Number(damage.amount)));
        const isAgg = damage.type === 'aggravated';
        if (!isAgg) {
          amt = Math.max(0, amt - soak);
          if (damage.halve) amt = Math.ceil(amt / 2);
        }
        for (let i = 0; i < amt; i += 1) {
          if (sup + agg < max) { if (isAgg) agg += 1; else sup += 1; }
          else if (sup > 0) { sup -= 1; agg += 1; }
          else agg = Math.min(max, agg + 1);
        }
        sheet.health.superficial = sup;
        sheet.health.aggravated = agg;
      }

      if (forceRouseCheck) {
        const rouseDie = rollD10();
        if (rouseDie < 6) {
          sheet.hunger = Math.max(0, Math.min(5, (sheet.hunger || 0) + 1));
        }
        const internalId = await getSessionInternalId(req.params.id);
        const [[target]] = await pool.query('SELECT user_id, name FROM characters WHERE id=?', [charId]);
        await insertRoll(pool, {
          userId: target?.user_id ?? req.user.id, characterId: charId, characterName: target?.name, sessionId: internalId ?? null,
          rollType: 'rouse_check', rouse: [rouseDie], hungerLevel: sheet.hunger,
          note: `Storyteller forced a Rouse Check: ${rouseDie < 6 ? 'Hunger +1' : 'no Hunger gained'}`,
        });
      }

      await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), charId]);

      await emitSessionRefresh(fastify.io, req.params.id);

      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to update player' });
    }
  });
};
