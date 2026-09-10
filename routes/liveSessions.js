// routes/liveSessions.js
//
// Live tabletop sessions: lifecycle, participants, dice rolls, and the
// Storyteller broadcast channel. Realtime nudges go through fastify.io.
const { computeV5Outcome } = require('../services/dice');
const { getSessionInternalId } = require('../services/liveSession');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, moderateLimiter } = opts;

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
      const [rows] = await pool.query('SELECT id, created_at, status FROM live_sessions WHERE session_code=? OR id=?', [req.params.id, req.params.id]);
      if (!rows.length) return reply.status(404).json({ error: 'Session not found' });
      if (rows[0].status === 'ended') return reply.send({ ok: true, message: 'Already ended' });

      const internalId = rows[0].id;
      // Calculate total duration
      const duration = Math.floor((Date.now() - new Date(rows[0].created_at).getTime()) / 1000);

      await pool.query(
        "UPDATE live_sessions SET status='ended', ended_at=NOW(), duration_seconds=? WHERE id=?",
        [duration, internalId]
      );

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

  // Get session details (Calculates running timer if active)
  fastify.get('/api/live-session/:id', { preHandler: [authRequired] }, async (req, reply) => {
    const [rows] = await pool.query(
      'SELECT s.*, u.display_name as admin_name FROM live_sessions s LEFT JOIN users u ON s.admin_id = u.id WHERE s.session_code=? OR s.id=?',
      [req.params.id, req.params.id]
    );
    if (!rows.length) return reply.status(404).json({ error: 'Session not found' });
    const s = rows[0];
    try { s.metadata = typeof s.metadata === 'string' ? JSON.parse(s.metadata) : (s.metadata || {}); } catch (e) { s.metadata = {}; }
    if (s.status === 'active') {
      s.duration_seconds = Math.floor((Date.now() - new Date(s.created_at).getTime()) / 1000);
    }
    reply.send({ session: s });
  });

  // Join a session
  fastify.post('/api/live-session/:id/join', { preHandler: [authRequired] }, async (req, reply) => {
    const internalId = await getSessionInternalId(req.params.id);
    if (!internalId) return reply.status(404).json({ error: 'Session not found' });

  const { characterId } = req.body;
    await pool.query('INSERT IGNORE INTO live_session_participants (session_id, user_id, character_id) VALUES (?, ?, ?)',
      [internalId, req.user.id, characterId]);
    reply.send({ ok: true });
  });

  fastify.get('/api/live-session/:id/rolls', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const internalId = await getSessionInternalId(req.params.id);
      const [rows] = await pool.query(
        `SELECT lsr.*, COALESCE(lsr.character_name, c.name) as character_name 
       FROM live_session_rolls lsr 
       LEFT JOIN characters c ON lsr.character_id = c.id 
       LEFT JOIN live_sessions ls ON lsr.session_id = ls.id
       WHERE lsr.session_id=? 
         AND (
           lsr.is_hidden = FALSE 
           OR c.user_id = ? 
           OR ls.admin_id = ? 
           OR ? = 'admin'
         )
       ORDER BY lsr.created_at DESC LIMIT 50`,
        [internalId, req.user.id, req.user.id, req.user.role]
      );
      reply.send({ rolls: rows });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch rolls' });
    }
  });

  // Log a roll: Double-Insert into BOTH live_session_rolls AND dice_rolls
  fastify.post('/api/live-session/:id/rolls', { preHandler: [authRequired] }, async (req, reply) => {
    const internalId = await getSessionInternalId(req.params.id);
    if (!internalId) return reply.status(404).json({ error: 'Session not found' });

  const { characterId, character_name, roll_type, pool: poolCount, hunger, results, successes, note, is_hidden } = req.body;

    try {
      // 1. Log to the localized session table
      await pool.query(
        'INSERT INTO live_session_rolls (session_id, character_id, character_name, roll_type, pool, hunger, results, successes, note, is_hidden) VALUES (?,?,?,?,?,?,?,?,?,?)',
        [internalId, characterId || null, character_name || null, roll_type || 'custom', poolCount || null, hunger !== undefined ? hunger : null, results ? JSON.stringify(results) : null, successes || 0, note || null, is_hidden ? 1 : 0]
      );

      // 2. Mirror into the Global/Permanent Dice Roller Table
      const outcome = computeV5Outcome({
        normal: (results?.normal || []).map(Number),
        hunger: (results?.hunger || []).map(Number),
      });

      const payload = {
        normal: results?.normal || [],
        hunger: results?.hunger || [],
        difficulty: null
      };

      const safeNote = note ? `[Session: ${req.params.id}] ${note}`.slice(0, 255) : `[Session: ${req.params.id}]`;

      await pool.query(
        `INSERT INTO dice_rolls 
       (user_id, character_id, pool, hunger, sides, results_json, successes, crit_pairs, messy_crit, bestial_failure, note, is_hidden)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          req.user.id, characterId || null,
          Number(poolCount) || (payload.normal.length + payload.hunger.length),
          Number(hunger) || payload.hunger.length,
          10,
          JSON.stringify(payload),
          outcome.successes || 0,
          outcome.crit_pairs || 0,
          outcome.messy_crit ? 1 : 0,
          outcome.bestial_failure ? 1 : 0,
          safeNote || null,
          is_hidden ? 1 : 0
        ]
      );

      if (outcome.messy_crit && characterId) {
        try {
          const [doms] = await pool.query('SELECT division FROM domain_claims WHERE owner_character_id=?', [characterId]);
          if (doms.length > 0) {
            const domId = doms[0].division;
            await pool.query('UPDATE domain_claims SET safety_rating = GREATEST(safety_rating - 1, 0) WHERE division=?', [domId]);
            await pool.query('INSERT INTO admin_audit_logs (admin_id, action, details) VALUES (?, ?, ?)', [0, 'SYSTEM_MESSY_CRIT', `Character ${characterId} rolled a Messy Critical. Domain ${domId} safety reduced.`]);
          }
        } catch (e) { log.err('Messy crit safety reduction failed', { error: e.message }); }
      }

      if (req.server.io) {
        req.server.io.to(`session_${req.params.id}`).emit('refresh_session');
      }

      reply.send({ ok: true });
    } catch (e) {
      console.error("Failed to log live session roll:", e);
      reply.status(500).json({ error: 'Failed to log roll' });
    }
  });

  // Get session players
  fastify.get('/api/live-session/:id/players', { preHandler: [authRequired] }, async (req, reply) => {
    const internalId = await getSessionInternalId(req.params.id);
    const [players] = await pool.query(`
    SELECT c.id, c.name, c.clan, c.sheet, c.user_id
    FROM live_session_participants lsp
    JOIN characters c ON lsp.character_id = c.id
    WHERE lsp.session_id = ?
  `, [internalId]);
    reply.send({ players });
  });

  // Update Session Metadata
  fastify.patch('/api/live-session/:id/metadata', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const internalId = await getSessionInternalId(req.params.id);
      const { metadata } = req.body;
      await pool.query('UPDATE live_sessions SET metadata = ? WHERE id = ?', [JSON.stringify(metadata || {}), internalId]);
      if (req.server.io) {
        req.server.io.to(`session_${req.params.id}`).emit('refresh_session');
      }
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
      const internalId = await getSessionInternalId(req.params.id);
      if (!internalId) return reply.status(404).json({ error: 'Session not found' });

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

      if (req.server.io) {
        req.server.io.to(`session_${req.params.id}`).emit('refresh_session');
      }

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

    if (req.server.io) {
      req.server.io.to(`session_${req.params.id}`).emit('refresh_session');
    }

    reply.send({ ok: true });
  });

  fastify.get('/api/live-session/:id/broadcast', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const internalId = await getSessionInternalId(req.params.id);
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
      const { hungerDelta, healthSupDelta, healthAggDelta, wpSupDelta, wpAggDelta, humanityDelta, stainsDelta, frenzyState, forceRouseCheck, damage } = req.body;

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
        const rouseDie = Math.floor(Math.random() * 10) + 1;
        if (rouseDie < 6) {
          sheet.hunger = Math.max(0, Math.min(5, (sheet.hunger || 0) + 1));
        }
        const internalId = await getSessionInternalId(req.params.id);
        if (internalId) {
          await pool.query('INSERT INTO live_session_broadcasts (session_id, message) VALUES (?, ?)',
            [internalId, `ST forced a Rouse Check. Result: ${rouseDie} ${rouseDie < 6 ? '(Failed)' : '(Safe)'}`]);
        }
      }

      await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), charId]);

      if (req.server.io) {
        req.server.io.to(`session_${req.params.id}`).emit('refresh_session');
      }

      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to update player' });
    }
  });
};
