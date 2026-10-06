// routes/dice.js
//
// Every dice roll in the app is thrown here, on the server, and stored in
// `dice_rolls` (services/rolls.js). Clients ask for a roll and show what comes
// back; they never send dice faces. Rolls made in a live session carry its
// session_id and appear in that session's feed.
const { rollPool, rollD10 } = require('../services/dice');
const { traitPool, frenzyPool, parsePowerPool, insertRoll, formatRoll, trackers, NO_REROLL } = require('../services/rolls');
const { CATALOG } = require('../utils/xpPurchase');
const { parseSheet } = require('../utils/sheet');
const { isAdmin } = require('../services/guards');

// Storyteller roll kinds that may be logged into a session feed.
const ST_ROLL_TYPES = new Set(['admin_roll', 'opposed_roll', 'remorse', 'npc_roll']);
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  // Dice only go into a session the roller has joined (staff may roll into any).
  async function findSession(db, idOrCode, user) {
    if (idOrCode == null || idOrCode === '') return null;
    const [[s]] = await db.query('SELECT id, session_code, status, admin_id, metadata FROM live_sessions WHERE session_code=? OR id=?', [idOrCode, idOrCode]);
    if (!s) fail(404, 'Session not found');
    if (s.status === 'ended') fail(400, 'That session has ended.');
    if (user.role !== 'admin' && user.role !== 'courtuser') {
      const [seat] = await db.query('SELECT 1 FROM live_session_participants WHERE session_id=? AND user_id=? LIMIT 1', [s.id, user.id]);
      if (!seat.length) fail(403, 'Join the session before rolling in it.');
    }
    s.metadata = parseSheet(s.metadata);
    return s;
  }

  // Tell everyone in the session to refresh; a Messy Critical costs the
  // roller's domain a point of safety (as the old session log did).
  async function afterSessionRoll(session, row) {
    if (!session) return;
    if (row.has_messy_critical && row.character_id) {
      try {
        const [doms] = await pool.query('SELECT division FROM domain_claims WHERE owner_character_id=?', [row.character_id]);
        if (doms.length) {
          await pool.query('UPDATE domain_claims SET safety_rating = GREATEST(safety_rating - 1, 0) WHERE division=?', [doms[0].division]);
          await pool.query('INSERT INTO admin_audit_logs (admin_id, action, details) VALUES (?, ?, ?)',
            [0, 'SYSTEM_MESSY_CRIT', `Character ${row.character_id} rolled a Messy Critical. Domain ${doms[0].division} safety reduced.`]);
        }
      } catch (e) { log.err('Messy crit safety reduction failed', { error: e.message }); }
    }
    const io = fastify.io || fastify.server?.io;
    for (const key of new Set([session.session_code, String(session.id)].filter(Boolean))) io?.to?.(`session_${key}`).emit('refresh_session');
  }

  /**
   * POST /api/dice/roll — body.mode:
   *  free     { pool, hunger, difficulty, note }               anyone; a Storyteller may also log it to a session
   *                                                             with { sessionId, rollType, characterName, characterId, isHidden }
   *  traits   { traits:[t1,t2], specialty, bloodSurge, effectIds, powerIds, situational:{mod,reason}, ignoreImpairment, difficulty }
   *  request  { requestId }                                      the Storyteller's requested pool, answered once
   *  power    { discipline, powerId }                            an owned power's activation pool
   *  frenzy   {}                                                 resist the current frenzy
   * Character modes take { sessionId, isHidden } and always use the caller's own character.
   */
  fastify.post('/api/dice/roll', { preHandler: [authRequired] }, async (req, reply) => {
    const b = req.body || {};
    const admin = isAdmin(req.user);
    try {
      if (!b.mode || b.mode === 'free') {
        const session = b.sessionId != null && b.sessionId !== '' ? await findSession(pool, b.sessionId, req.user) : null;
        if (session && !admin) fail(403, 'Only the Storyteller can post free rolls to a session.');
        const [[own]] = await pool.query('SELECT id, name FROM characters WHERE user_id=? LIMIT 1', [req.user.id]);
        const dice = rollPool(b.pool, b.hunger);
        const row = await insertRoll(pool, {
          userId: req.user.id,
          characterId: admin && session ? (b.characterId ?? null) : (own?.id ?? null),
          characterName: admin && session ? b.characterName : own?.name,
          sessionId: session?.id ?? null,
          rollType: admin && ST_ROLL_TYPES.has(b.rollType) ? b.rollType : (session ? 'admin_roll' : 'free'),
          normal: dice.normal, hunger: dice.hunger, hungerLevel: dice.hunger.length,
          difficulty: b.difficulty, note: b.note, isHidden: !!b.isHidden,
        });
        await afterSessionRoll(session, row);
        return reply.send({ roll: row });
      }

      // Everything else rolls the caller's own character, from its stored sheet.
      const conn = await pool.getConnection();
      let session = null;
      let rows = [];
      try {
        await conn.beginTransaction();
        session = await findSession(conn, b.sessionId, req.user);
        const [[ch]] = await conn.query('SELECT id, name, clan, sheet FROM characters WHERE user_id=? LIMIT 1 FOR UPDATE', [req.user.id]);
        if (!ch) fail(400, 'Create a character first');
        const sheet = parseSheet(ch.sheet);
        const base = { userId: req.user.id, characterId: ch.id, characterName: ch.name, sessionId: session?.id ?? null, isHidden: !!b.isHidden };
        let sheetChanged = false;

        if (b.mode === 'traits' || b.mode === 'request') {
          let traits = Array.isArray(b.traits) ? b.traits.slice(0, 2) : [];
          let specialty = !!b.specialty;
          let difficulty = Number(b.difficulty) || 0;
          let note = '';
          let ownSpecialtyOnly = true;
          if (b.mode === 'request') {
            // The Storyteller fixed the pool; it can be rolled once.
            const requests = session?.metadata?.rollRequests || [];
            const request = requests.find(r => r.id === b.requestId && String(r.targetId) === String(ch.id));
            if (!request) fail(404, 'That roll request is no longer open.');
            traits = [request.trait1, request.trait2];
            specialty = request.specialty || false;
            ownSpecialtyOnly = false;
            difficulty = Number(request.difficulty) || 0;
            note = `[${request.id.slice(-6)}] Storyteller's request${request.note ? `: ${String(request.note).slice(0, 80)}` : ''}`;
            await conn.query('UPDATE live_sessions SET metadata=? WHERE id=?',
              [JSON.stringify({ ...session.metadata, rollRequests: requests.filter(r => r !== request) }), session.id]);
          }

          // Blood Surge: one server Rouse Check first (not possible at Hunger 5).
          let surge = false;
          if (b.mode === 'traits' && b.bloodSurge && trackers(sheet).hunger < 5) {
            const die = rollD10();
            if (die < 6) sheet.hunger = Math.min(5, (Number(sheet.hunger) || 0) + 1);
            sheetChanged = true;
            surge = true;
            rows.push(await insertRoll(conn, { ...base, rollType: 'blood_surge', rouse: [die], hungerLevel: sheet.hunger, note: die >= 6 ? 'Blood Surge: No hunger gained' : 'Blood Surge: Hunger +1' }));
          }

          const effects = session?.metadata?.activeEffects?.[ch.id] || session?.metadata?.activeEffects?.[String(ch.id)] || [];
          const built = traitPool({
            sheet, clan: ch.clan, traits, specialty, ownSpecialtyOnly, surge,
            effects: b.mode === 'traits' ? effects : [],
            effectIds: Array.isArray(b.effectIds) ? b.effectIds : [],
            powerIds: b.mode === 'traits' && Array.isArray(b.powerIds) ? b.powerIds : [],
            situational: b.mode === 'traits' ? b.situational : null,
            ignoreImpairment: !!b.ignoreImpairment,
          });
          // Ignoring impairment costs a Willpower, taken here with the roll.
          if (b.ignoreImpairment && built.impaired) {
            if (trackers(sheet).willpowerLeft <= 0) fail(400, 'Not enough Willpower to ignore impairment.');
            sheet.willpower = { superficial: 0, aggravated: 0, ...(sheet.willpower || {}) };
            sheet.willpower.superficial = (Number(sheet.willpower.superficial) || 0) + 1;
            sheetChanged = true;
            built.parts.push('Impairment ignored (1 WP)');
          }
          const dice = rollPool(built.pool, trackers(sheet).hunger);
          rows.push(await insertRoll(conn, {
            ...base, rollType: b.mode === 'request' ? 'requested_roll' : 'pool_roll',
            normal: dice.normal, hunger: dice.hunger, hungerLevel: trackers(sheet).hunger, difficulty,
            note: [note, built.parts.join(' + ').replace(/\+ (−|-)/g, '$1'), difficulty ? `Diff ${difficulty}` : ''].filter(Boolean).join(' · '),
          }));
        } else if (b.mode === 'power') {
          const power = CATALOG.disciplines[b.discipline]?.powers?.[b.powerId];
          const owned = (sheet.disciplinePowers?.[b.discipline] || []).some(p => String(p?.id ?? p) === String(b.powerId));
          if (!power || !owned) fail(400, 'You don\'t have that power.');
          const traits = parsePowerPool(power.dicePool);
          if (!traits) fail(400, `${power.name} has no dice pool to roll.`);
          const built = traitPool({ sheet, clan: ch.clan, traits });
          const dice = rollPool(built.pool, trackers(sheet).hunger);
          rows.push(await insertRoll(conn, {
            ...base, rollType: 'discipline_roll', normal: dice.normal, hunger: dice.hunger, hungerLevel: trackers(sheet).hunger,
            note: `${b.discipline} • ${power.name}: ${built.parts.join(' + ')}`, extra: { disc: b.discipline, power_name: power.name },
          }));
        } else if (b.mode === 'frenzy') {
          if (!sheet.frenzyState) fail(400, 'You are not in frenzy.');
          const built = frenzyPool(sheet, ch.clan);
          const dice = rollPool(built.pool, 0);
          const resisted = dice.normal.some(d => d >= 6);
          const label = String(sheet.frenzyState);
          if (resisted) { sheet.frenzyState = null; sheetChanged = true; }
          rows.push(await insertRoll(conn, {
            ...base, rollType: 'frenzy_resistance', normal: dice.normal, hunger: [], hungerLevel: 0,
            note: `${resisted ? 'Resisted' : 'Failed to resist'} ${label} frenzy (${built.parts.join(' + ')})`,
          }));
        } else {
          fail(400, 'Unknown roll mode');
        }

        if (sheetChanged) await conn.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), ch.id]);
        await conn.commit();
        for (const row of rows) await afterSessionRoll(session, row);
        return reply.send({ roll: rows[rows.length - 1], rolls: rows, sheet });
      } catch (e) {
        await conn.rollback().catch(() => {});
        throw e;
      } finally {
        conn.release();
      }
    } catch (e) {
      if (e.status) return reply.status(e.status).send({ error: e.message });
      log.err('Dice roll failed', { message: e.message, stack: e.stack });
      return reply.status(500).send({ error: 'Failed to roll' });
    }
  });

  // Willpower reroll (V5): spend one Willpower to reroll up to three regular
  // dice of your own last roll, once. Logged as its own roll in the feed.
  fastify.post('/api/dice/rolls/:id/reroll', { preHandler: [authRequired] }, async (req, reply) => {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [[orig]] = await conn.query('SELECT * FROM dice_rolls WHERE id=? FOR UPDATE', [req.params.id]);
      if (!orig || orig.user_id !== req.user.id || !orig.character_id) fail(404, 'Roll not found');
      if (orig.rerolled) fail(400, 'That roll has already been rerolled.');
      if (NO_REROLL.has(orig.roll_type)) fail(400, 'Willpower can\'t reroll that kind of test.');
      if (orig.session_id) {
        const [[s]] = await conn.query('SELECT status FROM live_sessions WHERE id=?', [orig.session_id]);
        if (s?.status === 'ended') fail(400, 'That session has ended.');
      }
      const roll = formatRoll(orig);
      const normal = roll.results.normal || [];
      const picks = [...new Set((Array.isArray(req.body?.indices) ? req.body.indices : []).map(Number))]
        .filter(i => Number.isInteger(i) && i >= 0 && i < normal.length);
      if (!picks.length || picks.length > 3) fail(400, 'Pick one to three regular dice to reroll.');

      const [[ch]] = await conn.query('SELECT id, sheet FROM characters WHERE id=? FOR UPDATE', [orig.character_id]);
      const sheet = parseSheet(ch.sheet);
      if (trackers(sheet).willpowerLeft <= 0) fail(400, 'Not enough Willpower');
      sheet.willpower = { superficial: 0, aggravated: 0, ...(sheet.willpower || {}) };
      sheet.willpower.superficial = (Number(sheet.willpower.superficial) || 0) + 1;
      await conn.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), ch.id]);
      await conn.query('UPDATE dice_rolls SET rerolled=1 WHERE id=?', [orig.id]);

      const row = await insertRoll(conn, {
        userId: req.user.id, characterId: orig.character_id, characterName: orig.character_name, sessionId: orig.session_id,
        rollType: 'willpower_reroll', normal: normal.map((d, i) => (picks.includes(i) ? rollD10() : d)),
        hunger: roll.results.hunger || [], hungerLevel: orig.hunger, difficulty: roll.difficulty,
        note: `Willpower reroll of ${picks.length} ${picks.length === 1 ? 'die' : 'dice'} (spent 1 WP)`, isHidden: !!orig.is_hidden, rerolled: true,
      });
      await conn.commit();
      if (orig.session_id) {
        const [[s]] = await pool.query('SELECT id, session_code FROM live_sessions WHERE id=?', [orig.session_id]);
        await afterSessionRoll(s, row);
      }
      return reply.send({ roll: row, sheet });
    } catch (e) {
      await conn.rollback().catch(() => {});
      if (e.status) return reply.status(e.status).send({ error: e.message });
      log.err('Willpower reroll failed', { message: e.message });
      return reply.status(500).send({ error: 'Failed to reroll' });
    } finally {
      conn.release();
    }
  });

  /* -------------------- Dice log for the admin panel -------------------- */
  fastify.get('/api/admin/dice/rolls', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      let limitClause = '';
      const vals = [];

      // Allow the Stats Engine to pull all data, otherwise enforce a safe limit for the Logs tab
      if (req.query.limit !== 'all') {
        const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 1000);
        limitClause = `LIMIT ${limit}`;
      }

      const userId = Number(req.query.user_id) || null;
      const since = req.query.since ? new Date(req.query.since) : null;
      const where = ['r.pool > 0']; // dice only, not feed events (power activations)

      if (userId) { where.push('r.user_id=?'); vals.push(userId); }
      if (since && !isNaN(since.getTime())) { where.push('r.created_at >= ?'); vals.push(since); }

      const [rows] = await pool.query(`
        SELECT
          r.id, r.user_id, r.character_id, r.session_id, r.roll_type, r.pool, r.hunger, r.sides,
          r.results_json, r.successes, r.crit_pairs, r.messy_crit, r.bestial_failure, r.rerolled,
          r.note, r.is_hidden, r.created_at,
          u.display_name AS user_name,
          COALESCE(r.character_name, c.name) AS char_name, c.clan AS char_clan,
          s.session_code
        FROM dice_rolls r
        LEFT JOIN users u ON u.id = r.user_id
        LEFT JOIN characters c ON c.id = r.character_id
        LEFT JOIN live_sessions s ON s.id = r.session_id
        WHERE ${where.join(' AND ')}
        ORDER BY r.created_at DESC
        ${limitClause}
      `, vals);
      reply.send({ rolls: rows });
    } catch (e) {
      log.err('Admin fetch dice rolls failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch dice rolls' });
    }
  });

  // Admin: Clear All Dice Rolls
  fastify.delete('/api/admin/dice/rolls/all', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [result] = await pool.query('DELETE FROM dice_rolls');
      log.adm('Cleared all dice rolls', { admin_id: req.user.id, affectedRows: result.affectedRows });
      reply.send({ success: true, count: result.affectedRows });
    } catch (e) {
      log.err('Failed to clear dice rolls', { error: e.message });
      reply.status(500).json({ success: false, error: 'Internal Server Error' });
    }
  });
};
