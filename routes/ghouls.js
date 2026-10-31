// routes/ghouls.js
//
// Ghouls and retainers at the table. The Storyteller brings a player's retainer
// into a live session (metadata.ghouls, written by the dashboard like npcs);
// the player who plays it (owner, or a coterie ghoul's domitor) then sees its
// trackers and rolls for it (POST /api/dice/roll mode 'ghoul'). Health and
// Willpower change only here (services/ghoulTrackers.js).
const { parseSheet } = require('../utils/sheet');
const { isAdmin } = require('../services/guards');
const { insertRoll } = require('../services/rolls');
const { getSessionRow, emitSessionRefresh } = require('../services/liveSession');
const { attachFeeding } = require('../services/ghoulFeeding');
const {
  sessionGhoulIds, lockSessionGhoul, ghoulTrackers, applyGhoulChange, withRetainerLock,
} = require('../services/ghoulTrackers');

const RETAINER_SELECT = `
  SELECT r.id, r.name, r.tier, r.sheet, r.created_at, r.character_id, r.coterie_id, r.domitor_character_id,
         co.name AS coterie_name,
         ctl.id AS controller_id, ctl.name AS controller_name, ctl.user_id AS controller_user_id
    FROM retainers r
    LEFT JOIN coteries co ON co.id = r.coterie_id
    LEFT JOIN characters ctl ON ctl.id = COALESCE(r.character_id, r.domitor_character_id)`;

// What the table shows for one retainer: its sheet, trackers and feeding state.
const present = (r) => {
  const sheet = parseSheet(r.sheet) || {};
  return {
    id: r.id, name: r.name, tier: r.tier, created_at: r.created_at, coterie_id: r.coterie_id, coterie_name: r.coterie_name,
    isGhoul: sheet.isGhoul === true, sheet, trackers: ghoulTrackers(sheet),
    controller: r.controller_id ? { id: r.controller_id, name: r.controller_name, user_id: r.controller_user_id } : null,
  };
};

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  async function sessionFor(req) {
    const s = await getSessionRow(req.params.id);
    if (!s) return null;
    const [[full]] = await pool.query('SELECT id, session_code, status, metadata FROM live_sessions WHERE id=?', [s.id]);
    full.metadata = parseSheet(full.metadata) || {};
    return full;
  }

  /**
   * GET /api/live-session/:id/ghouls
   *  Storyteller: { ghouls: the session's retainers, candidates: participants' retainers not yet in it }
   *  Player:      { ghouls: only the session retainers they play }
   */
  fastify.get('/api/live-session/:id/ghouls', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const session = await sessionFor(req);
      if (!session) return reply.status(404).send({ error: 'Session not found' });
      const admin = isAdmin(req.user);
      if (!admin) {
        const [seat] = await pool.query('SELECT 1 FROM live_session_participants WHERE session_id=? AND user_id=? LIMIT 1', [session.id, req.user.id]);
        if (!seat.length || session.status === 'ended') return reply.status(403).send({ error: 'Not a participant in this session' });
      }
      const ids = sessionGhoulIds(session.metadata);
      const [rows] = ids.length ? await pool.query(`${RETAINER_SELECT} WHERE r.id IN (?) ORDER BY r.name`, [ids]) : [[]];
      let ghouls = rows.map(present);
      if (!admin) ghouls = ghouls.filter((g) => Number(g.controller?.user_id) === Number(req.user.id));
      await attachFeeding(pool, ghouls, (g) => g.isGhoul);
      if (!admin) return reply.send({ ghouls });

      // Retainers of the players at the table: personal ones and their coteries'.
      const [cands] = await pool.query(
        `${RETAINER_SELECT}
          WHERE (r.character_id IN (SELECT c.id FROM live_session_participants p JOIN characters c ON c.user_id = p.user_id WHERE p.session_id = ?)
             OR r.coterie_id IN (SELECT m.coterie_id FROM live_session_participants p JOIN coterie_members m ON m.user_id = p.user_id WHERE p.session_id = ?))
          ORDER BY ctl.name, r.name`,
        [session.id, session.id]
      );
      const candidates = cands.filter((r) => !ids.includes(Number(r.id))).map(present)
        .map(({ id, name, tier, isGhoul, controller, coterie_name }) => ({ id, name, tier, isGhoul, controller, coterie_name }));
      reply.send({ ghouls, candidates });
    } catch (e) {
      log.err('Session ghouls failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load ghouls' });
    }
  });

  /**
   * PATCH /api/ghouls/:rid/trackers — Storyteller: Health / Willpower deltas or
   * structured damage (see applyGhoulChange). { sessionId } refreshes that table.
   */
  fastify.patch('/api/ghouls/:rid/trackers', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const b = req.body || {};
      const result = await withRetainerLock(pool, Number(req.params.rid), async (sheet) => {
        applyGhoulChange(sheet, b);
      });
      if (result.notFound) return reply.status(404).send({ error: 'Retainer not found' });
      log.adm('Retainer trackers changed', { retainer_id: Number(req.params.rid), change: b, by_user_id: req.user.id });
      if (b.sessionId) await emitSessionRefresh(fastify.io, b.sessionId);
      reply.send({ trackers: ghoulTrackers(result.sheet) });
    } catch (e) {
      log.err('Retainer tracker change failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to update trackers' });
    }
  });

  /**
   * POST /api/live-session/:id/ghouls/:rid/overreach { power }
   * V5 Core: a ghoul using a power above level 1 (Draught of Elegance, alchemy,
   * other causes) takes 1 Aggravated Health instead of a Rouse Check. Logged
   * on the session feed.
   */
  fastify.post('/api/live-session/:id/ghouls/:rid/overreach', { preHandler: [authRequired] }, async (req, reply) => {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const session = await sessionFor(req);
      if (!session || session.status === 'ended') throw Object.assign(new Error('Session not found'), { status: 404 });
      const admin = isAdmin(req.user);
      if (!admin) {
        const [seat] = await conn.query('SELECT 1 FROM live_session_participants WHERE session_id=? AND user_id=? LIMIT 1', [session.id, req.user.id]);
        if (!seat.length) throw Object.assign(new Error('Join the session first.'), { status: 403 });
      }
      const { row, sheet, controller } = await lockSessionGhoul(conn, session, Number(req.params.rid), req.user, admin);
      if (sheet.isGhoul !== true) throw Object.assign(new Error('Only a ghoul has Discipline powers.'), { status: 400 });
      applyGhoulChange(sheet, { damage: { amount: 1, type: 'aggravated' } });
      await conn.query('UPDATE retainers SET sheet=? WHERE id=?', [JSON.stringify(sheet), row.id]);
      const power = String((req.body || {}).power || '').trim().slice(0, 80);
      const t = ghoulTrackers(sheet);
      await insertRoll(conn, {
        userId: req.user.id, characterId: controller?.id ?? null, characterName: row.name, sessionId: session.id,
        rollType: 'ghoul_overreach', extra: { retainer_id: row.id },
        note: `Used a power above level 1${power ? ` (${power})` : ''}: 1 Aggravated Health instead of a Rouse Check${t.dead ? '. Health is full of Aggravated damage.' : ''}`,
      });
      await conn.commit();
      await emitSessionRefresh(fastify.io, session.id);
      reply.send({ trackers: t });
    } catch (e) {
      await conn.rollback().catch(() => {});
      if (e.status) return reply.status(e.status).send({ error: e.message });
      log.err('Ghoul overreach failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to apply the cost' });
    } finally {
      conn.release();
    }
  });
};
