// routes/mechanics.js
//
// Server-authoritative V5 mechanics — rouse checks, willpower spends, mending.
// Players never write Hunger, Health or Willpower directly (see
// utils/playerSheetEdit.js); they change only through these rolls, or by a
// Storyteller (PATCH /api/live-session/:id/players/:charId, admin sheet editor).

const { isOwnerOrAdmin } = require('../services/guards');
const { parseSheet } = require('../utils/sheet');
const { CATALOG } = require('../utils/xpPurchase');
const { rollD10 } = require('../services/dice');
const { insertRoll } = require('../services/rolls');

// What a logged Rouse Check is labelled as in the feed and dice log.
const ROUSE_SOURCES = new Set(['rouse_check', 'discipline_rouse_check', 'blush_of_life']);

// V5 Blood Potency table (mirrors getBloodPotencyStats in the front end).
const ROUSE_REROLL_LEVEL = [0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5];
const MEND_AMOUNT = [1, 1, 2, 2, 3, 3, 3, 3, 4, 4, 5];
const bloodPotency = (sheet, clan) => Math.min(10, Math.max(0, Number(sheet.blood_potency ?? (clan === 'Thin-blood' ? 0 : 1)) || 0));

/** One Rouse Check against the sheet (mutates it): Hunger +1 on a fail, frenzy at Hunger 5. */
function rouse(sheet, advantage) {
  const dice = advantage ? [rollD10(), rollD10()] : [rollD10()];
  const success = dice.some(d => d >= 6);
  const before = Number(sheet.hunger) || 0;
  if (!success) {
    if (before >= 5) sheet.frenzyState = 'hunger';
    sheet.hunger = Math.min(5, before + 1);
  }
  return { success, dice };
}

module.exports = async function (fastify, opts) {
  const { pool, authRequired } = opts;

  /**
   * Locks the character row, checks ownership, runs `fn(sheet, row, log)`
   * and saves the sheet. `log(roll)` records a roll in dice_rolls, in the
   * live session named by body.sessionId when there is one.
   */
  async function withLockedSheet(req, reply, fn) {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [[row]] = await conn.query('SELECT id, user_id, name, clan, sheet FROM characters WHERE id=? FOR UPDATE', [req.params.id]);
      if (!row) { await conn.rollback(); return reply.status(404).send({ error: 'Not found' }); }
      if (!isOwnerOrAdmin(req.user, row.user_id)) { await conn.rollback(); return reply.status(403).send({ error: 'Forbidden' }); }
      const sheet = parseSheet(row.sheet);
      let session = null;
      if (req.body?.sessionId) {
        [[session]] = await conn.query("SELECT id, session_code FROM live_sessions WHERE (session_code=? OR id=?) AND status='active'", [req.body.sessionId, req.body.sessionId]);
      }
      const logged = [];
      const logRoll = async (roll) => logged.push(await insertRoll(conn, {
        userId: row.user_id, characterId: row.id, characterName: row.name, sessionId: session?.id ?? null,
        isHidden: !!req.body?.isHidden, hungerLevel: sheet.hunger, ...roll,
      }));
      const result = await fn(sheet, row, logRoll);
      if (result?.error) { await conn.rollback(); return reply.status(400).send({ error: result.error }); }
      await conn.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), row.id]);
      await conn.commit();
      if (session && fastify.io) {
        for (const key of new Set([session.session_code, String(session.id)].filter(Boolean))) fastify.io.to(`session_${key}`).emit('refresh_session');
      }
      return reply.send({ ...result, sheet, logged });
    } catch (e) {
      await conn.rollback().catch(() => {});
      req.log?.error?.(e);
      return reply.status(500).send({ error: 'Mechanic failed' });
    } finally {
      conn.release();
    }
  }

  // Rouse Check. Blood Potency grants a second die only for an owned
  // Discipline power at or below its reroll level, decided here, not by the
  // client: body { discipline, powerId } names the power being used.
  fastify.post('/api/characters/:id/rouse', { preHandler: [authRequired] }, (req, reply) =>
    withLockedSheet(req, reply, async (sheet, row, logRoll) => {
      const { discipline, powerId, source } = req.body || {};
      let advantage = false;
      if (discipline && powerId) {
        const power = CATALOG.disciplines[discipline]?.powers?.[powerId];
        const owned = (sheet.disciplinePowers?.[discipline] || []).some(p => String(p?.id ?? p) === String(powerId));
        advantage = !!power && owned && power.level <= ROUSE_REROLL_LEVEL[bloodPotency(sheet, row.clan)];
      }
      const { success, dice } = rouse(sheet, advantage);
      const power = discipline && powerId ? CATALOG.disciplines[discipline]?.powers?.[powerId] : null;
      await logRoll({
        rollType: ROUSE_SOURCES.has(source) ? source : 'rouse_check', rouse: dice,
        note: `${power ? `${discipline} • ${power.name}: ` : ''}${success ? 'No Hunger gained' : 'Hunger +1'}${advantage ? ' (BP reroll)' : ''}`,
      });
      return { success, die1: dice[0], die2: dice[1] ?? null, advantage, nextHunger: sheet.hunger };
    }));

  // Spend one Willpower (marks one Superficial Willpower damage).
  fastify.post('/api/characters/:id/spend-wp', { preHandler: [authRequired] }, (req, reply) =>
    withLockedSheet(req, reply, async (sheet) => {
      if (!sheet.willpower) sheet.willpower = { superficial: 0, aggravated: 0 };
      const max = (Number(sheet.attributes?.Composure) || 1) + (Number(sheet.attributes?.Resolve) || 1);
      const used = (Number(sheet.willpower.superficial) || 0) + (Number(sheet.willpower.aggravated) || 0);
      if (used >= max) return { error: 'Not enough Willpower' };
      sheet.willpower.superficial = (Number(sheet.willpower.superficial) || 0) + 1;
      return { ok: true };
    }));

  // Mend (V5): one Rouse Check heals Superficial damage by the Blood Potency
  // mend amount; three Rouse Checks heal one Aggravated. body { type }.
  fastify.post('/api/characters/:id/mend', { preHandler: [authRequired] }, (req, reply) =>
    withLockedSheet(req, reply, async (sheet, row, logRoll) => {
      const aggravated = req.body?.type === 'aggravated';
      sheet.health = { superficial: 0, aggravated: 0, ...(sheet.health || {}) };
      const key = aggravated ? 'aggravated' : 'superficial';
      const before = Number(sheet.health[key]) || 0;
      if (before <= 0) return { error: `No ${key} damage to mend.` };
      const rolls = Array.from({ length: aggravated ? 3 : 1 }, () => rouse(sheet, false));
      const healed = Math.min(before, aggravated ? 1 : MEND_AMOUNT[bloodPotency(sheet, row.clan)]);
      sheet.health[key] = before - healed;
      const fails = rolls.filter(r => !r.success).length;
      await logRoll({
        rollType: 'mend_rouse', rouse: rolls.flatMap(r => r.dice),
        note: `Mend ${key}: healed ${healed}${fails ? `, Hunger +${fails}` : ''}`,
      });
      return { healed, type: key, rolls, nextHunger: sheet.hunger };
    }));
};
