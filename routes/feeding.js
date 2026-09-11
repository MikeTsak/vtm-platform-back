// routes/feeding.js
//
// The Feeding system: a required, server-authoritative hunting roll gating
// downtime submission each 3-week cycle (see routes/downtimes.js's
// feeding-gate check). Dice are rolled here, not on the client — same
// "server is the source of truth" principle as routes/mechanics.js — so a
// player can never fabricate or redo a masquerade-affecting result. A roll
// is persisted as 'pending' the instant it's made; from there the only two
// moves are POST /:id/reroll (spend 1 Willpower, once) or POST /:id/confirm
// (lock it in). Reloading the page always reconstructs the same pending row
// via GET /status — there is no way to discard a roll and start over.

const { getSetting, setSetting } = require('../utils/settings');
const { getCycleInfo } = require('../utils/feedingCycle');
const { huntingDifficulty } = require('../data/huntingDifficulty');
const { chasseBonus } = require('../data/chasseMerits');
const { PREDATOR_HUNTING_POOLS } = require('../data/predatorHuntingPools');
const { rollDice, computeFeedingOutcome, OUTCOME_DELTAS } = require('../services/feedingDice');
const { pickFlavor } = require('../data/predatorFlavor');
const { runFeedingDecay } = require('../services/feedingDecay');

function parseSheet(raw) {
  if (!raw) return {};
  if (typeof raw === 'string') {
    try { return JSON.parse(raw) || {}; } catch { return {}; }
  }
  return raw;
}

// Character sheets store this as `predator_type` (snake_case) everywhere the
// rest of the app reads it (CharacterEditor.jsx's edit field, CharacterView.jsx,
// xp-shop/suggestions.js, pdfGenerator.js) — `predatorType` only ever appears
// as a fallback for the brief window between initial creation and a
// character's first edit, since CharacterEditor.jsx's save is a full sheet
// overwrite that only knows about the snake_case field.
function getPredatorType(sheet) {
  return sheet?.predator_type || sheet?.predatorType || null;
}

function getTraitValue(sheet, traitName) {
  if (!traitName) return 0;
  if (sheet?.attributes?.[traitName] !== undefined) return Number(sheet.attributes[traitName]) || 0;
  const skillData = sheet?.skills?.[traitName];
  if (skillData !== undefined) {
    if (typeof skillData === 'object') return Number(skillData.dots) || 0;
    return Number(skillData) || 0;
  }
  if (sheet?.disciplines?.[traitName] !== undefined) return Number(sheet.disciplines[traitName]) || 0;
  return 0;
}

const clamp = (v, min, max) => Math.max(min, Math.min(max, Number(v) || 0));

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, sendPushNotification } = opts;

  async function getMyCharacter(userId) {
    const [rows] = await pool.query('SELECT id, sheet FROM characters WHERE user_id=?', [userId]);
    if (!rows.length) return null;
    return { id: rows[0].id, sheet: parseSheet(rows[0].sheet) };
  }

  async function getCurrentCycle() {
    const anchor = await getSetting('feeding_cycle_anchor', new Date().toISOString());
    return getCycleInfo(anchor);
  }

  async function isFeedingEnabled() {
    return (await getSetting('feeding_enabled', 'true')) === 'true';
  }

  /* -------------------- Status -------------------- */
  fastify.get('/api/feeding/status', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const enabled = await isFeedingEnabled();
      if (!enabled) return reply.send({ enabled: false });

      const { cycleIndex, cycleStart, cycleEnd } = await getCurrentCycle();
      const char = await getMyCharacter(req.user.id);
      if (!char) {
        return reply.send({ enabled: true, cycleIndex, cycleStart, cycleEnd, noCharacter: true });
      }

      const predatorType = getPredatorType(char.sheet);
      const canAutomate = !!predatorType && (PREDATOR_HUNTING_POOLS[predatorType]?.length > 0);
      const pools = predatorType ? (PREDATOR_HUNTING_POOLS[predatorType] || []) : [];

      const [ownedRows] = await pool.query(
        'SELECT division FROM domain_claims WHERE owner_character_id=? LIMIT 1',
        [char.id]
      );
      const myDivision = ownedRows.length ? ownedRows[0].division : null;

      const [pendingRows] = await pool.query(
        "SELECT * FROM feedings WHERE character_id=? AND status='pending' ORDER BY id DESC LIMIT 1",
        [char.id]
      );
      const [resolvedRows] = await pool.query(
        "SELECT * FROM feedings WHERE character_id=? AND cycle_index=? AND status='resolved' LIMIT 1",
        [char.id, cycleIndex]
      );

      reply.send({
        enabled: true,
        cycleIndex,
        cycleStart,
        cycleEnd,
        predatorType,
        canAutomate,
        pools: pools.map((p) => ({
          pool: p.pool,
          total: getTraitValue(char.sheet, p.attribute) + getTraitValue(char.sheet, p.skill),
        })),
        myDivision,
        pending: pendingRows[0] || null,
        resolvedThisCycle: resolvedRows[0] || null,
      });
    } catch (err) {
      log.err('GET /api/feeding/status failed', { error: err.message });
      reply.status(500).json({ error: 'Database error fetching feeding status' });
    }
  });

  /* -------------------- Roll -------------------- */
  fastify.post('/api/feeding/roll', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      if (!(await isFeedingEnabled())) return reply.status(400).json({ error: 'The Feeding system is currently disabled.' });

      const char = await getMyCharacter(req.user.id);
      if (!char) return reply.status(404).json({ error: 'No character found for this account.' });

      const predatorType = getPredatorType(char.sheet);
      const pools = predatorType ? (PREDATOR_HUNTING_POOLS[predatorType] || []) : [];
      if (!predatorType) return reply.status(400).json({ error: 'Set a Predator Type on your character sheet before feeding.' });
      if (!pools.length) {
        return reply.status(400).json({ error: `${predatorType} isn't automatable for the Feeding roll. It's GM-adjudicated. Use a Monthly Action to describe your feeding instead.` });
      }

      const division = Number(req.body?.division);
      const poolIndex = Number(req.body?.poolIndex ?? 0);
      if (!Number.isInteger(poolIndex) || poolIndex < 0 || poolIndex >= pools.length) {
        return reply.status(400).json({ error: 'Invalid hunting method selected.' });
      }
      const difficulty = huntingDifficulty(division);
      if (difficulty === null) return reply.status(400).json({ error: 'Invalid domain.' });

      const { cycleIndex } = await getCurrentCycle();

      const [existing] = await pool.query(
        "SELECT id, status FROM feedings WHERE character_id=? AND cycle_index=? AND status IN ('pending','resolved') LIMIT 1",
        [char.id, cycleIndex]
      );
      if (existing.length) {
        return reply.status(409).json({ error: 'You already have a feeding roll for this cycle.', feedingId: existing[0].id, status: existing[0].status });
      }

      const chosenPool = pools[poolIndex];
      const basePool = getTraitValue(char.sheet, chosenPool.attribute) + getTraitValue(char.sheet, chosenPool.skill);
      const { bonusDice, meritsApplied } = chasseBonus(division, predatorType);
      const totalPool = clamp(basePool + bonusDice, 0, 30);

      const hunger = clamp(char.sheet?.hunger ?? 1, 0, 5);
      const hungerCount = Math.min(totalPool, hunger);
      const normalCount = totalPool - hungerCount;
      const normalDice = rollDice(normalCount);
      const hungerDice = rollDice(hungerCount);
      const outcome = computeFeedingOutcome(normalDice, hungerDice, difficulty);

      const [result] = await pool.query(
        `INSERT INTO feedings
          (character_id, division, predator_type, pool_label, dice_pool, difficulty, bonus_dice,
           chasse_merits_applied, hunger_before, normal_dice, hunger_dice, outcome, status, cycle_index)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
        [
          char.id, division, predatorType, chosenPool.pool, totalPool, difficulty, bonusDice,
          JSON.stringify(meritsApplied), hunger, JSON.stringify(normalDice), JSON.stringify(hungerDice),
          outcome.tier, cycleIndex,
        ]
      );

      const [rows] = await pool.query('SELECT * FROM feedings WHERE id=?', [result.insertId]);
      log.info('Feeding roll made', { character_id: char.id, division, tier: outcome.tier });
      reply.send({ feeding: rows[0], projected: OUTCOME_DELTAS[outcome.tier] });
    } catch (err) {
      log.err('POST /api/feeding/roll failed', { error: err.message });
      reply.status(500).json({ error: 'Database error making feeding roll' });
    }
  });

  /* -------------------- Reroll (spend Willpower, once) -------------------- */
  fastify.post('/api/feeding/:id/reroll', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const feedingId = Number(req.params.id);
      const [rows] = await pool.query('SELECT * FROM feedings WHERE id=?', [feedingId]);
      if (!rows.length) return reply.status(404).json({ error: 'Feeding roll not found.' });
      const feeding = rows[0];

      const [charRows] = await pool.query('SELECT user_id, sheet FROM characters WHERE id=?', [feeding.character_id]);
      if (!charRows.length) return reply.status(404).json({ error: 'Character not found.' });
      if (charRows[0].user_id !== req.user.id && req.user.role !== 'admin') {
        return reply.status(403).json({ error: 'Forbidden' });
      }
      if (feeding.status !== 'pending') return reply.status(400).json({ error: 'This roll is already resolved.' });
      if (feeding.wp_rerolled) return reply.status(400).json({ error: 'You have already spent Willpower on this roll.' });

      const selected = Array.from(new Set(req.body?.selectedIndices || [])).slice(0, 3);
      if (!selected.length) return reply.status(400).json({ error: 'Select at least one die to reroll.' });

      let sheet = parseSheet(charRows[0].sheet);
      if (!sheet.willpower) sheet.willpower = { superficial: 0, aggravated: 0 };
      const comp = Number(sheet.attributes?.Composure) || 1;
      const reso = Number(sheet.attributes?.Resolve) || 1;
      const max = comp + reso;
      const currentWp = (Number(sheet.willpower.superficial) || 0) + (Number(sheet.willpower.aggravated) || 0);
      if (currentWp >= max) return reply.status(400).json({ error: 'Not enough Willpower.' });

      sheet.willpower.superficial = (Number(sheet.willpower.superficial) || 0) + 1;
      await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), feeding.character_id]);

      const normalDice = Array.isArray(feeding.normal_dice) ? feeding.normal_dice : JSON.parse(feeding.normal_dice || '[]');
      const hungerDice = Array.isArray(feeding.hunger_dice) ? feeding.hunger_dice : JSON.parse(feeding.hunger_dice || '[]');
      const rerolled = rollDice(selected.length);
      let r = 0;
      const nextNormal = normalDice.map((die, idx) => (selected.includes(idx) ? rerolled[r++] : die));
      const outcome = computeFeedingOutcome(nextNormal, hungerDice, feeding.difficulty);

      await pool.query(
        "UPDATE feedings SET normal_dice=?, outcome=?, wp_rerolled=1 WHERE id=?",
        [JSON.stringify(nextNormal), outcome.tier, feedingId]
      );

      const [updated] = await pool.query('SELECT * FROM feedings WHERE id=?', [feedingId]);
      reply.send({ feeding: updated[0], projected: OUTCOME_DELTAS[outcome.tier], sheet });
    } catch (err) {
      log.err('POST /api/feeding/:id/reroll failed', { error: err.message });
      reply.status(500).json({ error: 'Database error rerolling' });
    }
  });

  /* -------------------- Confirm (final — applies Hunger/Safety) -------------------- */
  fastify.post('/api/feeding/:id/confirm', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const feedingId = Number(req.params.id);
      const [rows] = await pool.query('SELECT * FROM feedings WHERE id=?', [feedingId]);
      if (!rows.length) return reply.status(404).json({ error: 'Feeding roll not found.' });
      const feeding = rows[0];

      const [charRows] = await pool.query('SELECT id, user_id, sheet FROM characters WHERE id=?', [feeding.character_id]);
      if (!charRows.length) return reply.status(404).json({ error: 'Character not found.' });
      if (charRows[0].user_id !== req.user.id && req.user.role !== 'admin') {
        return reply.status(403).json({ error: 'Forbidden' });
      }
      if (feeding.status !== 'pending') return reply.status(400).json({ error: 'This roll is already resolved.' });

      const deltas = OUTCOME_DELTAS[feeding.outcome];
      if (!deltas) return reply.status(500).json({ error: 'Unresolved outcome on this roll.' });

      let sheet = parseSheet(charRows[0].sheet);
      sheet.hunger = clamp((Number(sheet.hunger) || 0) + deltas.hunger, 0, 5);
      await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), feeding.character_id]);

      const [existingClaim] = await pool.query(
        'SELECT division, owner_character_id, owner_npc_id, owner_name, safety_rating FROM domain_claims WHERE division=?',
        [feeding.division]
      );
      if (existingClaim.length) {
        await pool.query(
          'UPDATE domain_claims SET safety_rating = GREATEST(0, LEAST(10, IFNULL(safety_rating, 10) + ?)) WHERE division=?',
          [deltas.safety, feeding.division]
        );
      } else {
        await pool.query(
          'INSERT INTO domain_claims (division, owner_name, color, safety_rating) VALUES (?, NULL, ?, ?)',
          [feeding.division, '#888888', clamp(10 + deltas.safety, 0, 10)]
        );
      }

      await pool.query(
        "UPDATE feedings SET status='resolved', resolved_at=NOW(), hunger_delta=?, safety_delta=? WHERE id=?",
        [deltas.hunger, deltas.safety, feedingId]
      );

      // Domain incident: only on a bad-for-the-domain outcome, only when
      // hunting someone else's (player-owned) division.
      const isIncidentOutcome = ['bestial_failure', 'failure', 'messy_critical'].includes(feeding.outcome);
      if (isIncidentOutcome && existingClaim.length && existingClaim[0].owner_character_id
          && existingClaim[0].owner_character_id !== feeding.character_id) {
        const [ownerRows] = await pool.query('SELECT id, user_id, name FROM characters WHERE id=?', [existingClaim[0].owner_character_id]);
        if (ownerRows.length) {
          const [hunterRows] = await pool.query('SELECT name FROM characters WHERE id=?', [feeding.character_id]);
          const hunterName = hunterRows[0]?.name || 'An unknown Kindred';
          const flavor = pickFlavor(feeding.predator_type);

          await pool.query(
            `INSERT INTO domain_incidents
              (feeding_id, division, owner_user_id, owner_character_id, intruder_character_id, intruder_character_name, outcome, flavor_text)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [feedingId, feeding.division, ownerRows[0].user_id, ownerRows[0].id, feeding.character_id, hunterName, feeding.outcome, flavor]
          );

          sendPushNotification(
            ownerRows[0].user_id,
            'Feeding Incident',
            `${hunterName} hunted in your domain (Division ${feeding.division}) and drew attention.`,
            {}, 'court'
          ).catch(() => {});
        }
      }

      reply.send({ ok: true, tier: feeding.outcome, hungerDelta: deltas.hunger, safetyDelta: deltas.safety, sheet });
    } catch (err) {
      log.err('POST /api/feeding/:id/confirm failed', { error: err.message });
      reply.status(500).json({ error: 'Database error confirming feeding roll' });
    }
  });

  /* -------------------- Domain Incidents -------------------- */
  fastify.get('/api/domain-incidents/mine', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(
        'SELECT * FROM domain_incidents WHERE owner_user_id=? AND dismissed_at IS NULL ORDER BY created_at DESC',
        [req.user.id]
      );
      reply.send({ incidents: rows });
    } catch (err) {
      log.err('GET /api/domain-incidents/mine failed', { error: err.message });
      reply.status(500).json({ error: 'Database error fetching incidents' });
    }
  });

  fastify.patch('/api/domain-incidents/:id/dismiss', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const id = Number(req.params.id);
      const [rows] = await pool.query('SELECT owner_user_id FROM domain_incidents WHERE id=?', [id]);
      if (!rows.length) return reply.status(404).json({ error: 'Not found' });
      if (rows[0].owner_user_id !== req.user.id && req.user.role !== 'admin') {
        return reply.status(403).json({ error: 'Forbidden' });
      }
      await pool.query('UPDATE domain_incidents SET dismissed_at=NOW() WHERE id=?', [id]);
      reply.send({ ok: true });
    } catch (err) {
      log.err('PATCH /api/domain-incidents/:id/dismiss failed', { error: err.message });
      reply.status(500).json({ error: 'Database error dismissing incident' });
    }
  });

  /* -------------------- Admin -------------------- */
  fastify.post('/api/admin/feeding/status', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const enabled = !!req.body?.enabled;
      await setSetting('feeding_enabled', enabled ? 'true' : 'false');
      log.adm('Feeding system toggled', { user: req.user.id, enabled });
      reply.send({ enabled });
    } catch (err) {
      log.err('POST /api/admin/feeding/status failed', { error: err.message });
      reply.status(500).json({ error: 'Database error updating feeding status' });
    }
  });

  fastify.get('/api/admin/feeding/log', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
        SELECT f.*, c.name AS character_name
        FROM feedings f
        JOIN characters c ON c.id = f.character_id
        ORDER BY f.created_at DESC
        LIMIT 200
      `);
      reply.send({ log: rows });
    } catch (err) {
      log.err('GET /api/admin/feeding/log failed', { error: err.message });
      reply.status(500).json({ error: 'Database error fetching feeding log' });
    }
  });

  fastify.post('/api/admin/feeding/force-new-cycle', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const now = new Date().toISOString();
      await setSetting('feeding_cycle_anchor', now);
      log.adm('Feeding cycle force-reset', { user: req.user.id });
      reply.send({ ok: true, cycleAnchor: now });
    } catch (err) {
      log.err('POST /api/admin/feeding/force-new-cycle failed', { error: err.message });
      reply.status(500).json({ error: 'Database error resetting cycle' });
    }
  });

  fastify.post('/api/admin/feeding/run-decay', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const result = await runFeedingDecay(pool, log, { force: true });
      log.adm('Feeding decay manually triggered', { user: req.user.id, result });
      reply.send(result);
    } catch (err) {
      log.err('POST /api/admin/feeding/run-decay failed', { error: err.message });
      reply.status(500).json({ error: 'Database error running decay' });
    }
  });
};
