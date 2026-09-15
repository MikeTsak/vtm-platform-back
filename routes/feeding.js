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
const { PREDATOR_HUNTING_POOLS, PREDATOR_SPECIALTIES } = require('../data/predatorHuntingPools');
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

function hasRelevantSpecialty(sheet, predatorType, chosenSkill) {
  if (!sheet || !predatorType || !chosenSkill) return false;
  
  const granted = PREDATOR_SPECIALTIES[predatorType] || [];
  const relevantGrantedSpecs = granted
    .filter(s => s.toLowerCase().startsWith(chosenSkill.toLowerCase() + ':'))
    .map(s => s.split(':')[1].trim().toLowerCase());
  
  if (relevantGrantedSpecs.length === 0) return false;

  if (Array.isArray(sheet.specialties)) {
    for (const specStr of sheet.specialties) {
      if (typeof specStr === 'string' && specStr.toLowerCase().startsWith(chosenSkill.toLowerCase() + ':')) {
        const specName = specStr.split(':')[1].trim().toLowerCase();
        if (relevantGrantedSpecs.includes(specName)) return true;
      }
    }
  }

  if (sheet.skills && sheet.skills[chosenSkill] && Array.isArray(sheet.skills[chosenSkill].specialties)) {
    for (const specName of sheet.skills[chosenSkill].specialties) {
      if (typeof specName === 'string' && relevantGrantedSpecs.includes(specName.trim().toLowerCase())) {
        return true;
      }
    }
  }

  return false;
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
    let anchor = await getSetting('feeding_cycle_anchor', null);
    if (!anchor || Number.isNaN(new Date(anchor).getTime())) {
      anchor = new Date().toISOString();
      await setSetting('feeding_cycle_anchor', anchor);
    }
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

      // Herd background: stored in sheet.advantages.merits[] (not sheet.backgrounds[]).
      // Some entries only have a name field (no id), so fall back to name match.
      const sheetMerits = Array.isArray(char.sheet?.advantages?.merits) ? char.sheet.advantages.merits : [];
      const herdEntry = sheetMerits.find(b =>
        String(b.id || '').toLowerCase().includes('herd__herd') ||
        String(b.name || '').toLowerCase() === 'herd'
      );
      const herdDots = herdEntry ? clamp(Number(herdEntry.dots) || 0, 0, 5) : 0;

      // herd_current tracks the available pool (starts = dots, depletes on use, regens +1/cycle).
      // Undefined means never used — treat as full.
      const herdCurrent = herdDots > 0
        ? clamp(
            char.sheet.herd_current !== undefined ? Number(char.sheet.herd_current) : herdDots,
            0, herdDots
          )
        : 0;

      reply.send({
        enabled: true,
        cycleIndex,
        cycleStart,
        cycleEnd,
        predatorType,
        canAutomate,
        herdDots,
        herdCurrent,
          pools: pools.map((p) => {
            let specBonus = 0;
            if (hasRelevantSpecialty(char.sheet, predatorType, p.skill)) {
              specBonus = 1;
            }
            return {
              pool: p.pool,
              total: getTraitValue(char.sheet, p.attribute) + getTraitValue(char.sheet, p.skill) + specBonus,
              specialtyBonus: specBonus
            };
          }),
        myDivision,
        pending: pendingRows[0] || null,
        resolvedThisCycle: resolvedRows[0] || null,
      });
    } catch (err) {
      log.err('GET /api/feeding/status failed', { error: err.message });
      reply.status(500).send({ error: 'Database error fetching feeding status' });
    }
  });

  /* -------------------- Roll -------------------- */
  fastify.post('/api/feeding/roll', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      if (!(await isFeedingEnabled())) return reply.status(400).send({ error: 'The Feeding system is currently disabled.' });

      const char = await getMyCharacter(req.user.id);
      if (!char) return reply.status(404).send({ error: 'No character found for this account.' });

      const predatorType = getPredatorType(char.sheet);
      const pools = predatorType ? (PREDATOR_HUNTING_POOLS[predatorType] || []) : [];
      if (!predatorType) return reply.status(400).send({ error: 'Set a Predator Type on your character sheet before feeding.' });
      if (!pools.length) {
        return reply.status(400).send({ error: `${predatorType} isn't automatable for the Feeding roll. It's GM-adjudicated. Use a Monthly Action to describe your feeding instead.` });
      }

      const division = Number(req.body?.division);
      const poolIndex = Number(req.body?.poolIndex ?? 0);
      if (!Number.isInteger(poolIndex) || poolIndex < 0 || poolIndex >= pools.length) {
        return reply.status(400).send({ error: 'Invalid hunting method selected.' });
      }
      const difficulty = huntingDifficulty(division);
      if (difficulty === null) return reply.status(400).send({ error: 'Invalid domain.' });

      const { cycleIndex } = await getCurrentCycle();

      const [existing] = await pool.query(
        "SELECT id, status FROM feedings WHERE character_id=? AND cycle_index=? AND status IN ('pending','resolved') LIMIT 1",
        [char.id, cycleIndex]
      );
      if (existing.length) {
        return reply.status(409).send({ error: 'You already have a feeding roll for this cycle.', feedingId: existing[0].id, status: existing[0].status });
      }

      const chosenPool = pools[poolIndex];
      const basePool = getTraitValue(char.sheet, chosenPool.attribute) + getTraitValue(char.sheet, chosenPool.skill);
      let specialtyBonus = 0;
      if (hasRelevantSpecialty(char.sheet, predatorType, chosenPool.skill)) {
        specialtyBonus = 1;
      }
      const { bonusDice, meritsApplied } = chasseBonus(division, predatorType);
      const totalPool = clamp(basePool + specialtyBonus + bonusDice, 0, 30);

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
      reply.status(500).send({ error: 'Database error making feeding roll' });
    }
  });

  /* -------------------- Herd Feed (Background — no roll) -------------------- */
  // Rule: 1 dot of Herd pool = -1 hunger, 1:1. Pool tracked in sheet.herd_current.
  // Pool starts = herd dots, depletes on use, regens +1 per cycle (3 weeks) up to max.
  // Hunger never drops below 1.
  fastify.post('/api/feeding/herd-feed', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      if (!(await isFeedingEnabled())) return reply.status(400).send({ error: 'The Feeding system is currently disabled.' });

      const char = await getMyCharacter(req.user.id);
      if (!char) return reply.status(404).send({ error: 'No character found for this account.' });

      const { cycleIndex } = await getCurrentCycle();

      // Already fed this cycle?
      const [existing] = await pool.query(
        "SELECT id, status FROM feedings WHERE character_id=? AND cycle_index=? AND status IN ('pending','resolved') LIMIT 1",
        [char.id, cycleIndex]
      );
      if (existing.length) {
        return reply.status(409).send({ error: 'You already have a feeding roll for this cycle.', feedingId: existing[0].id, status: existing[0].status });
      }

      // Herd background: stored in sheet.advantages.merits[] with id or name fallback
      const merits = Array.isArray(char.sheet?.advantages?.merits) ? char.sheet.advantages.merits : [];
      const herdEntry = merits.find(b =>
        String(b.id || '').toLowerCase().includes('herd__herd') ||
        String(b.name || '').toLowerCase() === 'herd'
      );
      const herdDots = herdEntry ? clamp(Number(herdEntry.dots) || 0, 0, 5) : 0;

      if (herdDots < 1) {
        return reply.status(400).send({ error: 'You do not have the Herd background.' });
      }

      // herd_current: initialize to full dots if never set, then clamp to [0, dots]
      const rawCurrent = char.sheet.herd_current !== undefined ? Number(char.sheet.herd_current) : herdDots;
      const herdCurrent = clamp(rawCurrent, 0, herdDots);

      if (herdCurrent < 1) {
        return reply.status(400).send({ error: 'Your Herd is depleted. It restores 1 point each feeding cycle.' });
      }

      const division = Number(req.body?.division);
      if (Number.isNaN(division) || division === 0) {
        return reply.status(400).send({ error: 'Please select a domain to feed in.' });
      }

      // Use exactly 1 pool point → -1 hunger (floor 1), -1 herd_current
      const currentHunger = clamp(Number(char.sheet?.hunger) ?? 1, 0, 5);
      const reduction = currentHunger > 1 ? 1 : 0; // can only reduce if hunger > 1
      const newHunger = currentHunger - reduction;
      const newHerdCurrent = herdCurrent - 1;

      char.sheet.hunger = newHunger;
      char.sheet.herd_current = newHerdCurrent;
      await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(char.sheet), char.id]);

      const predatorType = getPredatorType(char.sheet) || '';

      // Log as a resolved feeding with outcome 'herd'
      await pool.query(
        `INSERT INTO feedings
          (character_id, division, predator_type, pool_label, dice_pool, difficulty, bonus_dice,
           chasse_merits_applied, hunger_before, normal_dice, hunger_dice, outcome, status, cycle_index, hunger_delta, safety_delta, resolved_at)
         VALUES (?, ?, ?, 'Herd', 0, 0, 0, '[]', ?, '[]', '[]', 'herd', 'resolved', ?, ?, 0, NOW())`,
        [char.id, division, predatorType, currentHunger, cycleIndex, -reduction]
      );

      log.info('Herd feed used', { character_id: char.id, herdDots, herdCurrent, herdAfter: newHerdCurrent, hungerBefore: currentHunger, hungerAfter: newHunger });
      reply.send({
        ok: true,
        herdDots,
        herdCurrent: newHerdCurrent,
        hungerBefore: currentHunger,
        hungerAfter: newHunger,
        hungerDelta: -reduction,
        sheet: char.sheet,
      });
    } catch (err) {
      log.err('POST /api/feeding/herd-feed failed', { error: err.message });
      reply.status(500).send({ error: 'Database error using Herd feed' });
    }
  });

  /* -------------------- Reroll (spend Willpower, once) -------------------- */
  fastify.post('/api/feeding/:id/reroll', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const feedingId = Number(req.params.id);
      const [rows] = await pool.query('SELECT * FROM feedings WHERE id=?', [feedingId]);
      if (!rows.length) return reply.status(404).send({ error: 'Feeding roll not found.' });
      const feeding = rows[0];

      const [charRows] = await pool.query('SELECT user_id, sheet FROM characters WHERE id=?', [feeding.character_id]);
      if (!charRows.length) return reply.status(404).send({ error: 'Character not found.' });
      if (charRows[0].user_id !== req.user.id && req.user.role !== 'admin') {
        return reply.status(403).send({ error: 'Forbidden' });
      }
      if (feeding.status !== 'pending') return reply.status(400).send({ error: 'This roll is already resolved.' });
      if (feeding.wp_rerolled) return reply.status(400).send({ error: 'You have already spent Willpower on this roll.' });

      const selected = Array.from(new Set(req.body?.selectedIndices || [])).slice(0, 3);
      if (!selected.length) return reply.status(400).send({ error: 'Select at least one die to reroll.' });

      let sheet = parseSheet(charRows[0].sheet);
      if (!sheet.willpower) sheet.willpower = { superficial: 0, aggravated: 0 };
      const comp = Number(sheet.attributes?.Composure) || 1;
      const reso = Number(sheet.attributes?.Resolve) || 1;
      const max = comp + reso;
      const currentWp = (Number(sheet.willpower.superficial) || 0) + (Number(sheet.willpower.aggravated) || 0);
      if (currentWp >= max) return reply.status(400).send({ error: 'Not enough Willpower.' });

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
      reply.status(500).send({ error: 'Database error rerolling' });
    }
  });

  /* -------------------- Confirm (final — applies Hunger/Safety) -------------------- */
  fastify.post('/api/feeding/:id/confirm', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const feedingId = Number(req.params.id);
      const [rows] = await pool.query('SELECT * FROM feedings WHERE id=?', [feedingId]);
      if (!rows.length) return reply.status(404).send({ error: 'Feeding roll not found.' });
      const feeding = rows[0];

      const [charRows] = await pool.query('SELECT id, user_id, sheet FROM characters WHERE id=?', [feeding.character_id]);
      if (!charRows.length) return reply.status(404).send({ error: 'Character not found.' });
      if (charRows[0].user_id !== req.user.id && req.user.role !== 'admin') {
        return reply.status(403).send({ error: 'Forbidden' });
      }
      if (feeding.status !== 'pending') return reply.status(400).send({ error: 'This roll is already resolved.' });

      const deltas = OUTCOME_DELTAS[feeding.outcome];
      if (!deltas) return reply.status(500).send({ error: 'Unresolved outcome on this roll.' });

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
      reply.status(500).send({ error: 'Database error confirming feeding roll' });
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
      reply.status(500).send({ error: 'Database error fetching incidents' });
    }
  });

  fastify.patch('/api/domain-incidents/:id/dismiss', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const id = Number(req.params.id);
      const [rows] = await pool.query('SELECT owner_user_id FROM domain_incidents WHERE id=?', [id]);
      if (!rows.length) return reply.status(404).send({ error: 'Not found' });
      if (rows[0].owner_user_id !== req.user.id && req.user.role !== 'admin') {
        return reply.status(403).send({ error: 'Forbidden' });
      }
      await pool.query('UPDATE domain_incidents SET dismissed_at=NOW() WHERE id=?', [id]);
      reply.send({ ok: true });
    } catch (err) {
      log.err('PATCH /api/domain-incidents/:id/dismiss failed', { error: err.message });
      reply.status(500).send({ error: 'Database error dismissing incident' });
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
      reply.status(500).send({ error: 'Database error updating feeding status', details: err.sqlMessage || err.message });
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
      reply.status(500).send({ error: 'Database error fetching feeding log', details: err.sqlMessage || err.message });
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
      reply.status(500).send({ error: 'Database error resetting cycle', details: err.sqlMessage || err.message });
    }
  });

  fastify.post('/api/admin/feeding/run-decay', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const result = await runFeedingDecay(pool, log, { force: true });
      log.adm('Feeding decay manually triggered', { user: req.user.id, result });
      reply.send(result);
    } catch (err) {
      log.err('POST /api/admin/feeding/run-decay failed', { error: err.message });
      reply.status(500).send({ error: 'Database error running decay', details: err.sqlMessage || err.message });
    }
  });

  /* ---- Admin: Herd Roster (all chars with Herd background) ---- */
  fastify.get('/api/admin/feeding/herd-roster', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [chars] = await pool.query('SELECT id, name, sheet FROM characters WHERE sheet IS NOT NULL');
      const roster = [];
      for (const row of chars) {
        let sheet;
        try { sheet = typeof row.sheet === 'string' ? JSON.parse(row.sheet) : row.sheet; } catch { continue; }
        const merits = Array.isArray(sheet?.advantages?.merits) ? sheet.advantages.merits : [];
        const herdEntry = merits.find(b =>
          String(b.id || '').toLowerCase().includes('herd__herd') ||
          String(b.name || '').toLowerCase() === 'herd'
        );
        if (!herdEntry) continue;
        const herdDots = clamp(Number(herdEntry.dots) || 0, 0, 5);
        if (herdDots < 1) continue;
        const herdCurrent = sheet.herd_current !== undefined
          ? clamp(Number(sheet.herd_current), 0, herdDots)
          : herdDots; // never set = full
        roster.push({ character_id: row.id, name: row.name, herdDots, herdCurrent });
      }
      roster.sort((a, b) => a.name.localeCompare(b.name));
      reply.send({ roster });
    } catch (err) {
      log.err('GET /api/admin/feeding/herd-roster failed', { error: err.message });
      reply.status(500).send({ error: 'Database error fetching herd roster', details: err.sqlMessage || err.message });
    }
  });

  /* ---- Admin: Adjust Herd pool for a character (delta ±N) ---- */
  // body: { character_id, delta }  e.g. { character_id: 15, delta: -1 } or { delta: 2 }
  fastify.post('/api/admin/feeding/herd-adjust', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { character_id, delta } = req.body || {};
      if (!character_id || delta === undefined) return reply.status(400).send({ error: 'character_id and delta required' });
      const d = parseInt(delta, 10);
      if (isNaN(d) || d === 0) return reply.status(400).send({ error: 'delta must be a non-zero integer' });

      const [charRows] = await pool.query('SELECT id, name, sheet FROM characters WHERE id=? LIMIT 1', [character_id]);
      if (!charRows.length) return reply.status(404).send({ error: 'Character not found' });
      let sheet;
      try { sheet = typeof charRows[0].sheet === 'string' ? JSON.parse(charRows[0].sheet) : charRows[0].sheet; } catch { sheet = {}; }

      const merits = Array.isArray(sheet?.advantages?.merits) ? sheet.advantages.merits : [];
      const herdEntry = merits.find(b =>
        String(b.id || '').toLowerCase().includes('herd__herd') ||
        String(b.name || '').toLowerCase() === 'herd'
      );
      if (!herdEntry) return reply.status(400).send({ error: 'Character does not have the Herd background' });

      const herdDots = clamp(Number(herdEntry.dots) || 0, 0, 5);
      const rawCurrent = sheet.herd_current !== undefined ? Number(sheet.herd_current) : herdDots;
      const before = clamp(rawCurrent, 0, herdDots);
      const after = clamp(before + d, 0, herdDots);

      sheet.herd_current = after;
      await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), character_id]);
      log.adm('Admin herd adjust', { admin: req.user.id, character_id, delta: d, before, after });
      reply.send({ ok: true, character_id, name: charRows[0].name, herdDots, herdBefore: before, herdAfter: after });
    } catch (err) {
      log.err('POST /api/admin/feeding/herd-adjust failed', { error: err.message });
      reply.status(500).send({ error: 'Database error adjusting herd', details: err.sqlMessage || err.message });
    }
  });

  /* ---- Admin: Feeding stats for current cycle ---- */
  fastify.get('/api/admin/feeding/stats', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const cycle = await getCurrentCycle();
      const rawIndex = Number(cycle?.cycleIndex);
      const cycleIndex = Number.isInteger(rawIndex) && rawIndex >= 0 ? rawIndex : 0;
      const [rows] = await pool.query(
        "SELECT outcome, COUNT(*) as cnt FROM feedings WHERE cycle_index=? AND status='resolved' GROUP BY outcome",
        [cycleIndex]
      );
      const counts = {
        total: 0,
        success: 0,
        failure: 0,
        herd: 0,
        bestial_failure: 0,
        messy_critical: 0,
        critical: 0,
      };
      const byOutcome = {};
      for (const r of rows) {
        const count = Number(r.cnt) || 0;
        if (r.outcome) {
          byOutcome[r.outcome] = (byOutcome[r.outcome] || 0) + count;
        }
      }
      counts.total = Object.values(byOutcome).reduce((a, b) => a + b, 0);
      counts.herd = byOutcome.herd || 0;
      counts.critical = byOutcome.critical || 0;
      counts.messy_critical = byOutcome.messy_critical || 0;
      counts.bestial_failure = byOutcome.bestial_failure || 0;
      counts.success = (byOutcome.success || 0) + (byOutcome.critical || 0) + (byOutcome.messy_critical || 0) + (byOutcome.herd || 0);
      counts.failure = (byOutcome.failure || 0) + (byOutcome.bestial_failure || 0);

      const pct = counts.total > 0 ? Math.round((counts.success / counts.total) * 100) : null;
      reply.send({ cycleIndex, counts, successPct: pct });
    } catch (err) {
      log.err('GET /api/admin/feeding/stats failed', { error: err.message });
      reply.status(500).send({
        error: 'Database error fetching feeding stats',
        details: err.sqlMessage || err.message,
      });
    }
  });
};

