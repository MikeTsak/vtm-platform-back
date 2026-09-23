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
const { getCycleInfo, resolveCurrentFeedingCycle } = require('../utils/feedingCycle');
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

  // Granted specs like "Animal Ken: specific animal" are placeholders the
  // player fills in, so any specialty in that skill counts.
  const isPlaceholder = relevantGrantedSpecs.some(s => s.startsWith('specific'));
  const matches = (specName) => isPlaceholder || relevantGrantedSpecs.includes(specName);

  if (Array.isArray(sheet.specialties)) {
    for (const specStr of sheet.specialties) {
      if (typeof specStr === 'string' && specStr.toLowerCase().startsWith(chosenSkill.toLowerCase() + ':')) {
        const specName = specStr.split(':')[1].trim().toLowerCase();
        if (specName && matches(specName)) return true;
      }
    }
  }

  if (sheet.skills && sheet.skills[chosenSkill] && Array.isArray(sheet.skills[chosenSkill].specialties)) {
    for (const specName of sheet.skills[chosenSkill].specialties) {
      if (typeof specName === 'string' && specName.trim() && matches(specName.trim().toLowerCase())) {
        return true;
      }
    }
  }

  return false;
}

const clamp = (v, min, max) => Math.max(min, Math.min(max, Number(v) || 0));

// A missing/blank Hunger reads as 1 (a fresh sheet); 0 is a real value (GM-set).
function readHunger(sheet) {
  const raw = sheet?.hunger;
  if (raw === undefined || raw === null || raw === '' || !Number.isFinite(Number(raw))) return 1;
  return clamp(raw, 0, 5);
}

// House rule: Hunger after any feeding is always within 1..5. Only a GM
// manual edit can set 0.
function applyHungerDelta(current, delta) {
  return Math.max(1, Math.min(5, current + delta));
}

// Outcomes that leave a trail; each gets a stored predatorFlavor line.
const FAILURE_OUTCOMES = ['bestial_failure', 'failure', 'messy_critical'];

// Herd background: stored in sheet.advantages.merits[] (not sheet.backgrounds[]).
// Some entries only have a name field (no id), so fall back to name match.
function getHerdDots(sheet) {
  const merits = Array.isArray(sheet?.advantages?.merits) ? sheet.advantages.merits : [];
  const herdEntry = merits.find(b =>
    String(b.id || '').toLowerCase().includes('herd__herd') ||
    String(b.name || '').toLowerCase() === 'herd'
  );
  return herdEntry ? clamp(Number(herdEntry.dots) || 0, 0, 5) : 0;
}

function parseJsonArray(v) {
  if (Array.isArray(v)) return v;
  try { const a = JSON.parse(v || '[]'); return Array.isArray(a) ? a : []; } catch { return []; }
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, sendPushNotification } = opts;

  async function getMyCharacter(userId) {
    const [rows] = await pool.query('SELECT id, sheet FROM characters WHERE user_id=?', [userId]);
    if (!rows.length) return null;
    return { id: rows[0].id, sheet: parseSheet(rows[0].sheet) };
  }

  async function getCurrentCycle() {
    return resolveCurrentFeedingCycle();
  }

  // Runs fn(conn, character) in a transaction holding the character row lock
  // (character is null if the row is gone). fn returns { code, body }.
  async function withCharacterLock(characterId, fn) {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [rows] = await conn.query('SELECT id, user_id, sheet FROM characters WHERE id=? FOR UPDATE', [characterId]);
      const character = rows.length ? { ...rows[0], sheet: parseSheet(rows[0].sheet) } : null;
      const result = await fn(conn, character);
      await conn.commit();
      return result;
    } catch (err) {
      await conn.rollback().catch(() => {});
      throw err;
    } finally {
      conn.release();
    }
  }

  async function isFeedingEnabled() {
    return (await getSetting('feeding_enabled', 'true')) === 'true';
  }

  /* -------------------- Status -------------------- */
  fastify.get('/api/feeding/status', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const enabled = await isFeedingEnabled();
      if (!enabled) return reply.send({ enabled: false });

      const { cycleIndex, cycleStart, cycleEnd, cycleTitle, isDowntimeLinked } = await getCurrentCycle();
      const char = await getMyCharacter(req.user.id);
      if (!char) {
        return reply.send({ enabled: true, cycleIndex, cycleStart, cycleEnd, cycleTitle: cycleTitle || `Cycle ${cycleIndex}`, isDowntimeLinked: !!isDowntimeLinked, noCharacter: true });
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

      const herdDots = getHerdDots(char.sheet);

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
        cycleTitle: cycleTitle || `Cycle ${cycleIndex}`,
        isDowntimeLinked: !!isDowntimeLinked,
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

      // The character row lock serializes this against a double-submitted
      // roll (or a concurrent Herd feed), so the one-per-cycle check holds.
      const result = await withCharacterLock(char.id, async (conn, locked) => {
        const [existing] = await conn.query(
          "SELECT id, status FROM feedings WHERE character_id=? AND cycle_index=? AND status IN ('pending','resolved') LIMIT 1",
          [char.id, cycleIndex]
        );
        if (existing.length) {
          return { code: 409, body: { error: 'You already have a feeding roll for this cycle.', feedingId: existing[0].id, status: existing[0].status } };
        }

        const sheet = locked.sheet;
        const chosenPool = pools[poolIndex];
        const basePool = getTraitValue(sheet, chosenPool.attribute) + getTraitValue(sheet, chosenPool.skill);
        const specialtyBonus = hasRelevantSpecialty(sheet, predatorType, chosenPool.skill) ? 1 : 0;
        const { bonusDice, meritsApplied } = chasseBonus(division, predatorType);
        const totalPool = clamp(basePool + specialtyBonus + bonusDice, 0, 30);

        const hunger = readHunger(sheet);
        const hungerCount = Math.min(totalPool, hunger);
        const normalDice = rollDice(totalPool - hungerCount);
        const hungerDice = rollDice(hungerCount);
        const outcome = computeFeedingOutcome(normalDice, hungerDice, difficulty);

        const [ins] = await conn.query(
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
        const [rows] = await conn.query('SELECT * FROM feedings WHERE id=?', [ins.insertId]);
        log.info('Feeding roll made', { character_id: char.id, division, tier: outcome.tier });
        return { code: 200, body: { feeding: rows[0], projected: OUTCOME_DELTAS[outcome.tier] } };
      });
      reply.status(result.code).send(result.body);
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

      // Division is a flavor/log field for Herd, but it still has to be a real one.
      const division = Number(req.body?.division);
      if (huntingDifficulty(division) === null) {
        return reply.status(400).send({ error: 'Please select a domain to feed in.' });
      }

      const { cycleIndex } = await getCurrentCycle();

      const result = await withCharacterLock(char.id, async (conn, locked) => {
        const [existing] = await conn.query(
          "SELECT id, status FROM feedings WHERE character_id=? AND cycle_index=? AND status IN ('pending','resolved') LIMIT 1",
          [char.id, cycleIndex]
        );
        if (existing.length) {
          return { code: 409, body: { error: 'You already have a feeding roll for this cycle.', feedingId: existing[0].id, status: existing[0].status } };
        }

        const sheet = locked.sheet;
        const herdDots = getHerdDots(sheet);
        if (herdDots < 1) return { code: 400, body: { error: 'You do not have the Herd background.' } };

        // herd_current: initialize to full dots if never set, then clamp to [0, dots]
        const rawCurrent = sheet.herd_current !== undefined ? Number(sheet.herd_current) : herdDots;
        const herdCurrent = clamp(rawCurrent, 0, herdDots);
        if (herdCurrent < 1) {
          return { code: 400, body: { error: 'Your Herd is depleted. It restores 1 point each feeding cycle.' } };
        }

        // Use exactly 1 pool point: -1 hunger (result always at least 1), -1 herd_current
        const currentHunger = readHunger(sheet);
        const newHunger = applyHungerDelta(currentHunger, -1);
        const hungerDelta = newHunger - currentHunger;
        const newHerdCurrent = herdCurrent - 1;

        sheet.hunger = newHunger;
        sheet.herd_current = newHerdCurrent;
        await conn.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), char.id]);

        // Log as a resolved feeding with outcome 'herd'
        await conn.query(
          `INSERT INTO feedings
            (character_id, division, predator_type, pool_label, dice_pool, difficulty, bonus_dice,
             chasse_merits_applied, hunger_before, normal_dice, hunger_dice, outcome, status, cycle_index, hunger_delta, safety_delta, resolved_at)
           VALUES (?, ?, ?, 'Herd', 0, 0, 0, '[]', ?, '[]', '[]', 'herd', 'resolved', ?, ?, 0, NOW())`,
          [char.id, division, getPredatorType(sheet) || '', currentHunger, cycleIndex, hungerDelta]
        );

        log.info('Herd feed used', { character_id: char.id, herdDots, herdCurrent, herdAfter: newHerdCurrent, hungerBefore: currentHunger, hungerAfter: newHunger });
        return {
          code: 200,
          body: { ok: true, herdDots, herdCurrent: newHerdCurrent, hungerBefore: currentHunger, hungerAfter: newHunger, hungerDelta, sheet },
        };
      });
      reply.status(result.code).send(result.body);
    } catch (err) {
      log.err('POST /api/feeding/herd-feed failed', { error: err.message });
      reply.status(500).send({ error: 'Database error using Herd feed' });
    }
  });

  // Loads a pending feeding for reroll/confirm: locks its character row and
  // re-reads the feeding under that lock, so a double-submitted reroll can't
  // spend Willpower twice and a double-submitted confirm can't apply twice.
  async function withPendingFeeding(req, feedingId, fn) {
    const [rows] = await pool.query('SELECT character_id FROM feedings WHERE id=?', [feedingId]);
    if (!rows.length) return { code: 404, body: { error: 'Feeding roll not found.' } };

    return withCharacterLock(rows[0].character_id, async (conn, locked) => {
      if (!locked) return { code: 404, body: { error: 'Character not found.' } };
      if (locked.user_id !== req.user.id && req.user.role !== 'admin') {
        return { code: 403, body: { error: 'Forbidden' } };
      }
      const [[feeding]] = await conn.query('SELECT * FROM feedings WHERE id=?', [feedingId]);
      if (feeding.status !== 'pending') return { code: 400, body: { error: 'This roll is already resolved.' } };
      return fn(conn, locked, feeding);
    });
  }

  /* -------------------- Reroll (spend Willpower, once) -------------------- */
  fastify.post('/api/feeding/:id/reroll', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const feedingId = Number(req.params.id);
      const result = await withPendingFeeding(req, feedingId, async (conn, locked, feeding) => {
        if (feeding.wp_rerolled) return { code: 400, body: { error: 'You have already spent Willpower on this roll.' } };

        // Only regular dice can be rerolled (Hunger dice never can).
        const normalDice = parseJsonArray(feeding.normal_dice);
        const hungerDice = parseJsonArray(feeding.hunger_dice);
        const rawSelected = Array.isArray(req.body?.selectedIndices) ? req.body.selectedIndices : [];
        const selected = Array.from(new Set(rawSelected.map(Number)))
          .filter((i) => Number.isInteger(i) && i >= 0 && i < normalDice.length);
        if (!selected.length) return { code: 400, body: { error: 'Select at least one of your regular dice to reroll.' } };
        if (selected.length > 3) return { code: 400, body: { error: 'You can reroll at most 3 dice.' } };

        const sheet = locked.sheet;
        if (!sheet.willpower) sheet.willpower = { superficial: 0, aggravated: 0 };
        const comp = Number(sheet.attributes?.Composure) || 1;
        const reso = Number(sheet.attributes?.Resolve) || 1;
        const max = comp + reso;
        const currentWp = (Number(sheet.willpower.superficial) || 0) + (Number(sheet.willpower.aggravated) || 0);
        if (currentWp >= max) return { code: 400, body: { error: 'Not enough Willpower.' } };

        sheet.willpower.superficial = (Number(sheet.willpower.superficial) || 0) + 1;
        await conn.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), feeding.character_id]);

        const rerolled = rollDice(selected.length);
        let r = 0;
        const nextNormal = normalDice.map((die, idx) => (selected.includes(idx) ? rerolled[r++] : die));
        const outcome = computeFeedingOutcome(nextNormal, hungerDice, feeding.difficulty);

        await conn.query(
          "UPDATE feedings SET normal_dice=?, outcome=?, wp_rerolled=1 WHERE id=?",
          [JSON.stringify(nextNormal), outcome.tier, feedingId]
        );
        const [[updated]] = await conn.query('SELECT * FROM feedings WHERE id=?', [feedingId]);
        return { code: 200, body: { feeding: updated, projected: OUTCOME_DELTAS[outcome.tier], sheet } };
      });
      reply.status(result.code).send(result.body);
    } catch (err) {
      log.err('POST /api/feeding/:id/reroll failed', { error: err.message });
      reply.status(500).send({ error: 'Database error rerolling' });
    }
  });

  /* -------------------- Confirm (final — applies Hunger/Safety) -------------------- */
  fastify.post('/api/feeding/:id/confirm', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const feedingId = Number(req.params.id);
      let notify = null;
      const result = await withPendingFeeding(req, feedingId, async (conn, locked, feeding) => {
        const deltas = OUTCOME_DELTAS[feeding.outcome];
        if (!deltas) return { code: 500, body: { error: 'Unresolved outcome on this roll.' } };

        const sheet = locked.sheet;
        const currentHunger = readHunger(sheet);
        const newHunger = applyHungerDelta(currentHunger, deltas.hunger);
        const appliedHungerDelta = newHunger - currentHunger;
        sheet.hunger = newHunger;
        await conn.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), feeding.character_id]);

        const [existingClaim] = await conn.query(
          'SELECT division, owner_character_id, owner_npc_id, owner_name, safety_rating FROM domain_claims WHERE division=?',
          [feeding.division]
        );
        if (existingClaim.length) {
          await conn.query(
            'UPDATE domain_claims SET safety_rating = GREATEST(0, LEAST(10, IFNULL(safety_rating, 10) + ?)) WHERE division=?',
            [deltas.safety, feeding.division]
          );
        } else {
          await conn.query(
            'INSERT INTO domain_claims (division, owner_name, color, safety_rating) VALUES (?, NULL, ?, ?)',
            [feeding.division, '#888888', clamp(10 + deltas.safety, 0, 10)]
          );
        }

        // Picked once and stored, so the log and any incident read the same forever.
        const isIncidentOutcome = FAILURE_OUTCOMES.includes(feeding.outcome);
        const failureReason = isIncidentOutcome ? pickFlavor(feeding.predator_type) : null;

        await conn.query(
          "UPDATE feedings SET status='resolved', resolved_at=NOW(), hunger_delta=?, safety_delta=?, failure_reason=? WHERE id=?",
          [appliedHungerDelta, deltas.safety, failureReason, feedingId]
        );

        // Domain incident: only on a bad-for-the-domain outcome, only when
        // hunting someone else's (player-owned) division.
        if (isIncidentOutcome && existingClaim.length && existingClaim[0].owner_character_id
            && existingClaim[0].owner_character_id !== feeding.character_id) {
          const [ownerRows] = await conn.query('SELECT id, user_id, name FROM characters WHERE id=?', [existingClaim[0].owner_character_id]);
          if (ownerRows.length) {
            const [hunterRows] = await conn.query('SELECT name FROM characters WHERE id=?', [feeding.character_id]);
            const hunterName = hunterRows[0]?.name || 'An unknown Kindred';
            const flavor = failureReason;

            await conn.query(
              `INSERT INTO domain_incidents
                (feeding_id, division, owner_user_id, owner_character_id, intruder_character_id, intruder_character_name, outcome, flavor_text)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
              [feedingId, feeding.division, ownerRows[0].user_id, ownerRows[0].id, feeding.character_id, hunterName, feeding.outcome, flavor]
            );
            notify = { userId: ownerRows[0].user_id, hunterName, division: feeding.division };
          }
        }

        return { code: 200, body: { ok: true, tier: feeding.outcome, hungerDelta: appliedHungerDelta, safetyDelta: deltas.safety, sheet } };
      });

      // Push only once the transaction has committed.
      if (notify) {
        sendPushNotification(
          notify.userId,
          'Feeding Incident',
          `${notify.hunterName} hunted in your domain (Division ${notify.division}) and drew attention.`,
          {}, 'court'
        ).catch(() => {});
      }
      reply.status(result.code).send(result.body);
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
        SELECT f.*, c.name AS character_name, c.sheet AS character_sheet,
               dc.owner_name AS domain_owner_name,
               dc_char.name AS domain_owner_char_name,
               dc_npc.name AS domain_owner_npc_name,
               dc.safety_rating AS current_domain_safety
        FROM feedings f
        JOIN characters c ON c.id = f.character_id
        LEFT JOIN domain_claims dc ON dc.division = f.division
        LEFT JOIN characters dc_char ON dc_char.id = dc.owner_character_id
        LEFT JOIN npcs dc_npc ON dc_npc.id = dc.owner_npc_id
        ORDER BY f.created_at DESC
        LIMIT 200
      `);
      const logRows = rows.map(r => {
        const sheet = parseSheet(r.character_sheet);
        const currentHunger = sheet?.hunger !== undefined && sheet?.hunger !== null ? Number(sheet.hunger) : 1;
        const { character_sheet, domain_owner_char_name, domain_owner_npc_name, domain_owner_name, ...rest } = r;
        return {
          ...rest,
          current_hunger: currentHunger,
          domain_owner: domain_owner_char_name || domain_owner_npc_name || domain_owner_name || null,
        };
      });
      reply.send({ log: logRows });
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

  /* ---- Admin: Allow Reroll (undo a feeding so the player can feed again) ---- */
  // Reverses everything the feeding applied: the Hunger change, the Willpower
  // spent on its reroll, the domain Safety change and the Herd point, then
  // deletes the row (its domain incident cascades) so the one-per-cycle
  // check lets the player roll again. Downtimes already submitted stay.
  fastify.post('/api/admin/feeding/:id/allow-reroll', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const feedingId = Number(req.params.id);
      const [rows] = await pool.query('SELECT character_id FROM feedings WHERE id=?', [feedingId]);
      if (!rows.length) return reply.status(404).send({ error: 'Feeding roll not found.' });

      const result = await withCharacterLock(rows[0].character_id, async (conn, locked) => {
        const [[feeding]] = await conn.query('SELECT * FROM feedings WHERE id=?', [feedingId]);
        if (!feeding) return { code: 404, body: { error: 'Feeding roll not found.' } };

        const resolved = feeding.status === 'resolved';
        const undone = {};
        if (locked) {
          const sheet = locked.sheet;
          if (resolved && feeding.hunger_delta) {
            const before = readHunger(sheet);
            sheet.hunger = clamp(before - feeding.hunger_delta, 0, 5);
            undone.hunger = { before, after: sheet.hunger };
          }
          if (feeding.wp_rerolled && Number(sheet.willpower?.superficial) > 0) {
            sheet.willpower.superficial = Number(sheet.willpower.superficial) - 1;
            undone.willpower = true;
          }
          if (feeding.outcome === 'herd' && sheet.herd_current !== undefined) {
            sheet.herd_current = clamp(Number(sheet.herd_current) + 1, 0, getHerdDots(sheet));
            undone.herd = sheet.herd_current;
          }
          await conn.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), locked.id]);
        }

        if (resolved && feeding.safety_delta) {
          await conn.query(
            'UPDATE domain_claims SET safety_rating = GREATEST(0, LEAST(10, IFNULL(safety_rating, 10) - ?)) WHERE division=?',
            [feeding.safety_delta, feeding.division]
          );
          undone.safety = -feeding.safety_delta;
        }

        await conn.query('DELETE FROM feedings WHERE id=?', [feedingId]);
        log.adm('Admin allowed feeding reroll', { admin: req.user.id, feeding, undone });
        return { code: 200, body: { ok: true, undone } };
      });
      reply.status(result.code).send(result.body);
    } catch (err) {
      log.err('POST /api/admin/feeding/:id/allow-reroll failed', { error: err.message });
      reply.status(500).send({ error: 'Database error undoing feeding', details: err.sqlMessage || err.message });
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

  /* ---- Admin: Adjust Hunger for a character (delta ±N or direct value) ---- */
  fastify.post('/api/admin/feeding/hunger-adjust', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { character_id, delta, hunger } = req.body || {};
      if (!character_id) return reply.status(400).send({ error: 'character_id required' });

      const [charRows] = await pool.query('SELECT id, name, sheet FROM characters WHERE id=? LIMIT 1', [character_id]);
      if (!charRows.length) return reply.status(404).send({ error: 'Character not found' });
      let sheet;
      try { sheet = typeof charRows[0].sheet === 'string' ? JSON.parse(charRows[0].sheet) : charRows[0].sheet; } catch { sheet = {}; }
      if (!sheet) sheet = {};

      const before = clamp(sheet.hunger !== undefined && sheet.hunger !== null ? Number(sheet.hunger) : 1, 0, 5);
      let after = before;

      if (hunger !== undefined && !isNaN(Number(hunger))) {
        after = clamp(Number(hunger), 0, 5);
      } else if (delta !== undefined) {
        const d = parseInt(delta, 10);
        if (isNaN(d) || d === 0) return reply.status(400).send({ error: 'delta must be a non-zero integer' });
        // GM manual edit: allows 0 to 5, but cannot go below 0 (cannot go to minus)
        after = clamp(before + d, 0, 5);
      } else {
        return reply.status(400).send({ error: 'delta or hunger required' });
      }

      sheet.hunger = after;
      await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), character_id]);
      log.adm('Admin hunger adjust', { admin: req.user.id, character_id, delta, before, after });
      reply.send({ ok: true, character_id, name: charRows[0].name, hungerBefore: before, hungerAfter: after });
    } catch (err) {
      log.err('POST /api/admin/feeding/hunger-adjust failed', { error: err.message });
      reply.status(500).send({ error: 'Database error adjusting hunger', details: err.sqlMessage || err.message });
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

