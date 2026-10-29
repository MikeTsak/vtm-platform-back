// routes/feeding.js
//
// The Feeding system: server-authoritative hunting rolls, up to
// HUNTS_PER_CYCLE per downtime cycle, at least one feeding (a roll or a Herd
// use) gating downtime submission (see services/downtimeSchedule.js's
// checkSubmission). Herd uses are not hunts: they repeat until the Herd pool
// runs dry. Hunting is open from the cycle's opening to its deadline, so the
// ghoul upkeep that lands before the event (services/ghoulFeeding.js) can
// only be offset by feeding ghouls early. Dice are rolled here, not on the client — same
// "server is the source of truth" principle as routes/mechanics.js — so a
// player can never fabricate or redo a masquerade-affecting result. A roll
// is persisted as 'pending' the instant it's made; from there the only two
// moves are POST /:id/reroll (spend 1 Willpower, once) or POST /:id/confirm
// (lock it in). Reloading the page always reconstructs the same pending row
// via GET /status — there is no way to discard a roll and start over.

const { getSetting, setSetting } = require('../utils/settings');
const { getCycleInfo, resolveCurrentFeedingCycle } = require('../utils/feedingCycle');
const { huntingDifficulty } = require('../data/huntingDifficulty');
const { isOwnerOrAdmin } = require('../services/guards');
const { chasseBonus } = require('../data/chasseMerits');
const { PREDATOR_HUNTING_POOLS, PREDATOR_SPECIALTIES } = require('../data/predatorHuntingPools');
const { rollDice, computeFeedingOutcome, OUTCOME_DELTAS } = require('../services/feedingDice');
const { mendAmount } = require('../services/dice');
const { pickFlavor } = require('../data/predatorFlavor');
const { runFeedingDecay } = require('../services/feedingDecay');
const { parseSheet } = require('../utils/sheet');
const { withSheetLock } = require('../utils/sheetLock');
const { feedGhoul, ghoulStates, ghoulsFor, runGhoulUpkeep, dueUpkeepCycle } = require('../services/ghoulFeeding');
const { readCycles, withDefaultDates, findActiveIndex, checkSubmission } = require('../services/downtimeSchedule');

const HUNTS_PER_CYCLE = 3;
// Feedings that aren't hunts: no roll, no domain, no cap.
const NOT_HUNTS = ['herd', 'manual', 'downtime'];
// Safe feeding paid with a downtime action: no roll, no domain, Hunger -2 (never below 1).
const SAFE_FEED_HUNGER = -2;

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
    const [rows] = await pool.query('SELECT id, clan, sheet FROM characters WHERE user_id=?', [userId]);
    if (!rows.length) return null;
    return { id: rows[0].id, clan: rows[0].clan, sheet: parseSheet(rows[0].sheet) };
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

  // Hunting runs from the cycle's opening to the end of its closing day.
  function isHuntingOpen(cycle, now = new Date()) {
    const start = cycle?.cycleStart instanceof Date ? cycle.cycleStart.getTime() : NaN;
    const end = cycle?.cycleEnd instanceof Date ? cycle.cycleEnd.getTime() : NaN;
    return !(now.getTime() < start) && !(now.getTime() > end);
  }

  // This cycle's feedings for a character (conn may hold the character lock).
  async function cycleFeedings(db, characterId, cycleIndex) {
    const [rows] = await db.query(
      "SELECT * FROM feedings WHERE character_id=? AND cycle_index=? ORDER BY id",
      [characterId, cycleIndex]
    );
    return {
      rows,
      pending: rows.find((r) => r.status === 'pending') || null,
      hunts: rows.filter((r) => !NOT_HUNTS.includes(r.outcome)).length,
      fed: rows.some((r) => r.status === 'resolved'),
    };
  }

  // Ghouls this character could still feed this cycle (nav badge, Feeding page).
  async function countUnfedGhouls(characterId, cycleIndex) {
    const ghouls = (await ghoulsFor(pool, characterId)).filter((g) => !g.let_starve);
    const states = await ghoulStates(pool, ghouls.map((g) => g.id), cycleIndex);
    return ghouls.filter((g) => states[g.id].canFeed).length;
  }

  // The current cycle's ghoul upkeep time from the Calendar.
  async function upkeepAt() {
    const cycles = withDefaultDates(await readCycles());
    const idx = await findActiveIndex(cycles);
    return idx >= 0 ? cycles[idx].ghoul_feeding_date || null : null;
  }

  // The trackers the Feeding page always shows on top (and Mending reads). Mend is
  // POST /api/characters/:id/mend: it costs Rouse Checks, so it lives on this page.
  function vitalsOf(char) {
    const track = (t, max) => ({ superficial: Number(t?.superficial) || 0, aggravated: Number(t?.aggravated) || 0, max });
    const attr = (name) => Number(char.sheet.attributes?.[name]) || 1;
    return {
      characterId: char.id,
      hunger: readHunger(char.sheet),
      health: track(char.sheet.health, attr('Stamina') + 3),
      willpower: track(char.sheet.willpower, attr('Composure') + attr('Resolve')),
      mendAmount: mendAmount(char.sheet, char.clan),
    };
  }

  /* -------------------- Status -------------------- */
  fastify.get('/api/feeding/status', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const enabled = await isFeedingEnabled();
      if (!enabled) {
        const char = await getMyCharacter(req.user.id);
        return reply.send({ enabled: false, ...(char ? vitalsOf(char) : { noCharacter: true }) });
      }

      const cycle = await getCurrentCycle();
      const { cycleIndex, cycleStart, cycleEnd, cycleTitle, isDowntimeLinked } = cycle;
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
      const cycleRows = await cycleFeedings(pool, char.id, cycleIndex);

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
        ...vitalsOf(char),
        safeFeedBlock: (await checkSubmission({ characterId: char.id, requireFed: false })).error,
        pending: pendingRows[0] || null,
        resolvedThisCycle: cycleRows.rows.find((r) => r.status === 'resolved') || null,
        feedings: cycleRows.rows.filter((r) => r.status === 'resolved'),
        fed: cycleRows.fed,
        huntsUsed: cycleRows.hunts,
        huntsMax: HUNTS_PER_CYCLE,
        huntingOpen: isHuntingOpen(cycle),
        ghoulsUnfed: await countUnfedGhouls(char.id, cycleIndex),
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

      const cycle = await getCurrentCycle();
      const { cycleIndex } = cycle;
      if (!isHuntingOpen(cycle)) return reply.status(400).send({ error: 'Hunting is closed until the next downtime cycle opens.' });

      // The character row lock serializes this against a double-submitted
      // roll (or a concurrent Herd feed), so the per-cycle cap holds.
      const result = await withCharacterLock(char.id, async (conn, locked) => {
        const mine = await cycleFeedings(conn, char.id, cycleIndex);
        if (mine.pending) {
          return { code: 409, body: { error: 'Accept your current hunt before hunting again.', feedingId: mine.pending.id, status: 'pending' } };
        }
        if (mine.hunts >= HUNTS_PER_CYCLE) {
          return { code: 409, body: { error: `You have already hunted ${HUNTS_PER_CYCLE} times this cycle.` } };
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

  /* -------------------- Safe feeding (spend a downtime action) -------------------- */
  // Same deal as XP training (utils/xpPurchase.js runPurchase): the action is filed as a resolved,
  // released downtime of this cycle in the same transaction, under the same phase/deadline and
  // 3-per-cycle checks as a normal submission. It is itself a feeding, so it skips the "fed first"
  // check, unlocks the rest of the actions, and is not one of the three hunts.
  fastify.post('/api/feeding/downtime-feed', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      if (!(await isFeedingEnabled())) return reply.status(400).send({ error: 'The Feeding system is currently disabled.' });
      const char = await getMyCharacter(req.user.id);
      if (!char) return reply.status(404).send({ error: 'No character found for this account.' });
      const { cycleIndex } = await getCurrentCycle();

      // The character row lock serialises this against the other ways of using up an action.
      const result = await withCharacterLock(char.id, async (conn, locked) => {
        const mine = await cycleFeedings(conn, char.id, cycleIndex);
        if (mine.pending) return { code: 409, body: { error: 'Accept your current hunt first.' } };
        const { error } = await checkSubmission({ characterId: char.id, requireFed: false });
        if (error) return { code: 400, body: { error: `A safe feeding uses a downtime action. ${error}` } };

        const sheet = locked.sheet;
        const before = readHunger(sheet);
        if (before <= 1) return { code: 400, body: { error: 'Your Hunger is already as low as feeding can bring it.' } };
        sheet.hunger = applyHungerDelta(before, SAFE_FEED_HUNGER);
        await conn.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), char.id]);

        const [owned] = await conn.query('SELECT division FROM domain_claims WHERE owner_character_id=? LIMIT 1', [char.id]);
        await conn.query(
          `INSERT INTO feedings
            (character_id, division, predator_type, pool_label, dice_pool, difficulty, bonus_dice,
             chasse_merits_applied, hunger_before, normal_dice, hunger_dice, outcome, status, cycle_index, hunger_delta, safety_delta, resolved_at)
           VALUES (?, ?, ?, 'Downtime', 0, 0, 0, '[]', ?, '[]', '[]', 'downtime', 'resolved', ?, ?, 0, NOW())`,
          [char.id, owned[0]?.division || 39, getPredatorType(sheet) || '', before, cycleIndex, sheet.hunger - before]
        );
        await conn.query(
          `INSERT INTO downtimes (character_id, title, body, status, gm_resolution, resolved_at, is_released)
           VALUES (?, ?, ?, 'resolved', ?, NOW(), 1)`,
          [char.id, '[Feeding] Safe feeding',
            `Spent the night feeding carefully and out of sight. Hunger ${before} → ${sheet.hunger}.`,
            'Filed automatically: a safe feeding uses a downtime action, needs no roll and leaves no trace on any domain.']
        );
        log.info('Safe feeding with a downtime action', { character_id: char.id, cycleIndex, hungerBefore: before, hungerAfter: sheet.hunger });
        return { code: 200, body: { ok: true, hungerBefore: before, hungerAfter: sheet.hunger } };
      });
      reply.status(result.code).send(result.body);
    } catch (err) {
      log.err('POST /api/feeding/downtime-feed failed', { error: err.message });
      reply.status(500).send({ error: 'Database error spending a downtime on feeding' });
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

      const cycle = await getCurrentCycle();
      const { cycleIndex } = cycle;
      if (!isHuntingOpen(cycle)) return reply.status(400).send({ error: 'Feeding is closed until the next downtime cycle opens.' });

      // Herd isn't a hunt: it repeats until the pool runs dry, and once you
      // have fed this cycle it is only worth using while Hunger can still drop.
      const result = await withCharacterLock(char.id, async (conn, locked) => {
        const mine = await cycleFeedings(conn, char.id, cycleIndex);
        if (mine.pending) {
          return { code: 409, body: { error: 'Accept your current hunt before feeding on your Herd.', feedingId: mine.pending.id, status: 'pending' } };
        }
        if (mine.fed && readHunger(locked.sheet) <= 1) {
          return { code: 400, body: { error: 'Your Hunger is already as low as feeding can bring it.' } };
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
      if (!isOwnerOrAdmin(req.user, locked.user_id)) {
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
      if (!isOwnerOrAdmin(req.user, rows[0].owner_user_id)) {
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
      // No force: re-running an already processed cycle would stack a second
      // -1 on every division (this happened once on prod via a misclick).
      const result = await runFeedingDecay(pool, log);
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

        // A safe feeding filed its downtime action in the same transaction: give the slot back too.
        if (feeding.outcome === 'downtime') {
          await conn.query(
            `DELETE FROM downtimes WHERE character_id=? AND title='[Feeding] Safe feeding'
               AND ABS(TIMESTAMPDIFF(SECOND, created_at, ?)) <= 5 ORDER BY id LIMIT 1`,
            [feeding.character_id, feeding.created_at]
          );
          undone.downtime = true;
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
      const [chars] = await pool.query('SELECT id, name, sheet FROM characters WHERE sheet IS NOT NULL AND user_id IS NOT NULL');
      const roster = [];
      for (const row of chars) {
        const sheet = parseSheet(row.sheet);
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

      const r = await withSheetLock(pool, character_id, (sheet, row) => {
        const merits = Array.isArray(sheet?.advantages?.merits) ? sheet.advantages.merits : [];
        const herdEntry = merits.find(b =>
          String(b.id || '').toLowerCase().includes('herd__herd') ||
          String(b.name || '').toLowerCase() === 'herd'
        );
        if (!herdEntry) return { error: 'Character does not have the Herd background' };

        const herdDots = clamp(Number(herdEntry.dots) || 0, 0, 5);
        const rawCurrent = sheet.herd_current !== undefined ? Number(sheet.herd_current) : herdDots;
        const before = clamp(rawCurrent, 0, herdDots);
        const after = clamp(before + d, 0, herdDots);

        sheet.herd_current = after;
        return { herdDots, before, after, name: row.name };
      });
      if (r.notFound) return reply.status(404).send({ error: 'Character not found' });
      if (r.error) return reply.status(400).send({ error: r.error });
      const { herdDots, before, after, name } = r;
      log.adm('Admin herd adjust', { admin: req.user.id, character_id, delta: d, before, after });
      reply.send({ ok: true, character_id, name, herdDots, herdBefore: before, herdAfter: after });
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

      const r = await withSheetLock(pool, character_id, (sheet, row) => {
        const before = clamp(sheet.hunger !== undefined && sheet.hunger !== null ? Number(sheet.hunger) : 1, 0, 5);
        let after = before;

        if (hunger !== undefined && !isNaN(Number(hunger))) {
          after = clamp(Number(hunger), 0, 5);
        } else if (delta !== undefined) {
          const d = parseInt(delta, 10);
          if (isNaN(d) || d === 0) return { error: 'delta must be a non-zero integer' };
          // GM manual edit: allows 0 to 5, but cannot go below 0 (cannot go to minus)
          after = clamp(before + d, 0, 5);
        } else {
          return { error: 'delta or hunger required' };
        }

        sheet.hunger = after;
        return { before, after, name: row.name };
      });
      if (r.notFound) return reply.status(404).send({ error: 'Character not found' });
      if (r.error) return reply.status(400).send({ error: r.error });
      const { before, after, name } = r;
      log.adm('Admin hunger adjust', { admin: req.user.id, character_id, delta, before, after });
      reply.send({ ok: true, character_id, name, hungerBefore: before, hungerAfter: after });
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
      counts.success = (byOutcome.success || 0) + (byOutcome.critical || 0) + (byOutcome.messy_critical || 0) + (byOutcome.herd || 0) + (byOutcome.manual || 0) + (byOutcome.downtime || 0);
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

  /* -------------------- Ghouls -------------------- */
  // A personal ghoul is its owner's; a coterie ghoul any member may feed, but
  // only its domitor lets it go (same split as the coterie retainer routes).
  const mayLetStarve = (g, characterId) => (g.coterie_id ? g.domitor_character_id : g.character_id) === characterId;

  async function loadGhoul(db, retainerId, characterId) {
    const ghoul = (await ghoulsFor(db, characterId)).find((g) => g.id === retainerId);
    return ghoul ? { ...ghoul, canLetStarve: mayLetStarve(ghoul, characterId) } : null;
  }

  fastify.get('/api/feeding/ghouls', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const char = await getMyCharacter(req.user.id);
      if (!char) return reply.send({ ghouls: [], upkeepAt: null });
      const { cycleIndex } = await getCurrentCycle();
      const ghouls = await ghoulsFor(pool, char.id);
      const states = await ghoulStates(pool, ghouls.map((g) => g.id), cycleIndex);
      reply.send({
        upkeepAt: await upkeepAt(),
        ghouls: ghouls.map((g) => ({
          ...g,
          let_starve: !!g.let_starve,
          canLetStarve: mayLetStarve(g, char.id),
          ...states[g.id],
        })),
      });
    } catch (err) {
      log.err('GET /api/feeding/ghouls failed', { error: err.message });
      reply.status(500).send({ error: 'Database error fetching ghouls' });
    }
  });

  fastify.post('/api/feeding/ghouls/:rid/feed', { preHandler: [authRequired] }, async (req, reply) => {
    const conn = await pool.getConnection();
    try {
      if (!(await isFeedingEnabled())) return reply.status(400).send({ error: 'The Feeding system is currently disabled.' });
      const char = await getMyCharacter(req.user.id);
      if (!char) return reply.status(404).send({ error: 'No character found for this account.' });
      const ghoul = await loadGhoul(pool, Number(req.params.rid), char.id);
      if (!ghoul) return reply.status(404).send({ error: 'Ghoul not found.' });
      const { cycleIndex } = await getCurrentCycle();

      await conn.beginTransaction();
      const r = await feedGhoul(conn, { ghoul, feederId: char.id, cycleIndex, method: 'early' });
      if (r.error) { await conn.rollback(); return reply.status(400).send({ error: r.error }); }
      await conn.query('UPDATE retainers SET let_starve=0 WHERE id=?', [ghoul.id]);
      await conn.commit();
      log.info('Ghoul fed early', { retainer_id: ghoul.id, character_id: char.id, cycleIndex, success: r.success });
      reply.send({ ok: true, success: r.success, dice: r.dice, hungerBefore: r.hungerBefore, hungerAfter: r.hungerAfter });
    } catch (err) {
      await conn.rollback().catch(() => {});
      if (err.code === 'ER_DUP_ENTRY') return reply.status(409).send({ error: 'This ghoul has already been fed (or starved) this cycle.' });
      log.err('POST /api/feeding/ghouls/:rid/feed failed', { error: err.message });
      reply.status(500).send({ error: 'Database error feeding ghoul' });
    } finally {
      conn.release();
    }
  });

  // Feeds every ghoul the character can still feed this cycle (not the ones let
  // go), one Rouse Check each, stopping when their Hunger reaches 5.
  fastify.post('/api/feeding/ghouls/feed-all', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      if (!(await isFeedingEnabled())) return reply.status(400).send({ error: 'The Feeding system is currently disabled.' });
      const char = await getMyCharacter(req.user.id);
      if (!char) return reply.status(404).send({ error: 'No character found for this account.' });
      const { cycleIndex } = await getCurrentCycle();
      const ghouls = (await ghoulsFor(pool, char.id)).filter((g) => !g.let_starve);
      const states = await ghoulStates(pool, ghouls.map((g) => g.id), cycleIndex);

      const fed = [];
      let stopped = null;
      for (const ghoul of ghouls.filter((g) => states[g.id].canFeed)) {
        const conn = await pool.getConnection();
        try {
          await conn.beginTransaction();
          const r = await feedGhoul(conn, { ghoul, feederId: char.id, cycleIndex, method: 'early' });
          if (r.error) { await conn.rollback(); stopped = r.error; break; }
          await conn.commit();
          fed.push({ id: ghoul.id, name: ghoul.name, success: r.success, hungerAfter: r.hungerAfter });
        } catch (err) {
          await conn.rollback().catch(() => {});
          if (err.code !== 'ER_DUP_ENTRY') throw err; // someone else fed it meanwhile
        } finally {
          conn.release();
        }
      }
      log.info('Ghouls fed in bulk', { character_id: char.id, cycleIndex, fed: fed.length, stopped });
      reply.send({ ok: true, fed, stopped });
    } catch (err) {
      log.err('POST /api/feeding/ghouls/feed-all failed', { error: err.message });
      reply.status(500).send({ error: 'Database error feeding ghouls' });
    }
  });

  fastify.post('/api/feeding/ghouls/:rid/let-starve', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const char = await getMyCharacter(req.user.id);
      if (!char) return reply.status(404).send({ error: 'No character found for this account.' });
      const ghoul = await loadGhoul(pool, Number(req.params.rid), char.id);
      if (!ghoul) return reply.status(404).send({ error: 'Ghoul not found.' });
      if (!ghoul.canLetStarve) return reply.status(403).send({ error: "Only this ghoul's domitor can let them go unfed." });
      const value = !!req.body?.value;
      await pool.query('UPDATE retainers SET let_starve=? WHERE id=?', [value ? 1 : 0, ghoul.id]);
      log.info('Ghoul let-starve toggled', { retainer_id: ghoul.id, character_id: char.id, value });
      reply.send({ ok: true, let_starve: value });
    } catch (err) {
      log.err('POST /api/feeding/ghouls/:rid/let-starve failed', { error: err.message });
      reply.status(500).send({ error: 'Database error updating ghoul' });
    }
  });

  /* ---- Admin: every ghoul's upkeep state this cycle ---- */
  fastify.get('/api/admin/feeding/ghouls', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { cycleIndex } = await getCurrentCycle();
      const [rows] = await pool.query(
        `SELECT r.id, r.name, r.tier, r.sheet, r.coterie_id, r.let_starve, co.name AS coterie_name,
                COALESCE(owner.name, dom.name) AS owner_name
           FROM retainers r
           LEFT JOIN coteries co ON co.id = r.coterie_id
           LEFT JOIN characters owner ON owner.id = r.character_id
           LEFT JOIN characters dom ON dom.id = r.domitor_character_id
          WHERE r.coterie_id IS NOT NULL OR owner.user_id IS NOT NULL
          ORDER BY r.name`
      );
      const ghouls = rows.filter((r) => parseSheet(r.sheet)?.isGhoul === true).map(({ sheet, ...r }) => r);
      const states = await ghoulStates(pool, ghouls.map((g) => g.id), cycleIndex);
      const due = await dueUpkeepCycle(new Date());
      reply.send({
        cycleIndex,
        upkeepAt: await upkeepAt(),
        lastProcessed: await getSetting('ghoul_upkeep_last_cycle', null),
        lastDue: due ? due.cycleIndex : null,
        ghouls: ghouls.map((g) => ({ ...g, let_starve: !!g.let_starve, ...states[g.id] })),
      });
    } catch (err) {
      log.err('GET /api/admin/feeding/ghouls failed', { error: err.message });
      reply.status(500).send({ error: 'Database error fetching ghouls', details: err.sqlMessage || err.message });
    }
  });

  /* ---- Admin: active characters with no feeding this cycle ---- */
  fastify.get('/api/admin/feeding/unfed', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { cycleIndex } = await getCurrentCycle();
      const [rows] = await pool.query(
        `SELECT c.id, c.name, c.sheet FROM characters c
          WHERE c.user_id IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM feedings f WHERE f.character_id = c.id AND f.cycle_index = ? AND f.status = 'resolved')
          ORDER BY c.name`,
        [cycleIndex]
      );
      reply.send({
        cycleIndex,
        characters: rows.map((r) => {
          const sheet = parseSheet(r.sheet);
          const predatorType = getPredatorType(sheet);
          return {
            id: r.id, name: r.name, predatorType, hunger: readHunger(sheet),
            canAutomate: !!predatorType && PREDATOR_HUNTING_POOLS[predatorType]?.length > 0,
          };
        }),
      });
    } catch (err) {
      log.err('GET /api/admin/feeding/unfed failed', { error: err.message });
      reply.status(500).send({ error: 'Database error fetching unfed characters', details: err.sqlMessage || err.message });
    }
  });

  /* ---- Admin: record a feeding by hand (no roll, no domain) ---- */
  // body { character_id, hunger }: the character's Hunger after feeding (1-5; 0 only by sheet edit).
  // Unlocks downtime actions like any feeding; not a hunt, so it never uses one of the three.
  fastify.post('/api/admin/feeding/manual', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const characterId = Number(req.body?.character_id);
      const hunger = Number(req.body?.hunger);
      if (!Number.isInteger(characterId)) return reply.status(400).send({ error: 'character_id required' });
      if (!Number.isInteger(hunger) || hunger < 1 || hunger > 5) return reply.status(400).send({ error: 'Hunger after feeding must be 1 to 5.' });
      const { cycleIndex } = await getCurrentCycle();

      const result = await withCharacterLock(characterId, async (conn, locked) => {
        if (!locked) return { code: 404, body: { error: 'Character not found.' } };
        const sheet = locked.sheet;
        const before = readHunger(sheet);
        sheet.hunger = hunger;
        await conn.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), characterId]);
        const [owned] = await conn.query('SELECT division FROM domain_claims WHERE owner_character_id=? LIMIT 1', [characterId]);
        await conn.query(
          `INSERT INTO feedings
            (character_id, division, predator_type, pool_label, dice_pool, difficulty, bonus_dice,
             chasse_merits_applied, hunger_before, normal_dice, hunger_dice, outcome, status, cycle_index, hunger_delta, safety_delta, resolved_at)
           VALUES (?, ?, ?, 'Storyteller', 0, 0, 0, '[]', ?, '[]', '[]', 'manual', 'resolved', ?, ?, 0, NOW())`,
          [characterId, owned[0]?.division || 39, getPredatorType(sheet) || '', before, cycleIndex, hunger - before]
        );
        log.adm('Admin recorded a feeding', { admin: req.user.id, character_id: characterId, cycleIndex, hungerBefore: before, hungerAfter: hunger });
        return { code: 200, body: { ok: true, hungerBefore: before, hungerAfter: hunger } };
      });
      reply.status(result.code).send(result.body);
    } catch (err) {
      log.err('POST /api/admin/feeding/manual failed', { error: err.message });
      reply.status(500).send({ error: 'Database error recording feeding', details: err.sqlMessage || err.message });
    }
  });

  /* ---- Admin: run this cycle's ghoul upkeep now ---- */
  // Only ghouls with nothing recorded this cycle are touched, so it is safe to repeat.
  fastify.post('/api/admin/feeding/ghoul-upkeep', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { cycleIndex } = await getCurrentCycle();
      const result = await runGhoulUpkeep(pool, log, { cycleIndex, notify: sendPushNotification });
      log.adm('Ghoul upkeep manually triggered', { user: req.user.id, result });
      reply.send(result);
    } catch (err) {
      log.err('POST /api/admin/feeding/ghoul-upkeep failed', { error: err.message });
      reply.status(500).send({ error: 'Database error running ghoul upkeep', details: err.sqlMessage || err.message });
    }
  });
};

