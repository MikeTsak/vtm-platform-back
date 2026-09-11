// services/feedingDecay.js
//
// Cycle-end passive Masquerade decay for the Feeding system: for every
// division, -1 Safety if that division had zero feedings in the completed
// cycle, or only Success/Critical outcomes (nothing that cycle already cost
// Safety). Shared by jobs/index.js's nightly cron and the admin "Run Decay
// Now" safety-valve endpoint.
//
// Deliberately does NOT back-fill every skipped cycle if the server (or the
// feature) was off for a while — it only ever processes the single most
// recently completed cycle, so re-enabling after a long pause doesn't dump a
// pile of accumulated penalties on every domain at once.

const { getSetting, setSetting } = require('../utils/settings');
const { getCycleInfo } = require('../utils/feedingCycle');

const MAX_DIVISION = 88;

async function runFeedingDecay(pool, log, { force = false } = {}) {
  const enabled = (await getSetting('feeding_enabled', 'true')) === 'true';
  if (!enabled) return { skipped: 'disabled' };

  const anchor = await getSetting('feeding_cycle_anchor', new Date().toISOString());
  const { cycleIndex } = getCycleInfo(anchor);
  const completedCycle = cycleIndex - 1;
  if (completedCycle < 0) return { skipped: 'no completed cycle yet' };

  const lastProcessed = parseInt(await getSetting('feeding_last_decay_cycle_index', '-1'), 10);
  if (!force && completedCycle <= lastProcessed) return { skipped: 'already processed', completedCycle, lastProcessed };

  const [rows] = await pool.query(
    "SELECT division, outcome FROM feedings WHERE cycle_index = ? AND status='resolved'",
    [completedCycle]
  );
  const byDivision = new Map();
  for (const r of rows) {
    if (!byDivision.has(r.division)) byDivision.set(r.division, []);
    byDivision.get(r.division).push(r.outcome);
  }

  let decayed = 0;
  for (let division = 1; division <= MAX_DIVISION; division += 1) {
    const outcomes = byDivision.get(division) || [];
    const onlyNeutral = outcomes.length === 0 || outcomes.every((o) => o === 'success' || o === 'critical');
    if (!onlyNeutral) continue;

    const [existing] = await pool.query('SELECT division FROM domain_claims WHERE division=?', [division]);
    if (existing.length) {
      await pool.query(
        'UPDATE domain_claims SET safety_rating = GREATEST(0, IFNULL(safety_rating, 10) - 1) WHERE division=?',
        [division]
      );
    } else {
      await pool.query(
        'INSERT INTO domain_claims (division, owner_name, color, safety_rating) VALUES (?, NULL, ?, ?)',
        [division, '#888888', 9]
      );
    }
    decayed += 1;
  }

  await setSetting('feeding_last_decay_cycle_index', String(completedCycle));
  log?.info?.(`Feeding cycle ${completedCycle} decay applied to ${decayed} division(s).`);
  return { completedCycle, decayed };
}

module.exports = { runFeedingDecay };
