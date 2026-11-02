// services/feedingCycleEnd.js
//
// The Feeding system's background upkeep, run by jobs/index.js (daily + at boot)
// and the admin Feeding > Tools button.
//
// Domain Safety never drops on its own. It drops only from a failed hunt
// (routes/feeding.js confirm: Failure -1, Bestial Failure / Messy Critical -2),
// a Live Session Messy Critical (routes/dice.js), or a Storyteller. It RISES by
// 1 for every 3 months a division goes without a failed hunt, up to 10.
// (Until 2026-11-02 every quiet division lost 1 Safety per cycle; migration
// 0076 gave those points back.)

const { getSetting, getSettingStrict, clearSettingCache } = require('../utils/settings');
const { getCycleInfo, resolveCurrentFeedingCycle } = require('../utils/feedingCycle');
const { withSheetLock } = require('../utils/sheetLock');

const FAILED_HUNTS = "('failure','bestial_failure','messy_critical')";

/**
 * +1 Safety for each division whose last failed hunt (or last +1, whichever is
 * later) is 3 months old. One atomic UPDATE: the +1 moves safety_recovered_at to
 * now, so a second run, or a second process, finds nothing due. A failed hunt
 * restarts the clock by being newer; undoing it deletes the row, so the clock
 * falls back to the hunt before it. Divisions with no rating (unset = 10) skip.
 */
async function runSafetyRecovery(pool) {
  const [res] = await pool.query(`
    UPDATE domain_claims dc
    LEFT JOIN (
      SELECT division, MAX(resolved_at) AS last_fail
        FROM feedings
       WHERE status = 'resolved' AND outcome IN ${FAILED_HUNTS}
       GROUP BY division
    ) f ON f.division = dc.division
       SET dc.safety_rating = LEAST(10, dc.safety_rating + 1),
           dc.safety_recovered_at = NOW()
     WHERE dc.safety_rating IS NOT NULL AND dc.safety_rating < 10
       AND GREATEST(COALESCE(f.last_fail, dc.safety_recovered_at), COALESCE(dc.safety_recovered_at, f.last_fail))
           <= NOW() - INTERVAL 3 MONTH`);
  return { recovered: res.affectedRows };
}

/**
 * Herd pool regen: every character with Herd regains 1 point when a cycle ends,
 * once per cycle (latched in feeding_last_decay_cycle_index, the key's old name).
 */
async function runHerdRegen(pool) {
  const enabled = (await getSetting('feeding_enabled', 'true')) === 'true';
  if (!enabled) return { skipped: 'disabled' };

  let cycleIndex = 0;
  try {
    cycleIndex = (await resolveCurrentFeedingCycle()).cycleIndex;
  } catch (e) {
    const anchor = await getSetting('feeding_cycle_anchor', new Date().toISOString());
    cycleIndex = getCycleInfo(anchor).cycleIndex;
  }

  const completedCycle = cycleIndex - 1;
  if (completedCycle < 0) return { skipped: 'no completed cycle yet' };

  // Strict read: a failed read must not look like "never processed". On
  // 2026-11-02 one did, and the cycle was processed twice.
  const lastProcessed = parseInt(await getSettingStrict('feeding_last_decay_cycle_index', '-1'), 10);
  if (completedCycle <= lastProcessed) return { skipped: 'already processed', completedCycle, lastProcessed };

  // Latch first, with a throwing write, so a crash mid-run never repeats the cycle.
  // ponytail: a half-finished run is not resumed; fix a missed point in the admin Herd section.
  await pool.query(
    `INSERT INTO app_settings (setting_key, setting_value) VALUES ('feeding_last_decay_cycle_index', ?)
     ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)`,
    [String(completedCycle)]
  );
  clearSettingCache('feeding_last_decay_cycle_index');

  const [charRows] = await pool.query('SELECT id FROM characters WHERE sheet IS NOT NULL AND user_id IS NOT NULL');
  let herdRegen = 0;
  for (const row of charRows) {
    // Re-read under a row lock: the sheet above may be stale by the time we write.
    const r = await withSheetLock(pool, row.id, (sheet) => {
      const merits = Array.isArray(sheet.advantages?.merits) ? sheet.advantages.merits : [];
      const herdEntry = merits.find(b =>
        String(b.id || '').toLowerCase().includes('herd__herd') ||
        String(b.name || '').toLowerCase() === 'herd'
      );
      if (!herdEntry) return { skip: true };

      const herdDots = Math.max(0, Math.min(5, Number(herdEntry.dots) || 0));
      if (herdDots < 1) return { skip: true };

      // If never used, herd_current is implicitly full — nothing to regen
      if (sheet.herd_current === undefined || sheet.herd_current === null) return { skip: true };

      const current = Math.max(0, Math.min(herdDots, Number(sheet.herd_current)));
      if (current >= herdDots) return { skip: true }; // already full

      sheet.herd_current = Math.min(herdDots, current + 1);
      return {};
    });
    if (!r.skip && !r.notFound) herdRegen += 1;
  }
  return { completedCycle, herdRegen };
}

module.exports = { runSafetyRecovery, runHerdRegen };
