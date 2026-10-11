// services/willpowerReset.js
//
// Willpower heals session to session: the day after a Modern Day event (any event that is not a
// "Past Time" one, same rule as downtimes.js's next_modern_event) every character's Willpower damage,
// Superficial and Aggravated, is cleared. The admin Calendar derives its "WP RESET" marker from the
// same rule, so moving an event moves the reset.
//
// resetDueDay is pure. `willpower_reset_through` (the last event day handled) makes the daily cron
// and the boot catch-up idempotent. With no marker yet only an event from yesterday triggers, so the
// first deploy never retro-resets for an old event.

const pool = require('../db');
const { getSetting, setSetting } = require('../utils/settings');
const { parseSheet } = require('../utils/sheet');
const { dateOnly } = require('./downtimeSchedule');

function nextDay(day) {
  const d = new Date(`${day}T12:00:00`);
  d.setDate(d.getDate() + 1);
  return dateOnly(d);
}

// The event day whose reset is due today, else null. Back-to-back event days reset after the last.
function resetDueDay(eventDays, today, through) {
  const days = new Set(eventDays);
  const due = [...days]
    .filter(d => d < today && d > (through || '') && !days.has(nextDay(d)))
    .sort()
    .pop();
  if (!due) return null;
  return !through && nextDay(due) !== today ? null : due;
}

async function resetAllWillpower() {
  const [rows] = await pool.query("SELECT id FROM characters WHERE sheet LIKE '%willpower%'");
  let reset = 0;
  for (const { id } of rows) {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [[row]] = await conn.query('SELECT sheet FROM characters WHERE id=? FOR UPDATE', [id]);
      const sheet = parseSheet(row?.sheet);
      if (Number(sheet.willpower?.superficial) || Number(sheet.willpower?.aggravated)) {
        sheet.willpower = { ...sheet.willpower, superficial: 0, aggravated: 0 };
        await conn.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), id]);
        reset += 1;
      }
      await conn.commit();
    } catch (e) {
      await conn.rollback().catch(() => {});
      throw e;
    } finally {
      conn.release();
    }
  }
  return reset;
}

async function runWillpowerReset(now = new Date()) {
  const [events] = await pool.query(
    "SELECT DISTINCT DATE_FORMAT(date, '%Y-%m-%d') AS day FROM events WHERE LOWER(title) NOT LIKE '%past time%'"
  );
  const through = await getSetting('willpower_reset_through', '');
  const day = resetDueDay(events.map(e => e.day), dateOnly(now), through);
  if (!day) return null;
  const reset = await resetAllWillpower();
  await setSetting('willpower_reset_through', day);
  return { day, reset };
}

module.exports = { runWillpowerReset, resetDueDay };

if (require.main === module) {
  const assert = require('assert');
  assert.strictEqual(resetDueDay(['2026-10-10'], '2026-10-11', ''), '2026-10-10');
  assert.strictEqual(resetDueDay(['2026-10-10'], '2026-10-10', ''), null);        // event day itself
  assert.strictEqual(resetDueDay(['2026-10-10'], '2026-10-12', ''), null);        // first run: no retro reset
  assert.strictEqual(resetDueDay(['2026-10-10'], '2026-10-12', '2026-09-01'), '2026-10-10'); // catch-up
  assert.strictEqual(resetDueDay(['2026-10-10'], '2026-10-12', '2026-10-10'), null);        // already done
  assert.strictEqual(resetDueDay(['2026-10-10', '2026-10-11'], '2026-10-11', '2026-09-01'), null); // day 2 of a weekend
  assert.strictEqual(resetDueDay(['2026-10-10', '2026-10-11'], '2026-10-12', ''), '2026-10-11');
  console.log('willpowerReset self-check ok');
  process.exit(0);
}
