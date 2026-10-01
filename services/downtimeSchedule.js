// services/downtimeSchedule.js
//
// The downtime calendar in one place. The admin Calendar tab is the source of truth:
// `downtime_cycles_schedule` (JSON list of cycles) holds every cycle's opening, closing and
// mass release, and the "active" cycle is mirrored into the flat settings the rest of the
// code reads (downtime_opening, downtime_deadline, downtime_mass_release_date). Every write,
// whether it comes from the Calendar or the Downtimes tab, goes through here so both stay in step.
//
// Dates: opening/closing are 'YYYY-MM-DD'; a closing date means "through the end of that day".
// Mass release is 'YYYY-MM-DDTHH:mm' (the admin datetime-local format), stored explicitly on every
// cycle so the calendar shows exactly what will happen. A new cycle is pre-filled with the morning
// after it closes; the admin then sets the real time per cycle.

const pool = require('../db');
const { getSetting, setSetting } = require('../utils/settings');

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;
const DEFAULT_RELEASE_TIME = '10:00';

// A deadline stored as a bare date is open until 23:59:59 that day (what players see as the countdown).
function deadlineEnd(value) {
  if (!value) return null;
  const s = String(value);
  const d = DATE_ONLY.test(s) ? new Date(`${s}T23:59:59`) : new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

function dateOnly(value) {
  if (!value) return '';
  const s = String(value);
  if (DATE_ONLY.test(s.slice(0, 10))) return s.slice(0, 10);
  const d = new Date(s);
  if (isNaN(d.getTime())) return '';
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

// Pre-fill for a new cycle's release: the morning after it closes.
function defaultReleaseFor(closingDate) {
  const close = dateOnly(closingDate);
  if (!close) return '';
  const d = new Date(`${close}T12:00:00`);
  d.setDate(d.getDate() + 1);
  return `${dateOnly(d)}T${DEFAULT_RELEASE_TIME}`;
}

function releaseOf(cycle) {
  return (cycle && cycle.release_date) || '';
}

// Every cycle carries a concrete release date: any cycle saved without one gets the pre-fill.
function withReleaseDates(cycles) {
  return cycles.map(c => (c.release_date || !c.closing_date ? c : { ...c, release_date: defaultReleaseFor(c.closing_date) }));
}

async function readCycles() {
  try {
    const parsed = JSON.parse(await getSetting('downtime_cycles_schedule', '[]'));
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return [];
  }
}

async function writeCycles(cycles) {
  await setSetting('downtime_cycles_schedule', JSON.stringify(cycles));
}

// The cycle whose dates are currently live: the one the settings mirror, else the one flagged active.
async function findActiveIndex(cycles) {
  const opening = dateOnly(await getSetting('downtime_opening', ''));
  const deadline = dateOnly(await getSetting('downtime_deadline', ''));
  let idx = cycles.findIndex(c => dateOnly(c.opening_date) === opening && dateOnly(c.closing_date) === deadline);
  if (idx < 0 && deadline) idx = cycles.findIndex(c => dateOnly(c.closing_date) === deadline);
  if (idx < 0) idx = cycles.findIndex(c => c.status === 'active');
  return idx;
}

// Make `cycle` the live one: settings follow its dates, flags follow its position.
async function applyActiveCycle(cycles, activeId) {
  const idx = cycles.findIndex(c => String(c.id) === String(activeId));
  if (idx < 0) return cycles;
  const next = cycles.map((c, i) => ({ ...c, status: i === idx ? 'active' : (i < idx ? 'closed' : (c.status === 'active' ? 'scheduled' : c.status)) }));
  const active = next[idx];
  if (active.opening_date) await setSetting('downtime_opening', dateOnly(active.opening_date));
  if (active.closing_date) await setSetting('downtime_deadline', dateOnly(active.closing_date));
  const release = releaseOf(active);
  if (release && release !== (await getSetting('downtime_mass_release_date', ''))) {
    await setSetting('downtime_mass_release_date', release);
    await setSetting('downtime_mass_release_notified', 'false');
  }
  await writeCycles(next);
  return next;
}

// The Downtimes tab (or the Calendar's quick panel) changed a live date: copy it onto the active cycle
// so the calendar shows the same thing. `changes` uses setting names.
async function syncSettingsToActiveCycle(changes) {
  const cycles = await readCycles();
  const idx = await findActiveIndex(cycles);
  if (idx < 0) return;
  const c = { ...cycles[idx] };
  if (changes.downtime_opening !== undefined) c.opening_date = dateOnly(changes.downtime_opening) || null;
  if (changes.downtime_deadline !== undefined && dateOnly(changes.downtime_deadline)) c.closing_date = dateOnly(changes.downtime_deadline);
  if (changes.downtime_mass_release_date !== undefined) c.release_date = changes.downtime_mass_release_date || null;
  cycles[idx] = c;
  await writeCycles(cycles);
}

// Forward-only auto advance: when a later cycle's opening date arrives, it becomes the live one.
// Never moves backwards, so a manual "Set active" on a future cycle is left alone.
async function advanceActiveCycle(now = new Date()) {
  const cycles = await readCycles();
  if (!cycles.length) return null;
  const today = dateOnly(now);
  const currentOpening = dateOnly(await getSetting('downtime_opening', ''));
  const due = cycles
    .filter(c => c.opening_date && dateOnly(c.opening_date) <= today)
    .sort((a, b) => dateOnly(b.opening_date).localeCompare(dateOnly(a.opening_date)))[0];
  if (!due || (currentOpening && dateOnly(due.opening_date) <= currentOpening)) return null;
  await applyActiveCycle(cycles, due.id);
  return due;
}

// Can this character submit a new action of this kind right now? Returns { reason, lateSlots }:
// reason null = open; 'closed' | 'phase' | 'not_open' | 'deadline'. After the deadline a player may
// still submit one replacement per action of theirs rejected this cycle (rejecting gives the slot back).
async function submissionState({ isProject, characterId, from, to, now = new Date() }) {
  const phase = await getSetting('downtime_active_phase', 'standard');
  if (phase === 'closed') return { reason: 'closed', lateSlots: 0 };
  if ((phase === 'project' && !isProject) || (phase === 'standard' && isProject)) return { reason: 'phase', lateSlots: 0 };

  const opening = await getSetting('downtime_opening', null);
  const op = opening ? new Date(DATE_ONLY.test(opening) ? `${opening}T00:00:00` : opening) : null;
  if (op && !isNaN(op.getTime()) && now < op) return { reason: 'not_open', lateSlots: 0 };

  const dl = deadlineEnd(await getSetting(isProject ? 'project_deadline' : 'downtime_deadline', null));
  if (!dl || now <= dl) return { reason: null, lateSlots: 0 };

  let lateSlots = 0;
  if (characterId && from && to) {
    const [[row]] = await pool.query(
      `SELECT SUM(status = 'rejected') AS rejected, SUM(created_at > ? AND status <> 'rejected') AS late
       FROM downtimes WHERE character_id = ? AND created_at >= ? AND created_at <= ?`,
      [dl, characterId, from, to]
    );
    lateSlots = Math.max(0, Number(row?.rejected || 0) - Number(row?.late || 0));
  }
  return { reason: lateSlots > 0 ? null : 'deadline', lateSlots };
}

// Release every held resolution and push each affected player once. Used by the release timer job and
// by the manual release (switching mass release off).
async function releasePendingAndNotify() {
  const [owners] = await pool.query(
    `SELECT DISTINCT c.user_id
     FROM downtimes d JOIN characters c ON c.id = d.character_id
     WHERE d.is_released = 0
       AND ((d.gm_resolution IS NOT NULL AND d.gm_resolution <> '')
            OR LOWER(d.status) IN ('resolved', 'rejected', 'resolved in scene'))`
  );
  await pool.query('UPDATE downtimes SET is_released = 1 WHERE is_released = 0');
  const { sendPushNotification } = require('./push');
  for (const o of owners) {
    sendPushNotification(o.user_id, 'Downtime resolutions are out', 'The Storytellers have released this cycle\'s resolutions. Open Downtimes to read yours.', { url: '/downtimes' }, 'system');
  }
  return owners.length;
}

module.exports = {
  releasePendingAndNotify,
  deadlineEnd,
  dateOnly,
  defaultReleaseFor,
  releaseOf,
  withReleaseDates,
  readCycles,
  writeCycles,
  findActiveIndex,
  applyActiveCycle,
  syncSettingsToActiveCycle,
  advanceActiveCycle,
  submissionState,
};

if (require.main === module) {
  const assert = require('assert');
  assert.strictEqual(defaultReleaseFor('2026-10-04'), '2026-10-05T10:00');
  assert.strictEqual(defaultReleaseFor('2026-12-31'), '2027-01-01T10:00');
  assert.strictEqual(releaseOf({ closing_date: '2026-10-04', release_date: '2026-10-06T09:00' }), '2026-10-06T09:00');
  assert.strictEqual(releaseOf({ closing_date: '2026-10-04' }), '');
  assert.deepStrictEqual(withReleaseDates([{ closing_date: '2026-10-04' }, { closing_date: '2026-10-04', release_date: 'X' }]).map(c => c.release_date), ['2026-10-05T10:00', 'X']);
  assert.strictEqual(deadlineEnd('2026-10-04').getHours(), 23);
  assert.strictEqual(dateOnly('2026-10-04T10:00'), '2026-10-04');
  console.log('downtimeSchedule self-check ok');
  process.exit(0);
}
