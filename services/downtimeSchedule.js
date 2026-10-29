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
const { resolveCurrentFeedingCycle } = require('../utils/feedingCycle');
const { startOfMonth, endOfMonth } = require('./format');

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;
const DEFAULT_RELEASE_TIME = '10:00';
const DEFAULT_GHOUL_FEEDING_TIME = '20:00';

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

// Pre-fill for a cycle's ghoul upkeep: the evening before the event (closing is a Sunday, the event
// the next Saturday). Same 'YYYY-MM-DDTHH:mm' format as the release.
function defaultGhoulFeedingFor(closingDate) {
  const close = dateOnly(closingDate);
  if (!close) return '';
  const d = new Date(`${close}T12:00:00`);
  d.setDate(d.getDate() + 5);
  return `${dateOnly(d)}T${DEFAULT_GHOUL_FEEDING_TIME}`;
}

function releaseOf(cycle) {
  return (cycle && cycle.release_date) || '';
}

// Every cycle carries a concrete release and ghoul upkeep date: any cycle saved without one gets the pre-fill.
function withDefaultDates(cycles) {
  return cycles.map(c => (!c.closing_date ? c : {
    ...c,
    release_date: c.release_date || defaultReleaseFor(c.closing_date),
    ghoul_feeding_date: c.ghoul_feeding_date || defaultGhoulFeedingFor(c.closing_date),
  }));
}

// A cycle's id carries the number every feeding and ghoul upkeep is filed under (cycleIndexOf in
// utils/feedingCycle.js), so ids must stay small, unique and stable. The Calendar's generators make
// ids from Date.now() (too big for the INT column) or from event ids (renumbering live cycles, which
// would make every player look unfed). On save: a valid `cycle_N` id is kept, otherwise the cycle
// takes the id of the stored cycle that closes the same day, otherwise the next free number.
// Returns the cycles plus the renames, so a caller can follow a renamed active cycle.
const CYCLE_ID = /^cycle_(\d{1,6})$/;
function withStableIds(cycles, previous = []) {
  const numberOf = (c) => { const m = CYCLE_ID.exec(String(c?.id || '')); return m ? Number(m[1]) : null; };
  let next = Math.max(0, ...[...previous, ...cycles].map(numberOf).filter(n => n !== null)) + 1;
  const used = new Set();
  const renames = {};
  const out = cycles.map((c) => {
    let id = numberOf(c) !== null && !used.has(c.id) ? c.id : null;
    if (!id) {
      const match = previous.find(p => numberOf(p) !== null && !used.has(p.id) && p.closing_date && dateOnly(p.closing_date) === dateOnly(c.closing_date));
      id = match ? match.id : `cycle_${next++}`;
      renames[c.id] = id;
    }
    used.add(id);
    return id === c.id ? c : { ...c, id };
  });
  return { cycles: out, renames };
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

const ACTIONS_PER_CYCLE = 3;

const SUBMIT_CLOSED_MESSAGES = {
  closed: () => 'Downtime submissions are currently closed.',
  phase: (isProject) => isProject
    ? 'Long Term Project submissions are currently closed. Only Monthly Actions are being accepted.'
    : 'Monthly Action submissions are currently closed. Only Long Term Projects are being accepted.',
  not_open: () => 'Downtime submissions have not opened yet.',
  deadline: (isProject) => `The deadline for ${isProject ? 'project' : 'downtime'} submissions has passed.`,
};

// The window a character's actions are counted in: the current cycle, stretched to a manually
// extended deadline and to "now" (replacements written after the deadline still belong to this
// cycle until the next one opens). Falls back to the opening date, then the calendar month.
async function cycleWindow({ isProject = false, now = new Date() } = {}) {
  let from = startOfMonth();
  let to = endOfMonth();
  let cycleIndex = 0;
  const valid = (d) => d instanceof Date && !isNaN(d.getTime());
  const cycle = await resolveCurrentFeedingCycle().catch(() => null);
  if (valid(cycle?.cycleStart)) {
    cycleIndex = cycle.cycleIndex || 0;
    from = cycle.cycleStart;
    to = valid(cycle.cycleEnd) ? cycle.cycleEnd : new Date(from.getTime() + 90 * 24 * 60 * 60 * 1000);
  } else {
    const openingStr = await getSetting('downtime_opening', null);
    const opening = openingStr ? new Date(openingStr) : null;
    if (valid(opening)) { from = opening; to = new Date(opening.getTime() + 90 * 24 * 60 * 60 * 1000); }
  }
  const dlStr = await getSetting(isProject ? 'project_deadline' : 'downtime_deadline', null);
  const dl = dlStr ? new Date(dlStr) : null;
  if (valid(dl) && dl > to) to = dl;
  if (to < now) to = now;
  return { from, to, cycleIndex };
}

// Can this character file one more action right now? Feeding gate, phase/window/deadline and the
// per-cycle limit. Returns { error, code } (error null = allowed; code 'not_fed' | 'limit' | a
// submissionState reason) plus the counting window.
async function checkSubmission({ characterId, isProject = false }) {
  const { from, to, cycleIndex } = await cycleWindow({ isProject });
  const done = (error, code = null) => ({ error, code, from, to });

  if ((await getSetting('feeding_enabled', 'true')) === 'true') {
    const [fed] = await pool.query(
      "SELECT id FROM feedings WHERE character_id=? AND cycle_index=? AND status='resolved' LIMIT 1",
      [characterId, cycleIndex]
    );
    if (!fed.length) return done('You must feed this cycle before submitting downtime actions.', 'not_fed');
  }
  const state = await submissionState({ isProject, characterId, from, to });
  if (state.reason) return done(SUBMIT_CLOSED_MESSAGES[state.reason](isProject), state.reason);

  const [[cnt]] = await pool.query(
    "SELECT COUNT(*) AS c FROM downtimes WHERE character_id=? AND created_at >= ? AND created_at <= ? AND status <> 'rejected'",
    [characterId, from, to]
  );
  if (Number(cnt.c) >= ACTIONS_PER_CYCLE) return done(`Downtime limit reached for this cycle (${ACTIONS_PER_CYCLE}).`, 'limit');
  return done(null);
}

// Release every held resolution and push each affected player once. Used by the release timer job and
// by the manual release (switching mass release off).
async function releasePendingAndNotify() {
  const [owners] = await pool.query(
    `SELECT DISTINCT c.user_id
     FROM downtimes d JOIN characters c ON c.id = d.character_id
     WHERE d.is_released = 0
       AND ((d.gm_resolution IS NOT NULL AND d.gm_resolution <> '')
            OR LOWER(d.status) IN ('resolved', 'rejected', 'resolved in scene', 'approved')
            OR LOWER(d.status) LIKE 'approved%')`
  );
  await pool.query('UPDATE downtimes SET is_released = 1 WHERE is_released = 0');
  const { sendPushNotification } = require('./push');
  for (const o of owners) {
    sendPushNotification(o.user_id, 'Downtime resolutions are out', 'The Storytellers have released this cycle\'s resolutions. Open Downtimes to read yours.', { url: '/downtimes' }, 'system');
  }
  return owners.length;
}

// Broadcasts @everyone announcement from Giannakis bot when mass downtime release happens.
async function broadcastMassDowntimeDiscordAnnouncement() {
  const { log } = require('../logger');
  const { sendDiscordChannelMessage } = require('./discord');
  try {
    const isEnabled = (await getSetting('discord_enabled', 'true')) === 'true';
    if (!isEnabled) {
      log.info('Discord notifications disabled: skipping mass downtime release announcement.');
      return false;
    }
    const channelId = await getSetting('discord_channel_id', null);
    if (!channelId) {
      log.warn('Discord notification skipped: no channel ID configured for mass downtime release.');
      return false;
    }

    const cycles = await readCycles();
    const activeIdx = await findActiveIndex(cycles);
    const cycle = activeIdx >= 0 ? cycles[activeIdx] : null;
    const rawCycleName = cycle?.title || (cycle?.id ? `Cycle ${cycle.id}` : 'the current cycle');
    const cycleName = String(rawCycleName).replace(/[-—]/g, ':').trim();

    const [events] = await pool.query(
      `SELECT e.id, e.title, e.date, e.is_elysium, i.name AS elysium_name
         FROM events e
    LEFT JOIN elysium_invitations i ON i.event_id = e.id
        WHERE e.date >= NOW()
        ORDER BY e.date ASC
        LIMIT 1`
    );
    const nextEvent = events[0] || null;

    let eventNotice = '';
    if (nextEvent) {
      const evDate = new Date(nextEvent.date);
      const weekday = new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Athens', weekday: 'long' }).format(evDate);
      const dateFormatted = new Intl.DateTimeFormat('el-GR', { timeZone: 'Europe/Athens', day: 'numeric', month: 'numeric' }).format(evDate);
      const eventTitle = String(nextEvent.title || '').replace(/[-—]/g, ':').trim();
      const elysiumName = String(nextEvent.elysium_name || '').replace(/[-—]/g, ':').trim();
      const combinedTitle = (elysiumName && elysiumName.toLowerCase() !== eventTitle.toLowerCase())
        ? `${eventTitle}: ${elysiumName}`
        : eventTitle;
      eventNotice = `\n\nDon't forget that this ${weekday} (${dateFormatted}) our next event will happen, we have the event: **${combinedTitle}**!`;
    }

    const content = `@everyone\n🦇 **Mass Downtime Release**\n\nMass downtime release happened for downtime cycle: **${cycleName}**!\nAll submitted downtime actions have been resolved and released. Log in to the platform to read your character's results.${eventNotice}`;

    const payload = {
      content,
      allowed_mentions: { parse: ['everyone'] },
      allowedMentions: { parse: ['everyone'] }
    };

    await sendDiscordChannelMessage(channelId, payload);
    log.info('Mass downtime release Discord announcement broadcast successfully', { cycleName });
    return true;
  } catch (err) {
    log.err('Failed to broadcast mass downtime release Discord announcement', { error: err.message });
    return false;
  }
}

module.exports = {
  releasePendingAndNotify,
  broadcastMassDowntimeDiscordAnnouncement,
  deadlineEnd,
  dateOnly,
  defaultReleaseFor,
  releaseOf,
  defaultGhoulFeedingFor,
  withDefaultDates,
  withStableIds,
  readCycles,
  writeCycles,
  findActiveIndex,
  applyActiveCycle,
  syncSettingsToActiveCycle,
  advanceActiveCycle,
  submissionState,
  ACTIONS_PER_CYCLE,
  cycleWindow,
  checkSubmission,
};

if (require.main === module) {
  const assert = require('assert');
  assert.strictEqual(defaultReleaseFor('2026-10-04'), '2026-10-05T10:00');
  assert.strictEqual(defaultReleaseFor('2026-12-31'), '2027-01-01T10:00');
  assert.strictEqual(releaseOf({ closing_date: '2026-10-04', release_date: '2026-10-06T09:00' }), '2026-10-06T09:00');
  assert.strictEqual(releaseOf({ closing_date: '2026-10-04' }), '');
  assert.deepStrictEqual(withDefaultDates([{ closing_date: '2026-10-04' }, { closing_date: '2026-10-04', release_date: 'X' }]).map(c => c.release_date), ['2026-10-05T10:00', 'X']);
  assert.strictEqual(defaultGhoulFeedingFor('2026-10-04'), '2026-10-09T20:00');
  assert.strictEqual(withDefaultDates([{ closing_date: '2026-10-04', ghoul_feeding_date: 'Y' }])[0].ghoul_feeding_date, 'Y');
  assert.strictEqual(deadlineEnd('2026-10-04').getHours(), 23);
  assert.strictEqual(dateOnly('2026-10-04T10:00'), '2026-10-04');
  const stable = withStableIds(
    [{ id: 'event_cycle_42', closing_date: '2026-10-25' }, { id: 'cycle_1730000000000', closing_date: '2026-11-08' }, { id: 'cycle_2', closing_date: '2026-10-04' }],
    [{ id: 'cycle_2', closing_date: '2026-10-04' }, { id: 'cycle_3', closing_date: '2026-10-25' }]
  );
  assert.deepStrictEqual(stable.cycles.map(c => c.id), ['cycle_3', 'cycle_4', 'cycle_2']);
  assert.deepStrictEqual(stable.renames, { event_cycle_42: 'cycle_3', cycle_1730000000000: 'cycle_4' });
  console.log('downtimeSchedule self-check ok');
  process.exit(0);
}
