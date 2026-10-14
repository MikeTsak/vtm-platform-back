// services/commsState.js
//
// Whether SchreckNet / Surface Web comms are open right now, and when that
// next changes. The admin calendar (setting chat_schedule) is the source of
// truth; the master switch shows the live state and can override it in an
// emergency (setting comms_override). An override only lasts until the
// calendar's own state next changes, then the calendar is in charge again.
//
// Calendar values per Athens date (YYYY-MM-DD):
//   true      open all day (from 00:01)
//   '17:00'   opens at 17:00 and stays open until 17:00 the next day,
//             unless that day is explicitly closed / an event
//   false     closed
//   'event'   closed (event day)
//   blank     closed
//
// comms_override: { state: bool, until: ISO | null, at: ISO, by: userId }.
// `until` is the first calendar change after the override was set; null means
// the calendar never changes within the horizon, so it holds until cleared.

const { getSetting, setSetting, clearSettingCache } = require('../utils/settings');
const { getAthensDate, getAthensHour, getAthensDayName, getAthensEuDate } = require('../utils/athensTime');

const HORIZON_DAYS = 60;
const DAY_MS = 24 * 60 * 60 * 1000;

function parseJson(raw, fallback) {
  if (raw && typeof raw === 'object') return raw;
  try { return JSON.parse(raw || '') ?? fallback; } catch { return fallback; }
}

// The calendar alone, at instant t.
function calendarOpenAt(schedule, t) {
  const today = getAthensDate(t);
  const yesterday = getAthensDate(new Date(t.getTime() - DAY_MS));
  const hour = getAthensHour(t);
  const state = schedule[today];
  if (state === false || state === 'event') return false;
  if (state === '17:00' && hour >= 17) return true;
  if (schedule[yesterday] === '17:00' && hour < 17) return true;
  return state === true;
}

const athensHHMM = (d) => new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Athens', hour: '2-digit', minute: '2-digit', hour12: false }).format(d);

// The Date for an Athens wall-clock time (handles summer/winter offsets).
function athensInstant(dateStr, hhmm) {
  for (const off of ['+03:00', '+02:00']) {
    const d = new Date(`${dateStr}T${hhmm}:00${off}`);
    if (getAthensDate(d) === dateStr && athensHHMM(d) === hhmm) return d;
  }
  return new Date(`${dateStr}T${hhmm}:00+02:00`);
}

// Every instant the calendar can change at (00:01 and 17:00 each day), after `from`.
function changePoints(from) {
  const points = [];
  for (let i = 0; i <= HORIZON_DAYS; i++) {
    const dateStr = getAthensDate(new Date(from.getTime() + i * DAY_MS));
    for (const hhmm of ['00:01', '17:00']) {
      const t = athensInstant(dateStr, hhmm);
      if (t > from) points.push({ t, hhmm });
    }
  }
  return points.sort((a, b) => a.t - b.t);
}

// When the calendar next changes from its state at `from`.
function nextCalendarChange(schedule, from) {
  const now = calendarOpenAt(schedule, from);
  return changePoints(from).find(p => calendarOpenAt(schedule, p.t) !== now)?.t || null;
}

const overrideActive = (override, t) => !!override && typeof override.state === 'boolean' && (!override.until || t < new Date(override.until));

function describe(point) {
  const { t, hhmm } = point;
  const day = getAthensDayName(t);
  const date = getAthensEuDate(t);
  return { day, time: hhmm, date, iso: t.toISOString(), formatted: `${day} at ${hhmm} (${date})` };
}

/**
 * Resolve the live comms state.
 * @returns {{ isCommsEnabled, calendarEnabled, override, overrideExpired, nextOpening, nextClosing }}
 */
function resolveCommsState(scheduleRaw, overrideRaw, nowInput = new Date()) {
  const schedule = parseJson(scheduleRaw, {}) || {};
  const now = nowInput instanceof Date && !isNaN(nowInput.getTime()) ? nowInput : new Date();
  const stored = parseJson(overrideRaw, null);
  const active = overrideActive(stored, now);
  const override = active ? stored : null;

  const effectiveAt = (t) => (overrideActive(override, t) ? override.state : calendarOpenAt(schedule, t));
  const isCommsEnabled = effectiveAt(now);
  const change = changePoints(now).find(p => effectiveAt(p.t) !== isCommsEnabled);

  return {
    isCommsEnabled,
    calendarEnabled: calendarOpenAt(schedule, now),
    override,
    overrideExpired: !!stored && !active,
    nextOpening: !isCommsEnabled && change ? describe(change) : null,
    nextClosing: isCommsEnabled && change ? describe(change) : null,
  };
}

async function loadCommsState(now = new Date()) {
  const [scheduleStr, overrideStr] = await Promise.all([
    getSetting('chat_schedule', '{}'),
    getSetting('comms_override', ''),
  ]);
  return resolveCommsState(scheduleStr, overrideStr, now);
}

// What clients get: on /api/comms/status and in the comms:status event.
// master_enabled is the switch position, which is now always the live state.
function statusPayload(info) {
  return {
    comms_enabled: info.isCommsEnabled,
    master_enabled: info.isCommsEnabled,
    calendar_enabled: info.calendarEnabled,
    override: info.override ? { state: info.override.state, until: info.override.until } : null,
    next_opening: info.nextOpening,
    next_closing: info.nextClosing,
  };
}

/**
 * Set the switch. Matching the calendar clears any override (back to the
 * calendar); anything else overrides until the calendar next changes.
 * `state === null` also clears it.
 */
async function setCommsSwitch(state, userId, now = new Date()) {
  clearSettingCache('chat_schedule');
  const schedule = parseJson(await getSetting('chat_schedule', '{}'), {}) || {};
  const calendar = calendarOpenAt(schedule, now);
  if (state === null || state === calendar) {
    await setSetting('comms_override', '');
  } else {
    const until = nextCalendarChange(schedule, now);
    await setSetting('comms_override', JSON.stringify({
      state, until: until ? until.toISOString() : null, at: now.toISOString(), by: userId,
    }));
  }
  clearSettingCache('comms_override');
  return loadCommsState(now);
}

// After the calendar is edited, an override still in force is re-anchored to
// the new calendar: it ends at the calendar's next change from now, or right
// away if the calendar now agrees with it.
async function reanchorOverride(now = new Date()) {
  clearSettingCache('comms_override');
  const stored = parseJson(await getSetting('comms_override', ''), null);
  if (!overrideActive(stored, now)) return;
  await setCommsSwitch(stored.state, stored.by, now);
}

async function clearExpiredOverride(info) {
  if (!info.overrideExpired) return false;
  await setSetting('comms_override', '');
  clearSettingCache('comms_override');
  return true;
}

module.exports = {
  resolveCommsState, loadCommsState, statusPayload, setCommsSwitch, reanchorOverride, clearExpiredOverride,
  calendarOpenAt, nextCalendarChange,
};
