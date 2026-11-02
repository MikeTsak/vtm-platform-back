// Player-entered life dates are set once (user ruling 2026-10-30): an empty date
// may be filled in by the player, a filled one is locked and only a Storyteller
// (admin routes, which skip this) can change or clear it. When the player set
// each one is kept in `datesSetAt` so the Storyteller can see it.
//   character sheet: birthDate, deathDate (the Embrace)
//   retainer sheet:  birthDate, ghouledDate

const CHARACTER_DATES = ['birthDate', 'deathDate'];
const RETAINER_DATES = ['birthDate', 'ghouledDate'];

const isDate = (v) => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(Date.parse(v));

/**
 * The date fields (and `datesSetAt`) to write, from the stored sheet and what
 * the player sent. Spread the result over the sheet being saved.
 */
function setOnceDates(stored, incoming, keys, now = new Date()) {
  const s = stored || {};
  const inc = incoming || {};
  const out = {};
  const setAt = { ...(s.datesSetAt || {}) };
  for (const k of keys) {
    if (s[k]) out[k] = s[k];
    else if (isDate(inc[k])) { out[k] = inc[k]; setAt[k] = now.toISOString(); }
    else out[k] = undefined;
  }
  out.datesSetAt = Object.keys(setAt).length ? setAt : undefined;
  return out;
}

// Same, applied to a whole sheet the player sent; undefined keys are dropped.
function withSetOnceDates(stored, sheet, keys, now) {
  const merged = { ...(sheet || {}), ...setOnceDates(stored, sheet, keys, now) };
  for (const k of [...keys, 'datesSetAt']) if (merged[k] === undefined) delete merged[k];
  return merged;
}

// --- Storyteller push when a player fills in a date -------------------------
// Ages mirror front/src/utils/ages.js. ponytail: a ghoul's apparent age here
// ignores starved cycles (dates are set early, before any starvation); the
// sheet shows the full working.
const YEAR_MS = 365.2425 * 864e5;
const yearsBetween = (a, b) => Math.max(0, Math.floor((new Date(b) - new Date(a)) / YEAR_MS));
const fmt = (v) => (v ? new Date(v).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }) : '?');

/** Markdown push body, or null when this save set no new date. */
function newDatesMessage(stored, saved, keys, { who, retainerName, createdAt, now = new Date() }) {
  const s = stored || {};
  const fresh = keys.filter((k) => !s[k] && saved?.[k]);
  if (!fresh.length) return null;
  const birth = saved.birthDate;
  const real = birth ? yearsBetween(birth, now) : null;
  let apparent = null;
  let dates;
  if (!retainerName) {
    if (birth && saved.deathDate) apparent = yearsBetween(birth, saved.deathDate);
    dates = `born **${fmt(birth)}**, Embraced **${fmt(saved.deathDate)}**`;
  } else if (saved.isGhoul === true) {
    const ghouled = saved.ghouledDate || createdAt || now;
    if (birth) {
      const crone = (saved.flaws || []).some((f) => /crone's curse/i.test(String(f?.name || '')));
      apparent = Math.min(yearsBetween(birth, ghouled), real) + (crone ? 10 : 0);
    }
    dates = `born **${fmt(birth)}**, ghouled **${fmt(saved.ghouledDate)}**`;
  } else {
    apparent = real;
    dates = `born **${fmt(birth)}**`;
  }
  const subject = retainerName ? `the dates of **${retainerName}** (${saved.isGhoul === true ? 'ghoul' : 'mortal retainer'})` : 'their dates';
  return `**${who}** set ${subject}: ${dates}.\nApparent age **${apparent ?? '?'}**, true age **${real ?? '?'}**.`;
}

/**
 * Fire-and-forget ntfy push to the Storytellers after a player's save. `deps`
 * is the route's { pool, log, broadcastNtfyAlert } (stubbed in tests); `userId`
 * is the player who saved, their character's name is used as "who".
 */
async function notifyNewDates(deps, userId, stored, saved, keys, opts = {}) {
  const { pool, log, broadcastNtfyAlert } = deps;
  if (typeof broadcastNtfyAlert !== 'function') return;
  try {
    if (!newDatesMessage(stored, saved, keys, { ...opts, who: '' })) return;
    const [[ch]] = await pool.query('SELECT name FROM characters WHERE user_id=? ORDER BY id ASC LIMIT 1', [userId]);
    const message = newDatesMessage(stored, saved, keys, { ...opts, who: ch?.name || 'A player' });
    await broadcastNtfyAlert(message, { title: 'Dates set', tags: 'calendar', priority: 'default' });
  } catch (e) {
    log?.err('Dates push failed', { message: e.message });
  }
}

module.exports = { CHARACTER_DATES, RETAINER_DATES, setOnceDates, withSetOnceDates, newDatesMessage, notifyNewDates };
