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

module.exports = { CHARACTER_DATES, RETAINER_DATES, setOnceDates, withSetOnceDates };
