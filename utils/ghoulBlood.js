// V5 Core (ghouls): a Rouse Check's worth of vitae gives a mortal "the first
// dot in their master's highest-rated discipline, along with a single level 1
// power possessed by the vampire". Applies to every vampire whose blood the
// ghoul carries: the domitor and, on a coterie ghoul, each member who gives it
// (user ruling 2026-10-30). Storytellers are exempt at the routes.

const { findPower } = require('./xpPurchase');

const key = (v) => String(v || '').replace(/\s*\(Errata\)\s*$/i, '').trim().toLowerCase();

// Ties all count: Potence 3 and Celerity 3 can both be passed on.
function highestDisciplines(vampSheet) {
  const rated = Object.entries((vampSheet && vampSheet.disciplines) || {})
    .filter(([d, v]) => d !== 'Thin-blood Alchemy' && Number(v) > 0);
  const top = Math.max(0, ...rated.map(([, v]) => Number(v)));
  return rated.filter(([, v]) => Number(v) === top).map(([d]) => d);
}

// Error string, or null when `vampSheet` can give `discipline` with `power`.
function giftError(vampSheet, discipline, power, who = 'their domitor') {
  const highest = highestDisciplines(vampSheet);
  if (!highest.includes(discipline)) {
    return highest.length
      ? `A ghoul gains only ${who}'s highest-rated Discipline: ${highest.join(' or ')}.`
      : `${who} has no Discipline to pass on.`;
  }
  const known = findPower(discipline, power && (power.id || power.name));
  if (!known || known.level !== 1) return `Pick a level 1 ${discipline} power.`;
  const wanted = [key(known.id), key(known.name)];
  const owned = ((vampSheet.disciplinePowers || {})[discipline] || [])
    .some((p) => (p && typeof p === 'object' ? [p.id, p.name] : [p]).some((k) => k && wanted.includes(key(k))));
  if (!owned) return `${known.name} is not a power ${who} has. The ghoul can only learn one they possess.`;
  return null;
}

// The ghoul's Disciplines with their powers, as a comparable string.
const giftKey = (sheet) => Object.entries((sheet && sheet.disciplines) || {})
  .filter(([, v]) => Number(v) === 1)
  .map(([d]) => `${d}:${key(((sheet.powers || []).find((p) => p && p.discipline === d) || {}).name)}`)
  .sort().join('|');

// Checks a ghoul sheet's Disciplines against the vampire feeding it. Only a
// changed set is checked, so ghouls made before this rule keep their gift.
function checkGhoulGift(vampSheet, sheet, oldSheet, who) {
  if (!sheet || sheet.isGhoul !== true) return null;
  if (oldSheet && oldSheet.isGhoul === true && giftKey(oldSheet) === giftKey(sheet)) return null;
  for (const [d, v] of Object.entries(sheet.disciplines || {})) {
    if (Number(v) !== 1) continue;
    const err = giftError(vampSheet, d, (sheet.powers || []).find((p) => p && p.discipline === d), who);
    if (err) return err;
  }
  return null;
}

module.exports = { highestDisciplines, giftError, checkGhoulGift };
