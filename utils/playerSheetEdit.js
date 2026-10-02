// utils/playerSheetEdit.js
//
// What a player may change on their own sheet WITHOUT spending XP: the
// narrative bits (ambition, desire, touchstones, convictions, notes on their
// merits) and two live-session flags (compulsion, Blush of Life). Frenzy is
// set by the Storyteller or a failed Rouse at Hunger 5, and cleared by a
// server-rolled frenzy test (routes/dice.js).
// Everything else is copied from the stored sheet: dots, powers and merits
// change through utils/xpPurchase.js; Hunger, Health and Willpower only
// through the server-rolled mechanics in routes/mechanics.js or a Storyteller.
const { CATALOG } = require('./xpPurchase');
const { parseSheet } = require('./sheet');

const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : null);
// Touchstones/convictions are small free-form records; cap their size, not their shape.
const smallArray = (v) => (Array.isArray(v) && v.length <= 30 && JSON.stringify(v).length <= 20000 ? v : null);

/**
 * @param {object} storedSheet the sheet in the database
 * @param {object} incoming    the sheet the client sent
 * @param {string} clan        the stored clan
 * @returns {object} the stored sheet with only the allowed fields taken from `incoming`
 */
function mergePlayerSheetEdit(storedSheet, incoming, clan) {
  const out = JSON.parse(JSON.stringify(parseSheet(storedSheet) || {}));
  const inc = incoming && typeof incoming === 'object' ? incoming : {};
  const has = (k) => Object.prototype.hasOwnProperty.call(inc, k);

  for (const k of ['ambition', 'desire']) if (has(k)) out[k] = str(inc[k], 2000) ?? '';
  if (has('compulsion')) out.compulsion = str(inc.compulsion, 500);
  if (has('blushOfLife')) out.blushOfLife = inc.blushOfLife === true;

  for (const k of ['touchstones', 'convictions']) {
    if (has(k) && smallArray(inc[k])) out[k] = inc[k];
    if (inc.morality && smallArray(inc.morality[k])) out.morality = { ...(out.morality || {}), [k]: inc.morality[k] };
  }

  // Notes / descriptions on merits, flaws and backgrounds the character
  // already has: same entries in the same order, only the text may differ.
  const lists = [['advantages', 'merits'], ['advantages', 'flaws'], [null, 'backgrounds']];
  for (const [parent, key] of lists) {
    const storedList = parent ? out[parent]?.[key] : out[key];
    const incList = parent ? inc[parent]?.[key] : inc[key];
    if (!Array.isArray(storedList) || !Array.isArray(incList) || storedList.length !== incList.length) continue;
    const same = storedList.every((e, i) => e?.id === incList[i]?.id && Number(e?.dots || 0) === Number(incList[i]?.dots || 0));
    if (!same) continue;
    storedList.forEach((e, i) => {
      if (!e || typeof e !== 'object') return;
      if (typeof incList[i].notes === 'string') e.notes = incList[i].notes.slice(0, 5000);
      if (typeof incList[i].desc === 'string') e.desc = incList[i].desc.slice(0, 5000);
    });
  }

  // Mystic of the Void picks: Oblivion powers within the character's rating,
  // as many as the merit allows (3 for Hecata/Lasombra with the 2-dot version).
  if (has('mystic_powers') && Array.isArray(inc.mystic_powers)) {
    const merit = (out.advantages?.merits || []).find(m => m?.id === 'other__mystic_of_the_void');
    const oblivion = Number(out.disciplines?.Oblivion || out.disciplines?.oblivion || 0);
    const max = ['Hecata', 'Lasombra'].includes(clan) && Number(merit?.dots) === 2 ? 3 : 1;
    const powers = CATALOG.disciplines.Oblivion?.powers || {};
    const picks = [...new Set(inc.mystic_powers.map(String))];
    if (merit && picks.length <= max && picks.every(id => powers[id] && powers[id].level <= oblivion)) {
      out.mystic_powers = picks;
    }
  }

  delete out._needsMysticFix; // view-only flag, never stored
  return out;
}

module.exports = { mergePlayerSheetEdit };
