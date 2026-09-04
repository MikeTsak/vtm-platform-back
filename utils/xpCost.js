// utils/xpCost.js
//
// Pure XP-cost calculator, shared by the self-serve and admin XP-spend
// routes. Kept dependency-free (no db/log/req) so it's trivially unit-testable
// and safe to import from anywhere.
function xpCost({ type, newLevel, ritualLevel, formulaLevel, dots = 1, disciplineKind }) {
  if (type === 'attribute') return Number(newLevel) * 5;
  if (type === 'skill') return Number(newLevel) * 3;
  if (type === 'specialty') return 3;
  if (type === 'discipline') {
    if (disciplineKind === 'clan') return Number(newLevel) * 5;
    if (disciplineKind === 'caitiff') return Number(newLevel) * 6;
    return Number(newLevel) * 7;
  }
  if (type === 'ritual' || type === 'ceremony') {
    const lvl = Number(ritualLevel ?? newLevel ?? 1);
    return lvl * 3;
  }
  if (type === 'thin_blood_formula') {
    const lvl = Number(formulaLevel ?? newLevel ?? 1);
    return lvl * 3;
  }
  if (type === 'advantage') return 3 * Number(dots || 1);
  if (type === 'flaw') return 0;
  if (type === 'blood_potency') return Number(newLevel) * 10;
  throw new Error('Unknown XP type: ' + type);
}

module.exports = { xpCost };
