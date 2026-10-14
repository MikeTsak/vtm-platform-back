// utils/bloodPotencyLimits.js
//
// V5 core: a Kindred's generation sets the lowest and highest Blood Potency they can hold.
// Dependency-free so routes, the purchase path and tests share one table. The front has a
// mirror in front/src/utils/bloodPotencyLimits.js (same pattern as xpCost / xpCosts).
//
// Generations 10-11 share a row, as do 12-13 and 14-16 (Thin-bloods, fixed at 0).
const TABLE = {
  4: { min: 5, max: 10 },
  5: { min: 4, max: 9 },
  6: { min: 3, max: 8 },
  7: { min: 3, max: 7 },
  8: { min: 2, max: 6 },
  9: { min: 2, max: 5 },
  10: { min: 1, max: 4 },
  11: { min: 1, max: 4 },
  12: { min: 1, max: 3 },
  13: { min: 1, max: 3 },
  14: { min: 0, max: 0 },
};

/** { min, max } Blood Potency for a generation. No generation on the sheet = no generation limit (0..10). */
function bloodPotencyLimits(generation) {
  const g = Math.floor(Number(generation));
  if (!Number.isFinite(g) || g < 1) return { min: 0, max: 10 };
  if (g <= 4) return TABLE[4];
  if (g >= 14) return TABLE[14];
  return TABLE[g];
}

const ordinal = (n) => `${n}${[, 'st', 'nd', 'rd'][(n % 100 >> 3) ^ 1 && n % 10] || 'th'}`;

/** Player-facing explanation of why a Blood Potency level is out of reach. */
function bloodPotencyLimitMessage(generation, { min, max }) {
  const g = Math.floor(Number(generation));
  return `Blood Potency ${max} is the most a ${ordinal(g)}-generation Kindred can reach (minimum ${min}). `
    + 'It can only go higher if your generation changes.';
}

/** Clamp a Blood Potency value into the generation's range (Storyteller tools). */
function clampBloodPotency(value, generation) {
  const { min, max } = bloodPotencyLimits(generation);
  return Math.max(min, Math.min(max, Number(value) || 0));
}

module.exports = { bloodPotencyLimits, bloodPotencyLimitMessage, clampBloodPotency };
