// services/dice.js
//
// V5 success maths. Pure — given the dice faces, it derives the outcome, so
// both the standalone roller and the live-session roller stay in agreement.

function computeV5Outcome({ normal = [], hunger = [] }) {
  const all = [...normal, ...hunger];
  const baseSuccesses = all.filter((v) => v >= 6).length;

  const tens = all.filter((v) => v === 10).length;
  const crit_pairs = Math.floor(tens / 2);

  const hungerTens = hunger.filter((v) => v === 10).length;
  const messy_crit = crit_pairs > 0 && hungerTens > 0;

  const hungerOnes = hunger.filter((v) => v === 1).length;
  const successes = baseSuccesses + crit_pairs * 2;
  const bestial_failure = successes === 0 && hungerOnes > 0;

  return { successes, crit_pairs, messy_crit, bestial_failure };
}

module.exports = { computeV5Outcome };
