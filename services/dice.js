// services/dice.js
//
// V5 dice, rolled on the server. Every roll in the app (standalone roller,
// live session, Storyteller tools, Rouse Checks) is thrown here and stored in
// the one `dice_rolls` table; clients only ever ask for a roll and display the
// result, so dice faces can't be chosen by the browser.
const { randomInt } = require('crypto');

const rollD10 = () => randomInt(1, 11);

/**
 * V5 outcome for a set of faces. Mirrors computeOutcome in
 * front/src/utils/liveSessionMechanics.js.
 */
function computeOutcome(normal = [], hunger = [], difficulty = 0) {
  const all = [...normal, ...hunger];
  const baseSuccesses = all.filter((d) => d >= 6).length;
  const totalTens = all.filter((d) => d === 10).length;
  const hungerTens = hunger.filter((d) => d === 10).length;
  const critPairs = Math.floor(totalTens / 2);
  const successes = baseSuccesses + critPairs * 2;

  const metDifficulty = Number(difficulty) > 0 ? successes >= Number(difficulty) : successes > 0;
  // A critical / messy critical only exists on a winning roll (V5 core).
  const hasCritical = totalTens >= 2 && metDifficulty;
  const hasMessyCritical = hasCritical && hungerTens > 0;
  const hasBestialFailure = !metDifficulty && hunger.some((d) => d === 1);

  let label = 'Failure';
  if (metDifficulty) label = 'Success';
  if (hasCritical) label = 'Critical';
  if (hasMessyCritical) label = 'Messy Critical';
  if (hasBestialFailure) label = 'Bestial Failure';

  return { successes, critPairs, hasCritical, hasMessyCritical, hasBestialFailure, metDifficulty, label };
}

/** The outcome in the shape the dice_rolls columns use. */
function computeV5Outcome({ normal = [], hunger = [], difficulty = 0 }) {
  const o = computeOutcome(normal, hunger, difficulty);
  return { successes: o.successes, crit_pairs: o.critPairs, messy_crit: o.hasMessyCritical, bestial_failure: o.hasBestialFailure };
}

/** Throws a pool: up to `hunger` of the dice are Hunger dice. */
function rollPool(pool, hunger = 0) {
  const total = Math.max(0, Math.min(30, Math.trunc(Number(pool) || 0)));
  const hungerCount = Math.min(total, Math.max(0, Math.min(5, Math.trunc(Number(hunger) || 0))));
  return {
    normal: Array.from({ length: total - hungerCount }, rollD10),
    hunger: Array.from({ length: hungerCount }, rollD10),
  };
}

module.exports = { rollD10, rollPool, computeOutcome, computeV5Outcome };
