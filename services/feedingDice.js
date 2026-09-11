// services/feedingDice.js
//
// V5 success math for the Feeding system, resolved server-side (the client is
// not trusted to roll its own dice for a Masquerade-affecting outcome — see
// routes/mechanics.js's header comment for the same principle applied to
// rouse checks and willpower spends). Mirrors the tier logic in
// front/src/utils/liveSessionMechanics.js's computeOutcome exactly, but adds
// the fifth named tier ('critical' vs plain 'success') that
// services/dice.js's computeV5Outcome doesn't distinguish, since the Feeding
// outcome table treats them differently.

const rollD10 = () => Math.floor(Math.random() * 10) + 1;

function rollDice(count) {
  return Array.from({ length: Math.max(0, count) }, () => rollD10());
}

// tier: 'bestial_failure' | 'failure' | 'success' | 'critical' | 'messy_critical'
function computeFeedingOutcome(normalDice, hungerDice, difficulty) {
  const normal = Array.isArray(normalDice) ? normalDice : [];
  const hunger = Array.isArray(hungerDice) ? hungerDice : [];
  const all = [...normal, ...hunger];

  const baseSuccesses = all.filter((d) => d >= 6).length;
  const totalTens = all.filter((d) => d === 10).length;
  const hungerTens = hunger.filter((d) => d === 10).length;
  const critPairs = Math.floor(totalTens / 2);
  const successes = baseSuccesses + critPairs * 2;

  const diff = Number(difficulty) || 0;
  const metDifficulty = diff > 0 ? successes >= diff : successes > 0;
  const hasCritical = totalTens >= 2 && metDifficulty;
  const hasMessyCritical = hasCritical && hungerTens > 0;
  const hasBestialFailure = !metDifficulty && hunger.some((d) => d === 1);

  let tier = 'failure';
  if (metDifficulty) tier = 'success';
  if (hasCritical) tier = 'critical';
  if (hasMessyCritical) tier = 'messy_critical';
  if (hasBestialFailure) tier = 'bestial_failure';

  return { successes, metDifficulty, hasCritical, hasMessyCritical, hasBestialFailure, tier };
}

// Locked outcome table (see the approved Feeding plan) — Hunger/Safety deltas
// applied on confirm. Safety delta is added to domain_claims.safety_rating
// (0-10, higher = safer), so a "worse" outcome is a more negative number.
const OUTCOME_DELTAS = {
  bestial_failure: { hunger: 1, safety: -2 },
  failure: { hunger: 0, safety: -1 },
  success: { hunger: -1, safety: 0 },
  critical: { hunger: -2, safety: 0 },
  messy_critical: { hunger: -2, safety: -2 },
};

module.exports = { rollD10, rollDice, computeFeedingOutcome, OUTCOME_DELTAS };
