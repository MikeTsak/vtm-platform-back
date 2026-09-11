// utils/feedingCycle.js
//
// Cycle math shared by routes/feeding.js (the gate check) and jobs/index.js
// (the decay job) — fixed 3-week cycles computed from a stored anchor date,
// fully automatic, no admin action required to advance them. The admin
// toggle (feeding_enabled) only turns the whole feature on/off; it never
// moves the anchor.

const CYCLE_LENGTH_MS = 21 * 24 * 60 * 60 * 1000; // 3 weeks

function getCycleInfo(anchorStr, now = new Date()) {
  const anchor = new Date(anchorStr);
  const elapsed = now.getTime() - anchor.getTime();
  const cycleIndex = Math.floor(elapsed / CYCLE_LENGTH_MS);
  const cycleStart = new Date(anchor.getTime() + cycleIndex * CYCLE_LENGTH_MS);
  const cycleEnd = new Date(cycleStart.getTime() + CYCLE_LENGTH_MS);
  return { cycleIndex, cycleStart, cycleEnd };
}

module.exports = { CYCLE_LENGTH_MS, getCycleInfo };
