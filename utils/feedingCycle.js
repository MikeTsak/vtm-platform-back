const { getSetting } = require('./settings');

const CYCLE_LENGTH_MS = 21 * 24 * 60 * 60 * 1000; // 3 weeks

function getCycleInfo(anchorInput, nowInput = new Date()) {
  const now = nowInput instanceof Date && !Number.isNaN(nowInput.getTime()) ? nowInput : new Date();
  let anchor = anchorInput instanceof Date ? anchorInput : new Date(anchorInput);
  if (!anchorInput || Number.isNaN(anchor.getTime())) {
    anchor = now;
  }
  const elapsed = Math.max(0, now.getTime() - anchor.getTime());
  const rawIndex = Math.floor(elapsed / CYCLE_LENGTH_MS);
  const cycleIndex = Number.isInteger(rawIndex) && rawIndex >= 0 ? rawIndex : 0;
  const cycleStart = new Date(anchor.getTime() + cycleIndex * CYCLE_LENGTH_MS);
  const cycleEnd = new Date(cycleStart.getTime() + CYCLE_LENGTH_MS);
  return { cycleIndex, cycleStart, cycleEnd };
}

/**
 * Resolves current feeding cycle tied directly to the Downtime Operations schedule.
 * If downtime_cycles_schedule exists, maps directly to the active DT cycle.
 * Falls back to anchor based 21 day calculation if no cycles are configured.
 */
async function resolveCurrentFeedingCycle(nowInput = new Date()) {
  const now = nowInput instanceof Date && !Number.isNaN(nowInput.getTime()) ? nowInput : new Date();
  const todayStr = now.toISOString().split('T')[0];

  try {
    const rawCycles = await getSetting('downtime_cycles_schedule', null);
    const downtimeOpening = await getSetting('downtime_opening', null);

    if (rawCycles) {
      let cycles = [];
      try {
        cycles = typeof rawCycles === 'string' ? JSON.parse(rawCycles) : rawCycles;
      } catch (e) {
        cycles = [];
      }

      if (Array.isArray(cycles) && cycles.length > 0) {
        // 1. Look for cycle explicitly marked active whose closing date has not elapsed
        let activeIdx = cycles.findIndex(c => c.status === 'active' && c.closing_date >= todayStr);

        // 2. If none active by date, find cycle where today falls between opening and closing
        if (activeIdx === -1) {
          activeIdx = cycles.findIndex(c => c.opening_date <= todayStr && c.closing_date >= todayStr);
        }

        // 3. Look for cycle matching current downtime_opening
        if (activeIdx === -1 && downtimeOpening) {
          activeIdx = cycles.findIndex(c => c.opening_date === downtimeOpening);
        }

        // 4. Fall back to any cycle with status 'active'
        if (activeIdx === -1) {
          activeIdx = cycles.findIndex(c => c.status === 'active');
        }

        // 5. If still none, find the latest cycle that has opened
        if (activeIdx === -1) {
          for (let i = cycles.length - 1; i >= 0; i--) {
            if (cycles[i].opening_date <= todayStr) {
              activeIdx = i;
              break;
            }
          }
        }

        // Default to first cycle if before all cycles
        if (activeIdx === -1) activeIdx = 0;

        const cycle = cycles[activeIdx];
        const cycleNum = parseInt(String(cycle.id || '').replace(/\D/g, ''), 10);
        const cycleIndex = !isNaN(cycleNum) && cycleNum > 0 ? cycleNum : activeIdx + 1;

        const cycleStart = new Date(cycle.opening_date + 'T00:00:00');
        const cycleEnd = new Date(cycle.closing_date + 'T23:59:59');

        return {
          cycleIndex,
          cycleStart,
          cycleEnd,
          cycleId: cycle.id,
          cycleTitle: cycle.title,
          isDowntimeLinked: true
        };
      }
    }
  } catch (err) {
    // Fall back to anchor based calculation
  }

  const anchor = await getSetting('feeding_cycle_anchor', new Date().toISOString());
  const fallback = getCycleInfo(anchor, now);
  return { ...fallback, isDowntimeLinked: false };
}

module.exports = { CYCLE_LENGTH_MS, getCycleInfo, resolveCurrentFeedingCycle };


