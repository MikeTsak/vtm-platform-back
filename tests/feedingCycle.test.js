// tests/feedingCycle.test.js
// Unit tests for feeding cycle math and resilience against invalid or missing anchor dates.
const { getCycleInfo, CYCLE_LENGTH_MS } = require('../utils/feedingCycle');

describe('feedingCycle', () => {
  it('calculates cycleIndex correctly for a known past anchor', () => {
    const anchor = new Date('2026-01-01T00:00:00.000Z');
    const now = new Date(anchor.getTime() + CYCLE_LENGTH_MS * 2.5); // 2 full cycles elapsed
    const info = getCycleInfo(anchor.toISOString(), now);

    expect(info.cycleIndex).toBe(2);
    expect(info.cycleStart.getTime()).toBe(anchor.getTime() + 2 * CYCLE_LENGTH_MS);
    expect(info.cycleEnd.getTime()).toBe(anchor.getTime() + 3 * CYCLE_LENGTH_MS);
  });

  it('safely handles null, undefined, or empty anchor without returning NaN', () => {
    const testCases = [null, undefined, '', '   '];
    for (const val of testCases) {
      const info = getCycleInfo(val);
      expect(Number.isInteger(info.cycleIndex)).toBe(true);
      expect(info.cycleIndex).toBeGreaterThanOrEqual(0);
      expect(Number.isNaN(info.cycleStart.getTime())).toBe(false);
      expect(Number.isNaN(info.cycleEnd.getTime())).toBe(false);
    }
  });

  it('safely handles completely invalid date strings', () => {
    const testCases = ['invalid-date', 'null', 'undefined', '2026-99-99'];
    for (const val of testCases) {
      const info = getCycleInfo(val);
      expect(Number.isInteger(info.cycleIndex)).toBe(true);
      expect(info.cycleIndex).toBeGreaterThanOrEqual(0);
      expect(Number.isNaN(info.cycleStart.getTime())).toBe(false);
      expect(Number.isNaN(info.cycleEnd.getTime())).toBe(false);
    }
  });

  it('handles future anchor gracefully by defaulting to cycleIndex 0', () => {
    const now = new Date('2026-06-01T00:00:00.000Z');
    const futureAnchor = new Date('2026-07-01T00:00:00.000Z');
    const info = getCycleInfo(futureAnchor.toISOString(), now);

    expect(info.cycleIndex).toBe(0);
    expect(Number.isInteger(info.cycleIndex)).toBe(true);
  });
});
