// tests/bloodPotencyLimits.test.js — pure unit tests: the generation table, the clamp used by
// Storyteller tools, and the XP purchase refusing a dot past the generation's maximum.
const { bloodPotencyLimits, clampBloodPotency, bloodPotencyLimitMessage } = require('../utils/bloodPotencyLimits');
const { applyPurchase } = require('../utils/xpPurchase');

describe('bloodPotencyLimits', () => {
  it.each([
    [4, 5, 10], [5, 4, 9], [6, 3, 8], [7, 3, 7], [8, 2, 6], [9, 2, 5],
    [10, 1, 4], [11, 1, 4], [12, 1, 3], [13, 1, 3], [14, 0, 0], [16, 0, 0],
  ])('generation %i allows %i to %i', (gen, min, max) => {
    expect(bloodPotencyLimits(gen)).toEqual({ min, max });
  });

  it('treats a missing or garbage generation as unrestricted, and 1st-3rd like 4th', () => {
    expect(bloodPotencyLimits(undefined)).toEqual({ min: 0, max: 10 });
    expect(bloodPotencyLimits('')).toEqual({ min: 0, max: 10 });
    expect(bloodPotencyLimits(3)).toEqual({ min: 5, max: 10 });
  });

  it('clamps both ways', () => {
    expect(clampBloodPotency(7, 10)).toBe(4);
    expect(clampBloodPotency(0, 9)).toBe(2);
    expect(clampBloodPotency(3, 10)).toBe(3);
  });

  it('explains itself in the player-facing message', () => {
    expect(bloodPotencyLimitMessage(10, { min: 1, max: 4 })).toMatch(/Blood Potency 4 .* 10th-generation/);
    expect(bloodPotencyLimitMessage(11, { min: 1, max: 4 })).toMatch(/11th-generation/);
  });
});

describe('XP purchase of Blood Potency', () => {
  const buy = (sheet) => applyPurchase({ sheet, clan: 'Brujah', body: { type: 'blood_potency', target: 'Blood Potency' } });

  it('refuses a dot past the generation maximum', async () => {
    await expect(buy({ generation: 10, blood_potency: 4 })).rejects.toThrow(/Blood Potency 4 is the most a 10th-generation/);
  });

  it('allows a dot below the maximum, and any dot when no generation is set', async () => {
    expect((await buy({ generation: 10, blood_potency: 3 })).to).toBe(4);
    expect((await buy({ blood_potency: 4 })).to).toBe(5);
  });
});
