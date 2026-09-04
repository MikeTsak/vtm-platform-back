// tests/xpCost.test.js — pure unit tests for the XP cost table. No DB, no
// server; just the extracted utils/xpCost.js function.
const { xpCost } = require('../utils/xpCost');

describe('xpCost', () => {
  it('prices attributes at 5x new level', () => {
    expect(xpCost({ type: 'attribute', newLevel: 3 })).toBe(15);
  });

  it('prices skills at 3x new level', () => {
    expect(xpCost({ type: 'skill', newLevel: 4 })).toBe(12);
  });

  it('prices a specialty as a flat 3', () => {
    expect(xpCost({ type: 'specialty' })).toBe(3);
  });

  it('prices in-clan disciplines at 5x new level', () => {
    expect(xpCost({ type: 'discipline', newLevel: 2, disciplineKind: 'clan' })).toBe(10);
  });

  it('prices caitiff disciplines at 6x new level', () => {
    expect(xpCost({ type: 'discipline', newLevel: 2, disciplineKind: 'caitiff' })).toBe(12);
  });

  it('prices out-of-clan disciplines at 7x new level', () => {
    expect(xpCost({ type: 'discipline', newLevel: 2, disciplineKind: 'other' })).toBe(14);
  });

  it('prices rituals/ceremonies at 3x their level', () => {
    expect(xpCost({ type: 'ritual', ritualLevel: 2 })).toBe(6);
    expect(xpCost({ type: 'ceremony', ritualLevel: 3 })).toBe(9);
  });

  it('prices thin-blood formulae at 3x their level', () => {
    expect(xpCost({ type: 'thin_blood_formula', formulaLevel: 2 })).toBe(6);
  });

  it('prices advantages at 3x dots (defaulting dots to 1)', () => {
    expect(xpCost({ type: 'advantage', dots: 2 })).toBe(6);
    expect(xpCost({ type: 'advantage' })).toBe(3);
  });

  it('flaws are always free (buying them off costs nothing here)', () => {
    expect(xpCost({ type: 'flaw' })).toBe(0);
  });

  it('prices blood potency at 10x new level', () => {
    expect(xpCost({ type: 'blood_potency', newLevel: 1 })).toBe(10);
  });

  it('rejects an unknown type instead of silently returning 0', () => {
    expect(() => xpCost({ type: 'not_a_real_type', newLevel: 1 })).toThrow(/Unknown XP type/);
  });
});
