// tests/dither.test.js — thermal pictures are pure black/white dots that keep the shading.
const { atkinson } = require('../utils/dither');

const flat = (value, w = 40, h = 40) => new Uint8Array(w * h).fill(value);
const blackShare = (dots) => dots.filter((v) => v === 0).length / dots.length;

describe('atkinson dithering', () => {
  it('outputs only on/off dots, never grey', () => {
    const ramp = Uint8Array.from({ length: 64 * 16 }, (_, i) => (i % 64) * 4);
    expect([...new Set(atkinson(ramp, 64, 16))].sort()).toEqual([0, 255]);
  });

  it('keeps black black and white white', () => {
    expect(blackShare(atkinson(flat(0), 40, 40))).toBe(1);
    expect(blackShare(atkinson(flat(255), 40, 40))).toBe(0);
  });

  it('turns grey into a matching share of dots', () => {
    expect(blackShare(atkinson(flat(64), 40, 40))).toBeGreaterThan(0.6);
    expect(blackShare(atkinson(flat(192), 40, 40))).toBeLessThan(0.35);
    const mid = blackShare(atkinson(flat(128), 40, 40));
    expect(mid).toBeGreaterThan(0.3);
    expect(mid).toBeLessThan(0.7);
  });
});
