// data/huntingDifficulty.js
//
// Server-side copy of the per-division Hunting Difficulty used by the Feeding
// system to resolve a roll's difficulty. Mirrors
// front/src/features/domains/data/huntingDifficulty.js (division -> difficulty
// only; the frontend file additionally carries density/area/population for its
// own dossier display, which the server doesn't need).
//
// If the frontend's Hunting Difficulty is ever regenerated (its builder
// script, _buildHuntingDifficulty.mjs), this file must be updated to match —
// there is no shared package between front/ and back/ today, so the two
// copies are kept in sync by hand.

const HUNTING_DIFFICULTY = {
  1: 5, 2: 3, 3: 3, 4: 3, 5: 4, 6: 5, 7: 5, 8: 7, 9: 4, 10: 5,
  11: 4, 12: 2, 13: 4, 14: 5, 15: 3, 16: 5, 17: 3, 18: 4, 19: 4, 20: 3,
  21: 3, 22: 2, 23: 2, 24: 4, 25: 6, 26: 4, 27: 3, 28: 2, 29: 2, 30: 3,
  31: 2, 32: 3, 33: 5, 34: 4, 35: 3, 36: 3, 37: 2, 38: 4, 39: 7, 40: 7,
  41: 6, 42: 6, 43: 7, 44: 3, 45: 4, 46: 2, 47: 6, 48: 3, 49: 5, 50: 6,
  51: 6, 52: 6, 53: 6, 54: 6, 55: 5, 56: 4, 57: 2, 58: 6, 59: 6, 60: 5,
  61: 4, 62: 4, 63: 6, 64: 4, 65: 4, 66: 5, 67: 4, 68: 6, 69: 5, 70: 6,
  71: 6, 72: 6, 73: 6, 74: 6, 75: 6, 76: 6, 77: 6, 78: 6, 79: 6, 80: 6,
  81: 6, 82: 6, 83: 6, 84: 6, 85: 4, 86: 6, 87: 6, 88: 6,
};

function huntingDifficulty(division) {
  return HUNTING_DIFFICULTY[Number(division)] ?? null;
}

module.exports = { HUNTING_DIFFICULTY, huntingDifficulty };
