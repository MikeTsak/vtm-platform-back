// data/chasseMerits.js
//
// Server-side copy of the Chasse (feeding-ground) Merit assignments used by
// the Feeding system to compute bonus hunting dice. Mirrors
// front/src/features/domains/data/chasseMerits.js (division -> merit keys,
// merit key -> favoured predator types) — trimmed to just what roll
// resolution needs; the frontend file additionally carries icon/color/full
// rules text for the Domains dossier display, which the server doesn't need.
//
// If Chasse Merit assignments are edited later, this file must be updated to
// match — there is no shared package between front/ and back/ today, so the
// two copies are kept in sync by hand.

const CHASSE_FAVOURS = {
  apartment_towers: ['Extortionist'],
  back_alleys: ['Alleycat', 'Montero'],
  funerary: ['Bagger', 'Graverobber'],
  gated_community: ['Sandman'],
  hospital: ['Bagger', 'Consensualist', 'Grim Reaper', 'Trapdoor'],
  nightlife: ['Montero', 'Pursuer', 'Scene Queen', 'Siren', 'Trapdoor'],
  shelter: ['Alleycat', 'Sandman'],
};

// division number -> [{ merit }] — dots/notes are dossier-display-only and
// omitted here; every listed merit grants its flat +1 bonus die regardless.
const DIVISION_CHASSE = {
  1: ['funerary'],
  2: ['funerary', 'nightlife'],
  3: ['back_alleys', 'shelter'],
  4: ['hospital', 'gated_community'],
  5: ['hospital', 'apartment_towers'],
  6: ['nightlife', 'apartment_towers'],
  8: ['back_alleys', 'nightlife'],
  9: ['nightlife', 'funerary'],
  11: ['nightlife'],
  13: ['nightlife'],
  14: ['nightlife'],
  16: ['nightlife'],
  18: ['nightlife', 'hospital'],
  19: ['apartment_towers', 'nightlife'],
  20: ['apartment_towers'],
  23: ['gated_community'],
  24: ['shelter', 'back_alleys'],
  25: ['apartment_towers'],
  27: ['gated_community', 'hospital'],
  28: ['nightlife'],
  29: ['hospital', 'apartment_towers'],
  33: ['apartment_towers', 'shelter'],
  34: ['shelter', 'back_alleys'],
  35: ['gated_community'],
  36: ['hospital'],
  39: ['shelter', 'back_alleys', 'nightlife', 'apartment_towers', 'funerary'],
  40: ['nightlife', 'back_alleys'],
  43: ['nightlife', 'hospital', 'apartment_towers', 'back_alleys', 'shelter'],
  44: ['hospital'],
  45: ['hospital'],
  46: ['nightlife', 'gated_community'],
  48: ['hospital'],
  83: ['back_alleys', 'shelter'],
  84: ['funerary'],
  85: ['back_alleys', 'shelter'],
  88: ['back_alleys', 'shelter'],
};

// Returns { bonusDice, meritsApplied } for a given division + predator type —
// one bonus die per Chasse Merit present in the domain that favours this
// predator type (the merits' own canonical rules text, not a new mechanic).
function chasseBonus(division, predatorType) {
  const merits = DIVISION_CHASSE[Number(division)] || [];
  const applied = merits.filter((key) => CHASSE_FAVOURS[key]?.includes(predatorType));
  return { bonusDice: applied.length, meritsApplied: applied };
}

module.exports = { CHASSE_FAVOURS, DIVISION_CHASSE, chasseBonus };
