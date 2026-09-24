// data/predatorDisciplines.js
//
// Server-side copy of each predator type's discipline pick (the free dot at
// character creation). Mirrors `picks.discipline` in
// front/src/data/predator_types.js; kept in sync by hand, same as
// predatorHuntingPools.js.
//
// House rule: the predator discipline counts as unlocked for XP purchases
// even when it's out of clan, so no Storyteller grant is needed to raise it.

const PREDATOR_DISCIPLINES = {
  Alleycat: ['Celerity', 'Potence'],
  Bagger: ['Obfuscate'],
  'Blood Leech': ['Celerity', 'Protean'],
  Cleaver: ['Dominate', 'Animalism'],
  Consensualist: ['Auspex', 'Fortitude'],
  Farmer: ['Animalism', 'Protean'],
  Osiris: ['Presence'],
  Sandman: ['Auspex', 'Obfuscate'],
  'Scene Queen': ['Dominate', 'Potence'],
  Siren: ['Fortitude', 'Presence'],
  Extortionist: ['Dominate', 'Potence'],
  Graverobber: ['Fortitude', 'Oblivion'],
  'Roadside Killer': ['Fortitude', 'Protean'],
  'Grim Reaper': ['Auspex', 'Oblivion'],
  Montero: ['Dominate', 'Obfuscate'],
  Pursuer: ['Animalism', 'Auspex'],
  Trapdoor: ['Protean', 'Obfuscate'],
  'Tithe Collector': ['Dominate', 'Presence'],
};

// Clan-specific extras (Bagger/Osiris), same as the frontend functions.
function predatorDisciplineOptions(predatorType, clan) {
  const opts = [...(PREDATOR_DISCIPLINES[predatorType] || [])];
  if ((predatorType === 'Bagger' || predatorType === 'Osiris') && (clan === 'Tremere' || clan === 'Banu Haqim')) opts.unshift('Blood Sorcery');
  if (predatorType === 'Bagger' && clan === 'Hecata') opts.unshift('Oblivion');
  return opts;
}

// True when `discipline` is this character's predator discipline. The pick
// itself isn't stored on the sheet, so "owns at least one dot of a predator
// option" stands in for it.
// ponytail: a two-option predator owning both off-clan options unlocks both; store the pick at creation if that matters.
function isPredatorDiscipline(sheet, clan, discipline) {
  const predatorType = sheet?.predator_type || sheet?.predatorType;
  return predatorDisciplineOptions(predatorType, clan).includes(discipline)
    && Number(sheet?.disciplines?.[discipline] || 0) >= 1;
}

module.exports = { PREDATOR_DISCIPLINES, predatorDisciplineOptions, isPredatorDiscipline };
