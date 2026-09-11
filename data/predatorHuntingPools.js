// data/predatorHuntingPools.js
//
// Server-side copy of each predator type's hunting dice pools, used by the
// Feeding system to resolve a roll. Mirrors the `huntingPools` field of
// front/src/data/predator_types.js (attributes/skills only — the frontend
// file additionally carries flavor text, discipline/merit picks, etc. for
// character creation, which the server doesn't need).
//
// 'Blood Leech' and 'Tithe Collector' are deliberately empty — V5 designates
// both "not abstracted" to a dice pool; the Feeding roll endpoint rejects
// these predator types with a clear message rather than guessing a pool.
//
// If predator_types.js's huntingPools are edited later, this file must be
// updated to match — there is no shared package between front/ and back/
// today, so the two copies are kept in sync by hand.

const PREDATOR_HUNTING_POOLS = {
  Alleycat: [
    { pool: 'Strength + Brawl', attribute: 'Strength', skill: 'Brawl' },
    { pool: 'Wits + Streetwise', attribute: 'Wits', skill: 'Streetwise' },
  ],
  Bagger: [
    { pool: 'Intelligence + Streetwise', attribute: 'Intelligence', skill: 'Streetwise' },
  ],
  'Blood Leech': [],
  Cleaver: [
    { pool: 'Manipulation + Subterfuge', attribute: 'Manipulation', skill: 'Subterfuge' },
  ],
  Consensualist: [
    { pool: 'Manipulation + Persuasion', attribute: 'Manipulation', skill: 'Persuasion' },
  ],
  Farmer: [
    { pool: 'Composure + Animal Ken', attribute: 'Composure', skill: 'Animal Ken' },
  ],
  Osiris: [
    { pool: 'Manipulation + Subterfuge', attribute: 'Manipulation', skill: 'Subterfuge' },
    { pool: 'Manipulation + Intimidation', attribute: 'Manipulation', skill: 'Intimidation' },
  ],
  Sandman: [
    { pool: 'Dexterity + Stealth', attribute: 'Dexterity', skill: 'Stealth' },
  ],
  'Scene Queen': [
    { pool: 'Manipulation + Persuasion', attribute: 'Manipulation', skill: 'Persuasion' },
  ],
  Siren: [
    { pool: 'Charisma + Subterfuge', attribute: 'Charisma', skill: 'Subterfuge' },
  ],
  Extortionist: [
    { pool: 'Strength + Intimidation', attribute: 'Strength', skill: 'Intimidation' },
    { pool: 'Manipulation + Intimidation', attribute: 'Manipulation', skill: 'Intimidation' },
  ],
  Graverobber: [
    { pool: 'Resolve + Medicine', attribute: 'Resolve', skill: 'Medicine' },
    { pool: 'Manipulation + Insight', attribute: 'Manipulation', skill: 'Insight' },
  ],
  'Roadside Killer': [
    { pool: 'Dexterity + Drive', attribute: 'Dexterity', skill: 'Drive' },
    { pool: 'Charisma + Drive', attribute: 'Charisma', skill: 'Drive' },
  ],
  'Grim Reaper': [
    { pool: 'Intelligence + Awareness', attribute: 'Intelligence', skill: 'Awareness' },
    { pool: 'Intelligence + Medicine', attribute: 'Intelligence', skill: 'Medicine' },
  ],
  Montero: [
    { pool: 'Intelligence + Stealth', attribute: 'Intelligence', skill: 'Stealth' },
    { pool: 'Resolve + Stealth', attribute: 'Resolve', skill: 'Stealth' },
  ],
  Pursuer: [
    { pool: 'Intelligence + Investigation', attribute: 'Intelligence', skill: 'Investigation' },
    { pool: 'Stamina + Stealth', attribute: 'Stamina', skill: 'Stealth' },
  ],
  Trapdoor: [
    { pool: 'Charisma + Stealth', attribute: 'Charisma', skill: 'Stealth' },
    { pool: 'Dexterity + Stealth', attribute: 'Dexterity', skill: 'Stealth' },
    { pool: 'Wits + Awareness', attribute: 'Wits', skill: 'Awareness' },
  ],
  'Tithe Collector': [],
};

module.exports = { PREDATOR_HUNTING_POOLS };
