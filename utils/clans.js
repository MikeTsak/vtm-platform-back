// Canonical clan roster, mirrors front/src/data/clans.js CLAN_NAMES.
// Kept independent (no cross-package import between front/back) but must
// stay in sync if a clan is ever added or renamed.
const CLAN_NAMES = [
  'Banu Haqim', 'Brujah', 'Caitiff', 'Gangrel', 'Hecata', 'Lasombra',
  'Malkavian', 'The Ministry', 'Nosferatu', 'Ravnos', 'Salubri',
  'Thin-blood', 'Toreador', 'Tremere', 'Tzimisce', 'Ventrue'
];

const DEFAULT_DISABLED_CLANS = ['Ravnos', 'Salubri', 'Tzimisce'];

function isValidClanName(name) {
  return CLAN_NAMES.includes(name);
}

module.exports = { CLAN_NAMES, DEFAULT_DISABLED_CLANS, isValidClanName };
