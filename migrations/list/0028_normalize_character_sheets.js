// migrations/list/0028_normalize_character_sheets.js
//
// Data-only migration (no schema change): bring every character/NPC sheet to
// the one structured shape the app writes. Until now the creator stored its
// flat wizard payload (numeric skills, "Skill: spec" strings, predatorType,
// bloodPotency) and a sheet only became structured on its first save from
// the sheet view, so backend readers and the admin editor saw two formats.
// The creator now posts the structured shape (front/.../sheetShape.js); this
// converts the sheets created before that, in place, from live data.
//
// Also syncs the top-level `humanity` copy to `morality.humanity`, which is
// the value every reader already prefers.
//
// Idempotent: a sheet already in shape is left untouched.

const FLAT_ONLY = ['predatorType', 'specialties', 'name', 'clan'];

function parse(raw) {
  if (!raw) return null;
  if (typeof raw === 'object') return raw;
  try { return JSON.parse(raw); } catch { return null; }
}

// Returns the normalized sheet, or null when nothing needs changing.
function normalizeSheet(input) {
  const s = JSON.parse(JSON.stringify(input));
  let changed = false;

  const skillVals = Object.values(s.skills || {});
  const flatSkills = skillVals.some(v => typeof v === 'number');
  if (flatSkills) {
    const skills = {};
    for (const [k, v] of Object.entries(s.skills)) {
      skills[k] = typeof v === 'object' && v
        ? { dots: Number(v.dots) || 0, specialties: Array.isArray(v.specialties) ? v.specialties : [] }
        : { dots: Number(v) || 0, specialties: [] };
    }
    // Same parse as sheetShape.js: "Skill: spec", or an older colon-less
    // "Skill spec" matched by known skill prefix.
    for (const raw of Array.isArray(s.specialties) ? s.specialties : []) {
      const str = String(raw).trim();
      let skill, spec;
      if (str.includes(':')) {
        skill = str.slice(0, str.indexOf(':')).trim();
        spec = str.slice(str.indexOf(':') + 1).trim();
      } else {
        skill = Object.keys(skills).find(k => str.toLowerCase().startsWith(k.toLowerCase() + ' '));
        spec = skill ? str.slice(skill.length).trim() : '';
      }
      if (!skill || !spec) continue;
      if (!skills[skill]) skills[skill] = { dots: 0, specialties: [] };
      if (!skills[skill].specialties.includes(spec)) skills[skill].specialties.push(spec);
    }
    s.skills = skills;
    s.predator_type = s.predator_type || s.predatorType || '';
    if (s.blood_potency == null) s.blood_potency = Number(s.bloodPotency ?? 1);
    for (const k of FLAT_ONLY) delete s[k];
    // Trackers the flat path used to default on load.
    s.health = s.health || { superficial: 0, aggravated: 0 };
    s.willpower = s.willpower || { superficial: 0, aggravated: 0 };
    if (s.hunger == null) s.hunger = 1;
    if (s.stains == null) s.stains = 0;
    if (!Array.isArray(s.resonances)) s.resonances = [];
    if (!Array.isArray(s.mystic_powers)) s.mystic_powers = [];
    changed = true;
  }

  if (s.blood_potency == null && s.bloodPotency != null) {
    s.blood_potency = Number(s.bloodPotency);
    changed = true;
  }

  const moralHum = s.morality?.humanity;
  if (moralHum != null && s.humanity !== moralHum) {
    s.humanity = moralHum;
    changed = true;
  }

  return changed ? s : null;
}

module.exports = {
  name: '0028_normalize_character_sheets',
  normalizeSheet,
  async up(pool) {
    for (const table of ['characters', 'npcs']) {
      const [rows] = await pool.query(`SELECT id, sheet FROM \`${table}\``);
      for (const r of rows) {
        const sheet = parse(r.sheet);
        if (!sheet || typeof sheet !== 'object') continue;
        const next = normalizeSheet(sheet);
        if (next) await pool.query(`UPDATE \`${table}\` SET sheet=? WHERE id=?`, [JSON.stringify(next), r.id]);
      }
    }
  },
};
