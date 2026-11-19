// utils/sheet.js
//
// Character/NPC/retainer `sheet` columns are stored as JSON text. Reading one
// safely (string or already-parsed, malformed or missing) was reimplemented
// ad hoc across ~14 route files; this is the one definition, promoted from
// routes/feeding.js's local helper (the most defensive of the copies).

function parseSheet(raw) {
  if (!raw) return {};
  if (typeof raw === 'string') {
    try { return JSON.parse(raw) || {}; } catch { return {}; }
  }
  return raw;
}

function matchesPremonitionEntry(entry) {
  if (!entry) return false;
  if (typeof entry === 'string') return entry.trim().toLowerCase() === 'premonition';
  if (typeof entry === 'object') {
    return String(entry.id || '').trim().toLowerCase() === 'premonition'
      || String(entry.name || '').trim().toLowerCase() === 'premonition';
  }
  return false;
}

function hasPremonitionPower(rawSheet) {
  const sheet = parseSheet(rawSheet);
  const dp = sheet.disciplinePowers;
  if (dp && typeof dp === 'object') {
    for (const [disc, list] of Object.entries(dp)) {
      if (disc.trim().toLowerCase() === 'auspex' && Array.isArray(list)) {
        if (list.some(matchesPremonitionEntry)) return true;
      }
    }
  }
  if (Array.isArray(sheet.ingrained_flaws)) {
    for (const flaw of sheet.ingrained_flaws) {
      if (Array.isArray(flaw?.bonus_powers) && flaw.bonus_powers.some(matchesPremonitionEntry)) {
        return true;
      }
    }
  }
  return false;
}

module.exports = { parseSheet, hasPremonitionPower };
