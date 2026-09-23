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

module.exports = { parseSheet };
