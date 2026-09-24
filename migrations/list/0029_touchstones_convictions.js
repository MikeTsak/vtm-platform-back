// migrations/list/0029_touchstones_convictions.js
//
// Data-only migration (no schema change).
//
// 1. Touchstones -> the current {name, conviction, background} objects.
//    Older sheets stored plain strings, and some kept two copies that
//    drifted apart (top-level `touchstones` vs `morality.touchstones`, e.g.
//    one empty and the other filled). Both copies are merged (nothing is
//    dropped, duplicates by name removed, top-level order first) and written
//    back to both keys, which is what the sheet view saves. Plain strings
//    follow the same rule as sheetShape.js normalizeTouchstoneArray: split
//    only on ':', strip a leading list bullet, never split on '-'. A string
//    that is literally one of the character's convictions is a copy bug,
//    not a touchstone, and is skipped. Conviction links are left empty:
//    the old lists never recorded which conviction went with which person.
//
// 2. Convictions: the same two-copy merge, written back to both keys.
//
// 3. #29 Issabela Giovanni: owned an Obfuscate power (Cloak of Shadows)
//    with no Obfuscate dot. Storyteller decision: grant Obfuscate 1.
//
// Idempotent: sheets already in shape are left untouched.

function parse(raw) {
  if (!raw) return null;
  if (typeof raw === 'object') return raw;
  try { return JSON.parse(raw); } catch { return null; }
}

const key = (v) => String(v || '').trim().toLowerCase();

function toTouchstone(item) {
  if (!item) return null;
  if (typeof item === 'object') {
    return {
      name: String(item.name || item.title || '').trim(),
      conviction: String(item.conviction || '').trim(),
      background: String(item.background || item.description || '').trim(),
    };
  }
  const str = String(item).trim().replace(/^[-–•]\s*/, '');
  const idx = str.indexOf(':');
  return idx !== -1
    ? { name: str.slice(0, idx).trim(), conviction: '', background: str.slice(idx + 1).trim() }
    : { name: str, conviction: '', background: '' };
}

function normalizeSheet(input) {
  const s = JSON.parse(JSON.stringify(input));
  const morality = s.morality && typeof s.morality === 'object' ? s.morality : {};

  const convictions = [];
  const seenConv = new Set();
  for (const c of [...(Array.isArray(s.convictions) ? s.convictions : []), ...(Array.isArray(morality.convictions) ? morality.convictions : [])]) {
    const text = typeof c === 'string' ? c : (c?.conviction || c?.description || c?.name || '');
    // A bare '-' is an NPC placeholder, not a conviction.
    if (!key(text).replace(/^[-–•]\s*/, '') || seenConv.has(key(text))) continue;
    seenConv.add(key(text));
    convictions.push(text);
  }

  const touchstones = [];
  const seenTs = new Set();
  for (const item of [...(Array.isArray(s.touchstones) ? s.touchstones : []), ...(Array.isArray(morality.touchstones) ? morality.touchstones : [])]) {
    if (typeof item === 'string' && seenConv.has(key(item))) continue;
    const t = toTouchstone(item);
    if (!t || (!t.name && !t.background)) continue;
    const k = key(t.name) || key(t.background);
    if (seenTs.has(k)) continue;
    seenTs.add(k);
    touchstones.push(t);
  }

  const before = JSON.stringify([s.touchstones, morality.touchstones, s.convictions, morality.convictions]);
  s.touchstones = touchstones;
  s.convictions = convictions;
  s.morality = { ...morality, touchstones, convictions };
  const after = JSON.stringify([s.touchstones, s.morality.touchstones, s.convictions, s.morality.convictions]);
  return before === after ? null : s;
}

module.exports = {
  name: '0029_touchstones_convictions',
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

    // #29: guarded so it only fires on the sheet described above.
    const [[c29]] = await pool.query("SELECT sheet FROM characters WHERE id=29 AND name='Issabela Giovanni'");
    const s29 = parse(c29?.sheet);
    if (s29 && !Number(s29.disciplines?.Obfuscate) && (s29.disciplinePowers?.Obfuscate || []).length) {
      s29.disciplines = { ...(s29.disciplines || {}), Obfuscate: 1 };
      await pool.query('UPDATE characters SET sheet=? WHERE id=29', [JSON.stringify(s29)]);
    }
  },
};
