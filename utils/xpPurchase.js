// utils/xpPurchase.js
//
// Server-authoritative XP purchases. The client says WHAT it wants to buy
// (type + target, plus the chosen power / specialty / merit entry); the server
// reads the current state from the STORED sheet, works out the next level and
// the price itself, and writes exactly that one change. Everything else in a
// client-sent `patchSheet` is ignored, so a crafted request can't rewrite the
// rest of the sheet, buy several dots for the price of one, or claim an
// out-of-clan discipline is in-clan.
//
// Shared by the player route (routes/characterXp.js), the Storyteller route
// (routes/xp.js) and the NPC route (routes/npcs.js). Storytellers keep
// unrestricted editing through the admin sheet editor; this path only skips
// the discipline-unlock gate for them.
const CATALOG = require('../data/rulesCatalog.json');
const { xpCost } = require('./xpCost');
const { parseSheet } = require('./sheet');
const { isPredatorDiscipline } = require('../data/predatorDisciplines');

class PurchaseError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const fail = (status, message) => { throw new PurchaseError(status, message); };

const ATTRIBUTES = ['Strength', 'Dexterity', 'Stamina', 'Charisma', 'Manipulation', 'Composure', 'Intelligence', 'Wits', 'Resolve'];
const SKILLS = [
  'Athletics', 'Brawl', 'Craft', 'Drive', 'Firearms', 'Larceny', 'Melee', 'Stealth', 'Survival',
  'Animal Ken', 'Etiquette', 'Insight', 'Intimidation', 'Leadership', 'Performance', 'Persuasion', 'Streetwise', 'Subterfuge',
  'Academics', 'Awareness', 'Finance', 'Investigation', 'Medicine', 'Occult', 'Politics', 'Science', 'Technology',
];
const MAX_BLOOD_POTENCY = 10;
// Backgrounds that can be held more than once as separate entries (two
// different Contacts, a second Allies group). Mirrors the "Add as another
// instance" option in MeritsBackgroundsSection.jsx; any other merit is one entry.
const REPEATABLE_MERITS = ['Allies', 'Contacts', 'Resources', 'Retainers', 'Influence', 'Status'];
const RITUAL_KINDS = { ritual: ['blood_sorcery', 'Blood Sorcery'], ceremony: ['oblivion', 'Oblivion'] };

const num = (v) => Number(v) || 0;
const keyOf = (p) => String((p && typeof p === 'object') ? (p.id || p.name || '') : (p || '')).toLowerCase();
const skillDots = (node) => (node && typeof node === 'object' ? num(node.dots) : num(node));

/** Allowed dot ratings for a catalog merit/flaw, from its display string ('•', '• - •••', '•• or ••••', '• +'). */
function allowedDots(dotsText) {
  const text = String(dotsText || '');
  const count = (s) => (s.match(/•/g) || []).length;
  if (/thin-blood/i.test(text)) return [1, 2, 3, 4, 5];
  if (text.includes('+')) { const lo = count(text) || 1; return Array.from({ length: 6 - lo }, (_, i) => lo + i); }
  if (text.includes('-')) {
    const [a, b] = text.split('-').map(count);
    return Array.from({ length: Math.max(0, b - a + 1) }, (_, i) => a + i);
  }
  return text.split(/\bor\b/).map(count).filter(Boolean);
}

/** Find a power in the catalog by id or name. */
function findPower(discipline, idOrName) {
  const powers = CATALOG.disciplines[discipline]?.powers || {};
  const k = String(idOrName || '').toLowerCase();
  if (!k) return null;
  for (const [id, p] of Object.entries(powers)) {
    if (id.toLowerCase() === k || String(p.name).toLowerCase() === k) return { id, ...p };
  }
  return null;
}

/** "Protean •", "Auspex ••" → unmet requirements against the given dots. Mirrors the picker's parseAmalgam. */
function unmetAmalgam(amalgam, dots) {
  if (!amalgam) return [];
  return String(amalgam).split(/(?:,|&|\+|and)/i).map(s => s.trim()).filter(Boolean).filter(part => {
    const disc = (part.match(/^[^\d•●○]+/) || [part])[0].trim().replace(/[:.-]+$/, '');
    const need = Math.max((part.match(/[•●○]/g) || []).length, parseInt((part.match(/\b(\d+)\b/) || [])[1], 10) || 1);
    const haveKey = Object.keys(dots).find(d => d.toLowerCase() === disc.toLowerCase());
    return num(haveKey ? dots[haveKey] : 0) < need;
  });
}

/** Owned powers, de-duplicated by identity and given their real tier (older saves stored the slot level). */
function cleanPowers(discipline, list) {
  const seen = new Set();
  const out = [];
  for (const raw of Array.isArray(list) ? list : []) {
    const k = keyOf(raw);
    if (!k || seen.has(k)) continue;
    seen.add(k);
    const p = typeof raw === 'object' ? { ...raw } : { id: raw, name: raw };
    const known = findPower(discipline, p.id || p.name);
    out.push(known ? { ...p, id: known.id, name: p.name || known.name, level: known.level } : p);
  }
  return out;
}

function disciplineKind(clan, discipline) {
  if (clan === 'Caitiff') return 'caitiff';
  return (CATALOG.disciplines[discipline]?.clanAffinity || []).includes(clan) ? 'clan' : 'other';
}

/** Rejects a purchase the client priced against a different sheet than the one stored (stale tab, double submit). */
function expectLevel(body, actual, what) {
  if (body.newLevel != null && body.newLevel !== '' && Number(body.newLevel) !== actual) {
    fail(409, `Your sheet is out of date (${what} is now ${actual - 1}). Reload and try again.`);
  }
}

/**
 * Applies one purchase to a stored sheet.
 * @param {object} args
 * @param {object} args.sheet    the stored sheet (parsed)
 * @param {string} args.clan     the stored clan
 * @param {object} args.body     { type, target, newLevel?, disciplineKind?, powerId?, powerName?, specialty?, dots?, patchSheet? }
 * @param {boolean} args.isAdmin Storyteller acting: skips the out-of-clan unlock gate
 * @param {(discipline:string)=>Promise<number|null>} [args.unlockedTo] ST-granted cap for an out-of-clan discipline
 * @returns {Promise<{sheet:object, cost:number, from:number|null, to:number|null}>}
 */
async function applyPurchase({ sheet: storedSheet, clan, body, isAdmin = false, unlockedTo = async () => null }) {
  const sheet = JSON.parse(JSON.stringify(parseSheet(storedSheet) || {}));
  const { type, target } = body || {};
  const patch = (body?.patchSheet && typeof body.patchSheet === 'object') ? body.patchSheet : {};

  switch (type) {
    case 'attribute': {
      if (!ATTRIBUTES.includes(target)) fail(400, `Unknown attribute: ${target}`);
      const from = num(sheet.attributes?.[target] ?? 1);
      const to = from + 1;
      if (to > 5) fail(400, `${target} is already at 5.`);
      expectLevel(body, to, target);
      sheet.attributes = { ...(sheet.attributes || {}), [target]: to };
      return { sheet, cost: xpCost({ type, newLevel: to }), from, to };
    }

    case 'skill': {
      if (!SKILLS.includes(target)) fail(400, `Unknown skill: ${target}`);
      const node = sheet.skills?.[target];
      const from = skillDots(node);
      const to = from + 1;
      if (to > 5) fail(400, `${target} is already at 5.`);
      expectLevel(body, to, target);
      const specialties = node && typeof node === 'object' && Array.isArray(node.specialties) ? node.specialties : [];
      sheet.skills = { ...(sheet.skills || {}), [target]: { ...(typeof node === 'object' ? node : {}), dots: to, specialties } };
      return { sheet, cost: xpCost({ type, newLevel: to }), from, to };
    }

    case 'specialty': {
      if (!SKILLS.includes(target)) fail(400, `Unknown skill: ${target}`);
      const spec = String(body.specialty ?? '').trim();
      if (!spec || spec.length > 60) fail(400, 'A specialty needs a name of up to 60 characters.');
      const node = sheet.skills?.[target];
      const dots = skillDots(node);
      if (dots < 1) fail(400, `You need at least one dot in ${target} to take a specialty.`);
      const specialties = node && typeof node === 'object' && Array.isArray(node.specialties) ? node.specialties : [];
      if (specialties.some(s => String(s).toLowerCase() === spec.toLowerCase())) fail(400, `You already have ${spec}.`);
      sheet.skills = { ...(sheet.skills || {}), [target]: { ...(typeof node === 'object' ? node : {}), dots, specialties: [...specialties, spec] } };
      return { sheet, cost: xpCost({ type }), from: null, to: null };
    }

    case 'blood_potency': {
      if (clan === 'Thin-blood') fail(400, 'Thin-blood Blood Potency cannot be raised with XP.');
      const from = num(sheet.blood_potency ?? 1);
      const to = from + 1;
      if (to > MAX_BLOOD_POTENCY) fail(400, `Blood Potency is already at ${MAX_BLOOD_POTENCY}.`);
      expectLevel(body, to, 'Blood Potency');
      sheet.blood_potency = to;
      return { sheet, cost: xpCost({ type, newLevel: to }), from, to };
    }

    case 'discipline': {
      if (!CATALOG.disciplines[target]) fail(400, `Unknown discipline: ${target}`);
      sheet.disciplines = { ...(sheet.disciplines || {}) };
      sheet.disciplinePowers = { ...(sheet.disciplinePowers || {}) };
      const owned = cleanPowers(target, sheet.disciplinePowers[target]);
      const from = num(sheet.disciplines[target]);
      const free = body.disciplineKind === 'select';
      const to = free ? from : from + 1;
      let kind = null;

      if (free) {
        // Assigning the power for a dot already paid for.
        if (owned.length >= from) fail(400, `Every ${target} dot already has a power.`);
      } else {
        expectLevel(body, to, target);
        kind = disciplineKind(clan, target);
        const otherAtSix = Object.entries(sheet.disciplines).some(([d, v]) => d !== target && num(v) > 5);
        if (to > 6 || (to === 6 && (kind !== 'clan' || otherAtSix))) {
          fail(400, to === 6 && kind === 'clan' && otherAtSix
            ? 'Only one discipline can be raised to 6 dots.'
            : `${target} can only exceed 5 dots as your one in-clan discipline at 6.`);
        }
        // Out-of-clan dots need a Storyteller unlock, except the predator-type discipline.
        if (kind === 'other' && !isAdmin && !isPredatorDiscipline(sheet, clan, target)) {
          const cap = await unlockedTo(target);
          if (cap == null) fail(403, `${target} isn't unlocked for your character. Ask your Storyteller, or send a request from the Disciplines tab.`);
          if (num(cap) < to) fail(403, `Your Storyteller has only unlocked ${target} up to level ${cap}.`);
        }
        sheet.disciplines[target] = to;
      }

      // Every dot comes with one power (the 6th dot buys an extra power from levels 1-5).
      const power = findPower(target, body.powerId || body.powerName);
      if (!power) fail(400, `Pick a ${target} power to go with this dot.`);
      if (owned.some(p => keyOf(p) === power.id.toLowerCase() || keyOf({ name: p.name }) === String(power.name).toLowerCase())) {
        fail(400, `You already have ${power.name}.`);
      }
      if (power.level > Math.min(to, 5)) fail(400, `${power.name} needs ${target} ${power.level}.`);
      if (power.clan && power.clan !== clan) fail(400, `${power.name} is restricted to ${power.clan}.`);
      const unmet = unmetAmalgam(power.amalgam, sheet.disciplines);
      if (unmet.length) fail(400, `${power.name} needs ${unmet.join(', ')}.`);

      sheet.disciplinePowers[target] = [...owned, { level: power.level, id: power.id, name: power.name }]
        .sort((a, b) => num(a.level) - num(b.level));
      const cost = free ? 0 : xpCost({ type, newLevel: to, disciplineKind: kind });
      return { sheet, cost, from, to };
    }

    case 'ritual':
    case 'ceremony': {
      const [path, discipline] = RITUAL_KINDS[type];
      const ritual = CATALOG.rituals[path][target];
      if (!ritual) fail(400, `Unknown ${type}: ${target}`);
      if (ritual.level > num(sheet.disciplines?.[discipline])) fail(400, `${ritual.name} needs ${discipline} ${ritual.level}.`);
      sheet.rituals = { blood_sorcery: [], oblivion: [], ...(sheet.rituals || {}) };
      const known = Array.isArray(sheet.rituals[path]) ? sheet.rituals[path] : [];
      if (known.some(r => keyOf(r) === target.toLowerCase())) fail(400, `You already know ${ritual.name}.`);
      sheet.rituals[path] = [...known, { id: target, name: ritual.name, level: ritual.level }];
      return { sheet, cost: xpCost({ type, ritualLevel: ritual.level }), from: null, to: ritual.level };
    }

    case 'advantage':
    case 'flaw': {
      const isFlaw = type === 'flaw';
      const item = CATALOG.advantages[target];
      if (!item || item.type !== (isFlaw ? 'Flaw' : 'Merit')) fail(400, `Unknown ${isFlaw ? 'flaw' : 'merit'}: ${target}`);
      if (/thin-blood/i.test(item.dots) && clan !== 'Thin-blood') fail(400, 'That is a Thin-blood only advantage.');
      const allowed = allowedDots(item.dots);

      // Only this one advantage's entries may change. They are taken from the
      // patch (the client chose instance / notes); every other entry comes
      // from the stored sheet.
      const lists = isFlaw ? [['advantages', 'flaws']] : [['advantages', 'merits'], [null, 'backgrounds']];
      const read = (s, [parent, key]) => {
        const holder = parent ? s?.[parent] : s;
        return Array.isArray(holder?.[key]) ? holder[key] : [];
      };
      let added = 0;
      let delta = 0;
      const alreadyHeld = lists.some(loc => read(sheet, loc).some(e => e?.id === target));
      const merged = lists.map((loc) => {
        const stored = read(sheet, loc);
        const storedT = stored.filter(e => e?.id === target);
        const patchT = read(patch, loc).filter(e => e?.id === target);
        if (patchT.length < storedT.length || patchT.length > storedT.length + 1) {
          fail(400, `Only one ${item.type.toLowerCase()} entry can be added at a time.`);
        }
        patchT.forEach((e, i) => {
          const was = i < storedT.length ? num(storedT[i].dots) : 0;
          const now = num(e?.dots);
          if (now < was) fail(400, 'Buying a merit cannot lower an existing rating.');
          if (now !== was && !allowed.includes(now)) fail(400, `That ${item.type.toLowerCase()} can't be rated ${now}.`);
          if (i >= storedT.length) added += 1;
          delta += now - was;
        });
        // Keep the stored order: non-target entries untouched, target entries replaced in place, new one appended.
        let t = 0;
        const out = stored.map(e => (e?.id === target ? sanitizeEntry(patchT[t++], target) : e));
        while (t < patchT.length) out.push(sanitizeEntry(patchT[t++], target));
        return [loc, out];
      });
      if (added > 1) fail(400, `Only one ${item.type.toLowerCase()} entry can be added at a time.`);
      if (!isFlaw && added && alreadyHeld && !REPEATABLE_MERITS.includes(item.name)) {
        fail(400, `You already have ${item.name}; raise its rating instead of adding a second one.`);
      }

      if (isFlaw) {
        if (added !== 1) fail(400, 'Pick the flaw to add.');
      } else if (delta <= 0) {
        fail(400, 'Nothing to buy: the merit rating did not go up.');
      }
      if (!isFlaw && body.dots != null && num(body.dots) !== delta) {
        fail(409, 'Your sheet is out of date. Reload and try again.');
      }

      for (const [[parent, key], list] of merged) {
        if (parent) sheet[parent] = { ...(sheet[parent] || {}), [key]: list };
        else sheet[key] = list;
      }
      return { sheet, cost: isFlaw ? 0 : xpCost({ type: 'advantage', dots: delta }), from: null, to: null };
    }

    default:
      return fail(400, `${type || 'That'} can't be bought with XP here. Ask your Storyteller.`);
  }
}

/** A merit/flaw entry from the client: fixed id, numeric dots, short free-text fields only. */
function sanitizeEntry(e, id) {
  const text = (v, max) => (typeof v === 'string' ? v.slice(0, max) : undefined);
  const out = { id, name: text(e?.name, 120), dots: num(e?.dots) };
  if (e?.from !== undefined) out.from = text(e.from, 40);
  if (e?.instance !== undefined) out.instance = num(e.instance);
  if (e?.notes !== undefined) out.notes = text(e.notes, 5000);
  if (e?.desc !== undefined) out.desc = text(e.desc, 5000);
  return out;
}

/**
 * Runs a purchase for one row of `table` inside a transaction. The row is
 * locked (SELECT ... FOR UPDATE) so two purchases racing each other can't both
 * pass the balance check or overwrite each other's sheet.
 * @returns {Promise<{row:object, cost:number}>}
 */
async function runPurchase({ pool, table, id, body, isAdmin, unlockedTo, logXp = true }) {
  if (!['characters', 'npcs'].includes(table)) throw new Error('bad table');
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[row]] = await conn.query(`SELECT * FROM ${table} WHERE id=? FOR UPDATE`, [id]);
    if (!row) fail(404, 'Character not found');

    const result = await applyPurchase({ sheet: row.sheet, clan: row.clan, body, isAdmin, unlockedTo });
    if (num(row.xp) < result.cost) fail(400, `Not enough XP (need ${result.cost}, have ${num(row.xp)})`);

    await conn.query(`UPDATE ${table} SET xp = xp - ?, sheet = ? WHERE id=?`, [result.cost, JSON.stringify(result.sheet), id]);
    if (logXp && table === 'characters') {
      await conn.query(
        'INSERT INTO xp_log (character_id, action, target, from_level, to_level, cost, payload) VALUES (?,?,?,?,?,?,?)',
        [id, body.type, body.target || null, result.from, result.to, result.cost,
          JSON.stringify({ disciplineKind: body.disciplineKind, powerId: body.powerId, specialty: body.specialty, by_admin: !!isAdmin })]
      );
    }
    await conn.commit();

    const [[out]] = await pool.query(`SELECT * FROM ${table} WHERE id=?`, [id]);
    if (out) out.sheet = parseSheet(out.sheet);
    return { row: out, cost: result.cost };
  } catch (e) {
    await conn.rollback().catch(() => {});
    throw e;
  } finally {
    conn.release();
  }
}

module.exports = { applyPurchase, runPurchase, PurchaseError, allowedDots, ATTRIBUTES, SKILLS, CATALOG };
