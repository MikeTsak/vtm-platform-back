// services/rolls.js
//
// Builds dice pools from the STORED character sheet and records every roll in
// `dice_rolls`, the one table for all dice (standalone roller, live session,
// Storyteller tools, Rouse Checks). The live-session feed reads from it too
// (rows with a session_id). Mirrors the pool rules the live-session screen
// shows (front/src/features/live-session/LiveSession.jsx); the screen's
// number is a preview, this is the roll.
const { CATALOG, ATTRIBUTES, SKILLS } = require('../utils/xpPurchase');
const { computeV5Outcome } = require('./dice');

const PHYSICAL = new Set(['Strength', 'Dexterity', 'Stamina', 'Athletics', 'Brawl', 'Craft', 'Drive', 'Firearms', 'Larceny', 'Melee', 'Stealth', 'Survival']);
const MENTAL_SOCIAL = new Set([...ATTRIBUTES, ...SKILLS].filter(t => !PHYSICAL.has(t)));

// V5 Blood Potency table (mirrors getBloodPotencyStats in the front end).
const BP = {
  surge: [1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6],
  disciplineBonus: [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5],
  bane: [1, 2, 2, 3, 3, 4, 4, 4, 5, 6, 6],
};

// Roll kinds V5 forbids a Willpower reroll on.
const NO_REROLL = new Set(['frenzy_resistance', 'remorse', 'rouse_check', 'discipline_rouse_check', 'blush_of_life', 'blood_surge', 'mend_rouse', 'willpower_reroll']);

const num = (v) => Number(v) || 0;
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, num(v)));

const isDiscipline = (t) => !!CATALOG.disciplines[t] || /alchemy/i.test(String(t));
const isTrait = (t) => ATTRIBUTES.includes(t) || SKILLS.includes(t) || isDiscipline(t);

function traitValue(sheet, t) {
  if (sheet?.attributes?.[t] !== undefined) return num(sheet.attributes[t]);
  const skill = sheet?.skills?.[t];
  if (skill !== undefined) return typeof skill === 'object' ? num(skill?.dots) : num(skill);
  return num(sheet?.disciplines?.[t]);
}

function bloodPotency(sheet, clan) {
  return clamp(sheet?.blood_potency ?? sheet?.bloodPotency ?? (clan === 'Thin-blood' ? 0 : 1), 0, 10);
}

/** Impairment and the other tracker facts a pool depends on (mirrors summarizeTrackers). */
function trackers(sheet) {
  const fortitude = num(sheet?.disciplines?.Fortitude);
  const resilience = (sheet?.disciplinePowers?.Fortitude || []).some(p => /resilien/i.test(String(p?.id ?? p?.name ?? p)));
  const maxHealth = Math.max(1, (num(sheet?.attributes?.Stamina) || 1) + 3 + (resilience ? fortitude : 0));
  const maxWillpower = Math.max(1, (num(sheet?.attributes?.Composure) || 1) + (num(sheet?.attributes?.Resolve) || 1));
  const humanity = clamp(sheet?.humanity ?? sheet?.morality?.humanity ?? 7, 0, 10);
  const stains = clamp(sheet?.stains ?? 0, 0, 10);
  return {
    hunger: clamp(sheet?.hunger ?? 1, 0, 5),
    maxWillpower,
    humanity,
    healthImpaired: num(sheet?.health?.superficial) + num(sheet?.health?.aggravated) >= maxHealth,
    willpowerImpaired: num(sheet?.willpower?.superficial) + num(sheet?.willpower?.aggravated) >= maxWillpower,
    willpowerLeft: maxWillpower - num(sheet?.willpower?.superficial) - num(sheet?.willpower?.aggravated),
    degeneration: stains > 10 - humanity,
  };
}

/** "Charisma + Dominate", "Wits / Resolve + Auspex" → [t1, t2] (mirrors parseDicePool). */
function parsePowerPool(text) {
  const s = String(text || '').trim();
  if (!s || /^(—|none|as power)/i.test(s)) return null;
  const parts = s.split('+').map(x => x.trim());
  if (parts.length < 2) return null;
  const norm = (t) => t.split('/')[0].replace(/\(.*$/, '').trim();
  const [t1, t2] = [norm(parts[0]), norm(parts[1])];
  const ok1 = ATTRIBUTES.includes(t1) || SKILLS.includes(t1);
  const ok2 = ATTRIBUTES.includes(t2) || SKILLS.includes(t2) || isDiscipline(t2);
  return ok1 && ok2 ? [t1, t2] : null;
}

/** "@Presence", "@Celerity/2" or a number (mirrors resolveMechAmount). */
function mechAmount(token, sheet) {
  if (typeof token === 'number') return token;
  const m = String(token || '').match(/^@([A-Za-z][A-Za-z '-]*?)\s*(\/2)?$/);
  if (!m) return 0;
  const name = m[1].trim();
  const rating = num(sheet?.disciplines?.[name] ?? sheet?.attributes?.[name] ?? (name === 'Alchemy' ? sheet?.disciplines?.['Thin-blood Alchemy'] : 0));
  return m[2] ? Math.ceil(rating / 2) : rating;
}

function ownsPower(sheet, powerId) {
  const target = String(powerId || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!target) return false;
  return Object.values(sheet?.disciplinePowers || {}).some(list =>
    (Array.isArray(list) ? list : []).some(p => {
      const pid = String(p?.id || '').toLowerCase().replace(/[^a-z0-9]/g, '');
      const pname = String(p?.name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
      const pstr = (typeof p === 'string' ? p : '').toLowerCase().replace(/[^a-z0-9]/g, '');
      return pid === target || pname === target || pstr === target;
    }));
}

function findPowerAnywhere(powerId) {
  const norm = String(powerId || '').toLowerCase().replace(/[^a-z0-9]/g, '_');
  const target = norm.replace(/[^a-z0-9]/g, '');
  for (const [discipline, d] of Object.entries(CATALOG.disciplines)) {
    if (d.powers[powerId]) return { discipline, ...d.powers[powerId] };
    if (d.powers[norm]) return { discipline, ...d.powers[norm] };
    for (const [pid, p] of Object.entries(d.powers)) {
      if (pid.toLowerCase().replace(/[^a-z0-9]/g, '') === target) {
        return { discipline, ...p };
      }
    }
  }
  return null;
}

/**
 * The dice pool for two traits plus the extras the player asked for, each one
 * checked against the stored sheet / session. Returns { pool, parts } where
 * parts is the human-readable breakdown that goes into the roll's note.
 */
function traitPool({ sheet, clan, traits, specialty, ownSpecialtyOnly = true, effects = [], effectIds = [], powerIds = [], situational, ignoreImpairment, surge }) {
  if (!traits || !traits.length || traits.some(t => !isTrait(t))) throw Object.assign(new Error('Unknown trait'), { status: 400 });
  const parts = [traits.join(' + ')];
  let pool = traits.reduce((sum, t) => sum + traitValue(sheet, t), 0);
  const bp = bloodPotency(sheet, clan);
  const tr = trackers(sheet);
  const frenzied = !!sheet?.frenzyState;

  if (traits.some(isDiscipline) && BP.disciplineBonus[bp]) {
    pool += BP.disciplineBonus[bp];
    parts.push(`BP Disc +${BP.disciplineBonus[bp]}`);
  }
  if (specialty) {
    // A Storyteller-granted specialty is taken as given; a player's own must exist on one of the skills.
    const hasOne = !ownSpecialtyOnly || traits.some(t => {
      const node = sheet?.skills?.[t];
      return node && typeof node === 'object' && Array.isArray(node.specialties) && node.specialties.length > 0;
    });
    if (hasOne) { pool += 1; parts.push(typeof specialty === 'string' ? specialty : 'Specialty'); }
  }
  if (surge) { pool += BP.surge[bp]; parts.push(`Blood Surge +${BP.surge[bp]}`); }

  // Storyteller effects on this character, as stored in the session.
  for (const e of effects) {
    if (effectIds.includes(e.id) && num(e.mod)) { pool += num(e.mod); parts.push(`${e.label} ${num(e.mod) > 0 ? '+' : ''}${num(e.mod)}`); }
  }
  // Running discipline powers that modify pools: owned, and valued from the sheet.
  for (const id of [...new Set(powerIds)]) {
    const p = findPowerAnywhere(id);
    if (!p || p.dicePoolMod == null || !ownsPower(sheet, id)) continue;
    const amt = mechAmount(p.dicePoolMod, sheet);
    if (amt) { pool += amt; parts.push(`${p.name} ${amt > 0 ? '+' : ''}${amt}`); }
  }
  if (situational && num(situational.mod)) {
    const mod = clamp(situational.mod, -10, 10);
    pool += mod;
    parts.push(`${mod > 0 ? '+' : ''}${mod}${situational.reason ? ` ${String(situational.reason).slice(0, 60)}` : ''}`);
  }

  // V5 Impairment: −2 to Physical (Health) / Social & Mental (Willpower) pools.
  // Ignored in frenzy, or for a spent Willpower (charged by the caller).
  let impaired = 0;
  if (!frenzied) {
    if (tr.healthImpaired && traits.some(t => PHYSICAL.has(t))) impaired += 2;
    if (tr.willpowerImpaired && traits.some(t => MENTAL_SOCIAL.has(t))) impaired += 2;
  }
  if (impaired && !ignoreImpairment) { pool -= impaired; parts.push(`Impaired −${impaired}`); }
  if (tr.degeneration && !frenzied) { pool -= 2; parts.push('Degeneration −2'); }

  return { pool: Math.max(0, pool), parts, impaired, hunger: tr.hunger };
}

/** Frenzy resistance: Willpower rating + Humanity/3, Brujah lose Bane Severity against fury. */
function frenzyPool(sheet, clan) {
  const tr = trackers(sheet);
  const bonus = Math.floor(tr.humanity / 3);
  const bane = clan === 'Brujah' && sheet?.frenzyState === 'fury' ? BP.bane[bloodPotency(sheet, clan)] : 0;
  return {
    pool: Math.max(0, tr.maxWillpower + bonus - bane),
    parts: [`Willpower ${tr.maxWillpower}`, `Humanity/3 ${bonus}`, ...(bane ? [`Bane −${bane}`] : [])],
  };
}

/**
 * Inserts one roll (or a dice-less feed event when there are no dice).
 * @returns {Promise<object>} the stored row in feed shape
 */
async function insertRoll(db, r) {
  const normal = r.normal || [];
  const hunger = r.hunger || [];
  const rouse = r.rouse || [];
  const difficulty = num(r.difficulty);
  const outcome = rouse.length
    ? { successes: rouse.some(d => d >= 6) ? 1 : 0, crit_pairs: 0, messy_crit: false, bestial_failure: false }
    : computeV5Outcome({ normal, hunger, difficulty });
  const results = { normal, hunger, ...(rouse.length ? { rouse } : {}), difficulty: difficulty || null, ...(r.extra || {}) };
  const [ins] = await db.query(
    `INSERT INTO dice_rolls
       (user_id, character_id, character_name, session_id, roll_type, pool, hunger, sides, results_json,
        successes, crit_pairs, messy_crit, bestial_failure, note, is_hidden, rerolled)
     VALUES (?,?,?,?,?,?,?,10,?,?,?,?,?,?,?,?)`,
    [r.userId, r.characterId ?? null, r.characterName ? String(r.characterName).slice(0, 255) : null, r.sessionId ?? null,
      r.rollType || 'free', normal.length + hunger.length + rouse.length, num(r.hungerLevel ?? hunger.length),
      JSON.stringify(results), outcome.successes, outcome.crit_pairs, outcome.messy_crit ? 1 : 0, outcome.bestial_failure ? 1 : 0,
      r.note ? String(r.note).slice(0, 255) : null, r.isHidden ? 1 : 0, r.rerolled ? 1 : 0]
  );
  const [[row]] = await db.query('SELECT * FROM dice_rolls WHERE id=?', [ins.insertId]);
  return formatRoll(row);
}

/** A dice_rolls row in the shape the live-session feed and dice screens read. */
function formatRoll(row) {
  let results = row.results_json;
  if (typeof results === 'string') { try { results = JSON.parse(results); } catch { results = {}; } }
  results = results || {};
  return {
    id: row.id,
    user_id: row.user_id,
    character_id: row.character_id,
    character_name: row.character_name ?? row.char_name ?? null,
    session_id: row.session_id,
    roll_type: row.roll_type || 'free',
    pool: row.pool,
    hunger: row.hunger,
    difficulty: results.difficulty || 0,
    results,
    successes: row.successes,
    crit_pairs: row.crit_pairs,
    has_critical: row.crit_pairs > 0,
    has_messy_critical: !!row.messy_crit,
    has_bestial_failure: !!row.bestial_failure,
    rerolled: !!row.rerolled,
    note: row.note,
    is_hidden: !!row.is_hidden,
    created_at: row.created_at,
  };
}

module.exports = { traitPool, frenzyPool, parsePowerPool, insertRoll, formatRoll, trackers, bloodPotency, NO_REROLL, BP };
