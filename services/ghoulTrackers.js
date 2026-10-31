// services/ghoulTrackers.js
//
// Ghouls (and mortal retainers) at the table: Health and Willpower trackers on
// the retainer sheet (`sheet.health`, `sheet.willpower`, {superficial,
// aggravated}), changed only here, under a row lock. Sheet saves elsewhere keep
// the stored trackers (keepTrackers), so a rebuild or a cached admin copy never
// heals or re-wounds a ghoul.
//
// Rolling: a ghoul has no Hunger and no Blood Potency, so its pools are plain
// dice built with the same rules as a vampire's (services/rolls.js traitPool,
// impairment included). V5 Core: a ghoul using a power above level 1 takes 1
// Aggravated Health instead of a Rouse Check (`overreach`).
const { parseSheet } = require('../utils/sheet');

const num = (v) => Number(v) || 0;
const isGhoulSheet = (sheet) => sheet?.isGhoul === true;

const hasPower = (sheet, discipline, name) => (sheet?.powers || [])
  .some((p) => p && p.discipline === discipline && new RegExp(`^${name}`, 'i').test(String(p.name || '')));

// Mirrors the sheet's summary in RetainersView: Stamina + 3, Crone's Curse -1,
// Resilience adds the Fortitude rating.
function ghoulMaxes(sheet) {
  let health = (num(sheet?.attributes?.Stamina) || 1) + 3;
  if ((sheet?.flaws || []).some((f) => /crone's curse/i.test(String(f?.name || '')))) health -= 1;
  if (hasPower(sheet, 'Fortitude', 'Resilience')) health += num(sheet?.disciplines?.Fortitude) || 1;
  const willpower = (num(sheet?.attributes?.Composure) || 1) + (num(sheet?.attributes?.Resolve) || 1);
  return { health: Math.max(1, health), willpower: Math.max(1, willpower) };
}

const track = (t) => ({ superficial: num(t?.superficial), aggravated: num(t?.aggravated) });

// The trackers clamped to the current maxima, plus the impairment facts.
function ghoulTrackers(sheet) {
  const max = ghoulMaxes(sheet);
  const fit = (t, m) => {
    const aggravated = Math.min(m, Math.max(0, t.aggravated));
    return { superficial: Math.min(m - aggravated, Math.max(0, t.superficial)), aggravated };
  };
  const health = fit(track(sheet?.health), max.health);
  const willpower = fit(track(sheet?.willpower), max.willpower);
  return {
    maxHealth: max.health, maxWillpower: max.willpower, health, willpower,
    willpowerLeft: max.willpower - willpower.superficial - willpower.aggravated,
    dead: health.aggravated >= max.health,
  };
}

// V5 damage: Superficial halved when asked (mortals take it whole from most
// sources), and once the track is full each new point turns a Superficial into
// an Aggravated.
function addDamage(t, max, amount, type) {
  let { superficial: sup, aggravated: agg } = t;
  for (let i = 0; i < amount; i += 1) {
    if (sup + agg < max) { if (type === 'aggravated') agg += 1; else sup += 1; } else if (sup > 0) { sup -= 1; agg += 1; } else agg = Math.min(max, agg + 1);
  }
  return { superficial: sup, aggravated: agg };
}

/**
 * Applies tracker changes to a retainer sheet (mutates and returns it).
 * change: { healthSupDelta, healthAggDelta, wpSupDelta, wpAggDelta,
 *           damage: { amount, type: 'superficial'|'aggravated', halve, track: 'health'|'willpower' } }
 */
function applyGhoulChange(sheet, change = {}) {
  const t = ghoulTrackers(sheet);
  let health = { ...t.health };
  let willpower = { ...t.willpower };
  const clampDelta = (v, d, lo, hi) => Math.max(lo, Math.min(hi, v + Math.round(num(d))));
  health.superficial = clampDelta(health.superficial, change.healthSupDelta, 0, t.maxHealth - health.aggravated);
  health.aggravated = clampDelta(health.aggravated, change.healthAggDelta, 0, t.maxHealth);
  health.superficial = Math.min(health.superficial, t.maxHealth - health.aggravated);
  willpower.superficial = clampDelta(willpower.superficial, change.wpSupDelta, 0, t.maxWillpower - willpower.aggravated);
  willpower.aggravated = clampDelta(willpower.aggravated, change.wpAggDelta, 0, t.maxWillpower);
  willpower.superficial = Math.min(willpower.superficial, t.maxWillpower - willpower.aggravated);

  const d = change.damage;
  if (d && num(d.amount) > 0) {
    let amount = Math.min(30, Math.round(num(d.amount)));
    const type = d.type === 'aggravated' ? 'aggravated' : 'superficial';
    if (type === 'superficial' && d.halve) amount = Math.ceil(amount / 2);
    if (d.track === 'willpower') willpower = addDamage(willpower, t.maxWillpower, amount, type);
    else health = addDamage(health, t.maxHealth, amount, type);
  }
  sheet.health = health;
  sheet.willpower = willpower;
  return sheet;
}

/** A sheet a player or the admin editor saved, with the stored trackers kept. */
function keepTrackers(storedSheet, sheet) {
  if (!sheet || typeof sheet !== 'object') return sheet;
  const out = { ...sheet };
  delete out.health;
  delete out.willpower;
  if (storedSheet?.health) out.health = storedSheet.health;
  if (storedSheet?.willpower) out.willpower = storedSheet.willpower;
  return out;
}

/** Row-locked read-modify-write of one retainer's sheet. fn(sheet, row, conn) may return extra data. */
async function withRetainerLock(pool, retainerId, fn) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[row]] = await conn.query('SELECT * FROM retainers WHERE id=? FOR UPDATE', [retainerId]);
    if (!row) { await conn.rollback(); return { notFound: true }; }
    const sheet = parseSheet(row.sheet) || {};
    const extra = await fn(sheet, row, conn);
    await conn.query('UPDATE retainers SET sheet=? WHERE id=?', [JSON.stringify(sheet), retainerId]);
    await conn.commit();
    return { sheet, row, ...(extra || {}) };
  } catch (e) {
    await conn.rollback().catch(() => {});
    throw e;
  } finally {
    conn.release();
  }
}

/**
 * The character who plays a retainer at the table: the owner of a personal
 * one, the domitor of a coterie ghoul (who manages it). Returns the
 * characters row (id, user_id, name) or null.
 */
async function controllerOf(db, row) {
  const charId = row.character_id || row.domitor_character_id;
  if (!charId) return null;
  const [[ch]] = await db.query('SELECT id, user_id, name FROM characters WHERE id=?', [charId]);
  return ch || null;
}

/** The sheet as services/rolls.js traitPool expects it: no Hunger, no Blood Potency. */
function rollableSheet(sheet) {
  const disciplinePowers = {};
  for (const p of sheet?.powers || []) {
    if (p && p.discipline) (disciplinePowers[p.discipline] = disciplinePowers[p.discipline] || []).push({ id: p.id, name: p.name });
  }
  // No health/willpower: the caller applies the ghoul's own impairment (ghoulImpairment),
  // since traitPool's max Health doesn't know Crone's Curse.
  return {
    attributes: sheet?.attributes || {}, skills: sheet?.skills || {}, disciplines: sheet?.disciplines || {},
    disciplinePowers, hunger: 0, blood_potency: 0, humanity: 7, stains: 0,
  };
}

// V5 Impairment for a ghoul's pool: -2 Physical when Health is full of damage,
// -2 Social/Mental when Willpower is.
function ghoulImpairment(sheet, traits) {
  const { PHYSICAL, MENTAL_SOCIAL } = require('./rolls');
  const t = ghoulTrackers(sheet);
  let minus = 0;
  if (t.health.superficial + t.health.aggravated >= t.maxHealth && traits.some((x) => PHYSICAL.has(x))) minus += 2;
  if (t.willpowerLeft <= 0 && traits.some((x) => MENTAL_SOCIAL.has(x))) minus += 2;
  return minus;
}

// Retainer ids the Storyteller has brought into a session (metadata.ghouls).
const sessionGhoulIds = (metadata) => (Array.isArray(metadata?.ghouls) ? metadata.ghouls : [])
  .map(Number).filter(Number.isInteger);

/**
 * Locks a retainer for a roll or a tracker change at the table: it must be in
 * the session, and the caller must play it (or be a Storyteller).
 * Returns { row, sheet, controller }; throws { status } errors.
 */
async function lockSessionGhoul(conn, session, retainerId, user, admin) {
  const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
  if (!session) fail(400, 'Ghouls roll inside a live session.');
  if (!sessionGhoulIds(session.metadata).includes(Number(retainerId))) fail(403, 'The Storyteller has not brought that retainer into this session.');
  const [[row]] = await conn.query('SELECT * FROM retainers WHERE id=? FOR UPDATE', [retainerId]);
  if (!row) fail(404, 'Retainer not found');
  const controller = await controllerOf(conn, row);
  if (!admin && Number(controller?.user_id) !== Number(user.id)) fail(403, 'Only the player who plays this retainer can roll for them.');
  return { row, sheet: parseSheet(row.sheet) || {}, controller };
}

module.exports = { sessionGhoulIds, lockSessionGhoul, ghoulMaxes, ghoulTrackers, applyGhoulChange, keepTrackers, withRetainerLock, controllerOf, rollableSheet, ghoulImpairment, isGhoulSheet };
