// services/ghoulFeeding.js
//
// Ghoul upkeep. Every downtime cycle each ghoul needs one feeding: a Rouse
// Check paid by a vampire (Hunger +1 on 1-5), thrown here and logged in
// dice_rolls like every other roll. Players may feed early from the Feeding
// page; whatever is still unfed when the cycle's `ghoul_feeding_date` (admin
// Calendar) passes is fed by the upkeep run: a personal ghoul by its owner, a
// coterie ghoul by a random member below Hunger 5.
//
// A ghoul starves when it was let go (`retainers.let_starve`) or nobody can pay
// (Hunger 5). A starved ghoul has lost its powers and is unavailable until a
// later cycle's feeding: its latest `ghoul_feedings` row is the whole state.

const { randomInt } = require('crypto');
const { parseSheet } = require('../utils/sheet');
const { getSetting, setSetting } = require('../utils/settings');
const { cycleIndexOf, resolveCurrentFeedingCycle } = require('../utils/feedingCycle');
const { readCycles, withDefaultDates } = require('./downtimeSchedule');
const { rouse } = require('./dice');
const { insertRoll } = require('./rolls');

const isGhoulRow = (row) => parseSheet(row.sheet)?.isGhoul === true;

function shuffle(list) {
  const a = [...list];
  for (let i = a.length - 1; i > 0; i -= 1) {
    const j = randomInt(0, i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/**
 * Feeds `ghoul` from one vampire inside conn's open transaction: locks the
 * feeder, refuses at Hunger 5, rolls the Rouse Check and records the feeding.
 * A second feeding for the same ghoul and cycle fails on the unique key
 * (ER_DUP_ENTRY), so the caller's rollback also undoes the Rouse.
 */
async function feedGhoul(conn, { ghoul, feederId, cycleIndex, method }) {
  const [[feeder]] = await conn.query('SELECT id, user_id, name, sheet FROM characters WHERE id=? FOR UPDATE', [feederId]);
  if (!feeder) return { error: 'Character not found.' };
  const sheet = parseSheet(feeder.sheet);
  const hungerBefore = Number(sheet.hunger) || 0;
  if (hungerBefore >= 5) return { error: 'At Hunger 5 there is no blood to spare. Hunt first.', hunger5: true };

  const { success, dice } = rouse(sheet);
  await conn.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), feeder.id]);
  await insertRoll(conn, {
    userId: feeder.user_id, characterId: feeder.id, characterName: feeder.name,
    rollType: 'ghoul_feeding', rouse: dice, hungerLevel: hungerBefore, note: `Fed ghoul ${ghoul.name}`,
  });
  await conn.query(
    `INSERT INTO ghoul_feedings (retainer_id, cycle_index, status, method, fed_by_character_id, rouse_dice, hunger_before, hunger_after)
     VALUES (?, ?, 'fed', ?, ?, ?, ?, ?)`,
    [ghoul.id, cycleIndex, method, feeder.id, JSON.stringify(dice), hungerBefore, sheet.hunger]
  );
  return { success, dice, hungerBefore, hungerAfter: sheet.hunger, feeder, sheet };
}

async function starveGhoul(conn, { ghoulId, cycleIndex, method }) {
  await conn.query(
    "INSERT IGNORE INTO ghoul_feedings (retainer_id, cycle_index, status, method) VALUES (?, ?, 'starved', ?)",
    [ghoulId, cycleIndex, method]
  );
}

/**
 * Feeding state per ghoul id, as seen in `cycleIndex`:
 *   state      'fed' | 'starved' | 'hungry'
 *   canFeed    no feeding (or starvation) recorded for this cycle yet
 *   current    this cycle's row, if any, with the feeder's name
 * A ghoul starved in an earlier cycle stays 'starved' until it is fed again.
 * Once a cycle's upkeep is done (or skipped: the cycle the system went live in), a
 * ghoul with nothing recorded for it owes nothing more that cycle.
 */
async function ghoulStates(db, ids, cycleIndex) {
  const settled = String(await getSetting('ghoul_upkeep_last_cycle', '')) === String(cycleIndex);
  const out = {};
  for (const id of ids) out[id] = settled ? { state: 'fed', canFeed: false, current: null } : { state: 'hungry', canFeed: true, current: null };
  if (!ids.length) return out;
  const [rows] = await db.query(
    `SELECT g.retainer_id, g.cycle_index, g.status, g.method, g.rouse_dice, g.hunger_before, g.hunger_after, g.created_at,
            c.name AS fed_by_name
       FROM ghoul_feedings g LEFT JOIN characters c ON c.id = g.fed_by_character_id
      WHERE g.retainer_id IN (?)
      ORDER BY g.created_at DESC, g.id DESC`,
    [ids]
  );
  const latest = new Set();
  for (const r of rows) {
    const s = out[r.retainer_id];
    if (Number(r.cycle_index) === Number(cycleIndex)) {
      s.state = r.status;
      s.canFeed = false;
      s.current = { ...r, rouse_dice: r.rouse_dice ? JSON.parse(r.rouse_dice) : null };
    } else if (!latest.has(r.retainer_id) && !s.current && r.status === 'starved') {
      s.state = 'starved';
    }
    latest.add(r.retainer_id);
  }
  return out;
}

// The cycle whose upkeep time has most recently passed, or null.
async function dueUpkeepCycle(now) {
  const cycles = withDefaultDates(await readCycles());
  let due = null;
  cycles.forEach((c, i) => {
    const at = c.ghoul_feeding_date ? new Date(c.ghoul_feeding_date) : null;
    if (!at || isNaN(at.getTime()) || at > now) return;
    if (!due || at > due.at) due = { at, cycleIndex: cycleIndexOf(c, i), title: c.title };
  });
  return due;
}

// Active characters (retired ones have no user) who may pay for a coterie ghoul.
async function coterieFeeders(db, coterieId) {
  const [rows] = await db.query(
    `SELECT ch.id FROM coterie_members m JOIN characters ch ON ch.user_id = m.user_id
      WHERE m.coterie_id=? AND ch.user_id IS NOT NULL`,
    [coterieId]
  );
  return rows.map((r) => r.id);
}

/**
 * Feeds (or starves) every ghoul with nothing recorded for the cycle.
 * Without `cycleIndex` it runs for the cycle whose upkeep time has passed, once:
 * the processed cycle is remembered. The very first run only records a baseline,
 * so going live never charges a cycle that was already under way: when the
 * current cycle's downtimes have closed, upkeep starts with the next cycle.
 */
async function runGhoulUpkeep(pool, log, { now = new Date(), cycleIndex: forced, notify } = {}) {
  if ((await getSetting('feeding_enabled', 'true')) !== 'true') return { skipped: 'disabled' };

  let cycleIndex = forced;
  if (cycleIndex == null) {
    const due = await dueUpkeepCycle(now);
    const last = await getSetting('ghoul_upkeep_last_cycle', null);
    if (last === null || last === '') {
      const current = await resolveCurrentFeedingCycle(now);
      const baseline = current.cycleEnd < now ? current.cycleIndex : (due ? due.cycleIndex : current.cycleIndex - 1);
      await setSetting('ghoul_upkeep_last_cycle', String(baseline));
      return { skipped: 'baseline recorded', cycleIndex: baseline };
    }
    if (!due) return { skipped: 'nothing due' };
    if (String(due.cycleIndex) === String(last)) return { skipped: 'already processed', cycleIndex: due.cycleIndex };
    cycleIndex = due.cycleIndex;
  }

  const [rows] = await pool.query(
    `SELECT r.id, r.name, r.sheet, r.character_id, r.coterie_id, r.let_starve, owner.user_id AS owner_user_id
       FROM retainers r LEFT JOIN characters owner ON owner.id = r.character_id
      WHERE NOT EXISTS (SELECT 1 FROM ghoul_feedings g WHERE g.retainer_id = r.id AND g.cycle_index = ?)`,
    [cycleIndex]
  );
  const ghouls = rows.filter(isGhoulRow).filter((g) => g.coterie_id || g.owner_user_id);

  const result = { cycleIndex, fed: 0, starved: 0, report: [] };
  const messages = [];
  for (const ghoul of ghouls) {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const candidates = ghoul.coterie_id ? shuffle(await coterieFeeders(conn, ghoul.coterie_id)) : [ghoul.character_id];
      let fed = null;
      if (!ghoul.let_starve) {
        for (const feederId of candidates) {
          const r = await feedGhoul(conn, { ghoul, feederId, cycleIndex, method: ghoul.coterie_id ? 'random' : 'upkeep' });
          if (!r.error) { fed = r; break; }
        }
      }
      if (!fed) {
        await starveGhoul(conn, {
          ghoulId: ghoul.id, cycleIndex,
          method: ghoul.let_starve ? 'let_starve' : (candidates.length ? 'hunger_5' : 'no_feeder'),
        });
      }
      await conn.commit();

      if (fed) {
        result.fed += 1;
        result.report.push(`${ghoul.name}: fed by ${fed.feeder.name}${fed.success ? '' : ` (Hunger ${fed.hungerAfter})`}`);
        messages.push({
          userId: fed.feeder.user_id, title: 'Ghoul fed',
          body: `${fed.feeder.name} fed ${ghoul.name}. ${fed.success ? 'The Rouse Check held.' : `Hunger rose to ${fed.hungerAfter}.`}`,
        });
      } else {
        result.starved += 1;
        result.report.push(`${ghoul.name}: STARVED (${ghoul.let_starve ? 'let go' : 'no feeder below Hunger 5'})`);
        const [owners] = ghoul.coterie_id
          ? await pool.query('SELECT DISTINCT user_id FROM coterie_members WHERE coterie_id=?', [ghoul.coterie_id])
          : [[{ user_id: ghoul.owner_user_id }]];
        for (const o of owners) {
          messages.push({ userId: o.user_id, title: 'Ghoul starved', body: `${ghoul.name} went unfed and lost their powers until fed again.` });
        }
      }
    } catch (err) {
      await conn.rollback().catch(() => {});
      log?.err?.('Ghoul upkeep failed for a ghoul', { retainer_id: ghoul.id, error: err.message });
    } finally {
      conn.release();
    }
  }

  await setSetting('ghoul_upkeep_last_cycle', String(cycleIndex));
  log?.info?.(`Ghoul upkeep for cycle ${cycleIndex}: ${result.fed} fed, ${result.starved} starved.`);

  const send = notify || require('./push').sendPushNotification;
  for (const m of messages) Promise.resolve(send(m.userId, m.title, m.body, { url: '/feeding' }, 'system')).catch(() => {});
  return result;
}

// Ghouls a character may see on the Feeding page: their own, and their coteries'.
async function ghoulsFor(db, characterId) {
  const [rows] = await db.query(
    `SELECT r.id, r.name, r.tier, r.sheet, r.character_id, r.coterie_id, r.domitor_character_id, r.let_starve,
            co.name AS coterie_name, dom.name AS domitor_name
       FROM retainers r
       LEFT JOIN coteries co ON co.id = r.coterie_id
       LEFT JOIN characters dom ON dom.id = r.domitor_character_id
      WHERE r.character_id = ?
         OR r.coterie_id IN (SELECT m.coterie_id FROM coterie_members m JOIN characters ch ON ch.user_id = m.user_id WHERE ch.id = ?)
      ORDER BY r.coterie_id IS NOT NULL, r.name`,
    [characterId, characterId]
  );
  return rows.filter(isGhoulRow).map(({ sheet, ...r }) => r);
}

async function currentCycleIndex() {
  return (await resolveCurrentFeedingCycle()).cycleIndex;
}

// Sets `feeding` ('fed' | 'hungry' | 'starved') on each ghoul of a retainer list, for the current
// cycle. A list without sheets can pass its own ghoul test (a coterie ghoul always has a domitor).
async function attachFeeding(db, retainers, isGhoul = isGhoulRow) {
  const ghouls = retainers.filter(isGhoul);
  if (!ghouls.length) return retainers;
  const states = await ghoulStates(db, ghouls.map((r) => r.id), await currentCycleIndex());
  for (const r of ghouls) r.feeding = states[r.id].state;
  return retainers;
}

// The next ghoul upkeep still to come (Calendar), for the Feeding page's countdown text.
// A cycle already settled (its upkeep ran, or it was skipped at go-live) is left out.
async function nextUpkeepAt(now = new Date()) {
  const settled = String(await getSetting('ghoul_upkeep_last_cycle', ''));
  const upcoming = withDefaultDates(await readCycles())
    .filter((c, i) => String(cycleIndexOf(c, i)) !== settled)
    .map((c) => c.ghoul_feeding_date)
    .filter((d) => d && new Date(d) > now)
    .sort();
  return upcoming[0] || null;
}

module.exports = { nextUpkeepAt, feedGhoul, starveGhoul, ghoulStates, ghoulsFor, runGhoulUpkeep, dueUpkeepCycle, currentCycleIndex, attachFeeding };
