// tests/ghoulFeeding.test.js — up to 3 rolled hunts per cycle, and ghoul
// upkeep: early feeding (a Rouse Check), refusal at Hunger 5, the cycle-end
// run (owner pays for a personal ghoul, a random member below Hunger 5 for a
// coterie ghoul), letting a ghoul starve, and no charge on the first run.
const { buildTestApp } = require('./setup/testApp');
const { setupTestDatabase, getTestPool, truncateAll } = require('./setup/testDb');
const { registerUser, extractSessionCookie } = require('./setup/helpers');
const { setSetting } = require('../utils/settings');
const { parseSheet } = require('../utils/sheet');
const { runGhoulUpkeep, nextUpkeepAt } = require('../services/ghoulFeeding');

const CYCLE = 7;
let app, pool, ana, bo, cy, coterieId;

const req = (method, url, who, payload) => app.inject({ method, url, headers: { cookie: who.cookie }, payload });
const day = (offset) => new Date(Date.now() + offset * 86400000).toISOString().slice(0, 10);
const setHunger = (who, hunger) => pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify({ hunger }), who.characterId]);
const hungerOf = async (who) => parseSheet((await pool.query('SELECT sheet FROM characters WHERE id=?', [who.characterId]))[0][0].sheet).hunger;
const ghoul = async (fields) => (await pool.query('INSERT INTO retainers SET ?', [{ tier: 1, sheet: JSON.stringify({ isGhoul: true }), ...fields }]))[0].insertId;
const rowFor = async (id) => (await pool.query('SELECT * FROM ghoul_feedings WHERE retainer_id=? AND cycle_index=?', [id, CYCLE]))[0][0];

async function makePlayer(name) {
  const u = await registerUser(app, { displayName: name });
  const [r] = await pool.query('INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?,?,?,0,?)', [u.user.id, name, 'Brujah', '{"hunger":1}']);
  return { ...u, characterId: r.insertId };
}

beforeAll(async () => {
  await setupTestDatabase();
  pool = getTestPool();
  await truncateAll();
  await pool.query('DELETE FROM ghoul_feedings');
  await pool.query('DELETE FROM feedings');
  app = buildTestApp(pool);
  await app.ready();
  await setSetting('feeding_enabled', 'true');
  await setSetting('ghoul_upkeep_last_cycle', '');
  await setSetting('downtime_cycles_schedule', JSON.stringify([
    { id: `cycle_${CYCLE}`, title: 'Test Cycle', opening_date: day(-2), closing_date: day(2), status: 'active' },
  ]));
  ana = await makePlayer('Ana');
  bo = await makePlayer('Bo');
  cy = await makePlayer('Cy');
  const res = await req('POST', '/api/coteries', ana, {
    name: 'Ghoul Test Coterie', domain_id: 7,
    traits: { chasse: 2, lien: 1, portillon: 0 }, backgrounds: [], merits: [], flaws: [],
    points_per_member: 1, bonus_points: 0, members: [ana, bo, cy].map((m) => ({ user_id: m.user.id })),
  });
  coterieId = JSON.parse(res.body).coterie.id;
});
afterAll(async () => { if (app) await app.close(); });

describe('hunts per cycle', () => {
  it('refuses a fourth rolled hunt, but herd rows do not count', async () => {
    await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify({ hunger: 3, predator_type: 'Alleycat' }), ana.characterId]);
    for (const outcome of ['success', 'failure', 'herd', 'critical']) {
      await pool.query(
        `INSERT INTO feedings (character_id, division, predator_type, pool_label, dice_pool, difficulty, hunger_before, outcome, status, cycle_index)
         VALUES (?, 39, 'Alleycat', 'x', 3, 3, 3, ?, 'resolved', ?)`,
        [ana.characterId, outcome, CYCLE]
      );
    }
    const status = JSON.parse((await req('GET', '/api/feeding/status', ana)).body);
    expect(status.huntsUsed).toBe(3);
    expect(status.fed).toBe(true);
    expect(status.huntingOpen).toBe(true);
    const roll = await req('POST', '/api/feeding/roll', ana, { division: 39, poolIndex: 0 });
    expect(roll.statusCode).toBe(409);
    await pool.query('DELETE FROM feedings');
  });
});

describe('ghoul upkeep', () => {
  it('feeds early with a Rouse Check, once per cycle, never at Hunger 5', async () => {
    const id = await ghoul({ character_id: bo.characterId, name: 'Igor' });
    await setHunger(bo, 5);
    expect((await req('POST', `/api/feeding/ghouls/${id}/feed`, bo)).statusCode).toBe(400);

    await setHunger(bo, 2);
    const fed = await req('POST', `/api/feeding/ghouls/${id}/feed`, bo);
    expect(fed.statusCode).toBe(200);
    const body = JSON.parse(fed.body);
    expect(await hungerOf(bo)).toBe(body.success ? 2 : 3);
    expect((await rowFor(id)).method).toBe('early');
    expect((await req('POST', `/api/feeding/ghouls/${id}/feed`, bo)).statusCode).toBe(409);
  });

  it('records a baseline on the first scheduled run instead of charging an old cycle', async () => {
    const id = await ghoul({ character_id: ana.characterId, name: 'Old Hand' });
    const res = await runGhoulUpkeep(pool, null, { now: new Date(Date.now() + 30 * 86400000), notify: () => {} });
    expect(res.skipped).toBe('baseline recorded');
    expect(res.cycleIndex).toBe(CYCLE); // its downtimes had closed: upkeep starts next cycle
    expect(await nextUpkeepAt()).toBeNull(); // the skipped cycle's date is not advertised
    expect(await rowFor(id)).toBeUndefined();
    // That cycle now owes nothing: no "needs feeding", no Feed button.
    const mine = JSON.parse((await req('GET', '/api/feeding/ghouls', ana)).body).ghouls.find((g) => g.id === id);
    expect(mine).toMatchObject({ state: 'fed', canFeed: false });
    await pool.query('DELETE FROM retainers WHERE id=?', [id]);
    await setSetting('ghoul_upkeep_last_cycle', '');
  });

  it('at cycle end: a random member below Hunger 5 pays for a coterie ghoul; let-go ghouls starve', async () => {
    const shared = await ghoul({ coterie_id: coterieId, domitor_character_id: ana.characterId, name: 'Renfield' });
    const stray = await ghoul({ character_id: ana.characterId, name: 'Stray' });
    await setHunger(ana, 5);
    await setHunger(bo, 1);
    await setHunger(cy, 5);

    // Only the domitor may let a coterie ghoul go; the owner a personal one.
    expect((await req('POST', `/api/feeding/ghouls/${shared}/let-starve`, bo, { value: true })).statusCode).toBe(403);
    expect((await req('POST', `/api/feeding/ghouls/${stray}/let-starve`, ana, { value: true })).statusCode).toBe(200);

    const res = await runGhoulUpkeep(pool, null, { cycleIndex: CYCLE, notify: () => {} });
    expect(res.fed).toBe(1);
    expect(res.starved).toBe(1);
    expect(res.report.some((l) => l.startsWith('Stray: STARVED'))).toBe(true);

    const sharedRow = await rowFor(shared);
    expect(sharedRow.status).toBe('fed');
    expect(sharedRow.method).toBe('random');
    expect(sharedRow.fed_by_character_id).toBe(bo.characterId);
    expect((await rowFor(stray)).method).toBe('let_starve');

    const list = JSON.parse((await req('GET', '/api/feeding/ghouls', ana)).body).ghouls;
    expect(list.find((g) => g.id === stray).state).toBe('starved');
    expect(list.find((g) => g.id === shared).state).toBe('fed');

    // Running again touches nothing.
    expect(await runGhoulUpkeep(pool, null, { cycleIndex: CYCLE, notify: () => {} })).toMatchObject({ fed: 0, starved: 0 });
  });
});

describe('feed all and Storyteller feedings', () => {
  it('feeds every ghoul the player can, skipping the ones let go', async () => {
    await setSetting('ghoul_upkeep_last_cycle', ''); // the previous test ran this cycle's upkeep
    const dee = await makePlayer('Dee');
    const a = await ghoul({ character_id: dee.characterId, name: 'First' });
    const b = await ghoul({ character_id: dee.characterId, name: 'Second' });
    const gone = await ghoul({ character_id: dee.characterId, name: 'Gone', let_starve: 1 });
    await setHunger(dee, 3);

    expect(JSON.parse((await req('GET', '/api/feeding/status', dee)).body).ghoulsUnfed).toBe(2);
    const res = JSON.parse((await req('POST', '/api/feeding/ghouls/feed-all', dee)).body);
    expect(res.fed.map((g) => g.id).sort()).toEqual([a, b].sort());
    expect(await rowFor(gone)).toBeUndefined();
    expect(JSON.parse((await req('GET', '/api/feeding/status', dee)).body).ghoulsUnfed).toBe(0);
  });

  it('lets a Storyteller record a feeding that unlocks actions without using a hunt', async () => {
    const st = await makePlayer('Storyteller');
    await pool.query('UPDATE users SET role="admin" WHERE id=?', [st.user.id]);
    st.cookie = extractSessionCookie(await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: st.email, password: st.password } }));
    const eve = await makePlayer('Eve');
    await setHunger(eve, 4);

    expect((await req('POST', '/api/admin/feeding/manual', eve, { character_id: eve.characterId, hunger: 1 })).statusCode).toBe(403);
    const before = JSON.parse((await req('GET', '/api/admin/feeding/roster', st)).body).characters;
    expect(before.find((c) => c.id === eve.characterId)).toMatchObject({ fed: false, hunts: 0 });

    expect((await req('POST', '/api/admin/feeding/manual', st, { character_id: eve.characterId, hunger: 2 })).statusCode).toBe(200);
    const status = JSON.parse((await req('GET', '/api/feeding/status', eve)).body);
    expect(status.fed).toBe(true);
    expect(status.huntsUsed).toBe(0);
    expect(await hungerOf(eve)).toBe(2);
    const after = JSON.parse((await req('GET', '/api/admin/feeding/roster', st)).body).characters;
    expect(after.find((c) => c.id === eve.characterId)).toMatchObject({ fed: true, hunts: 0, manual: 1 });
    const stats = JSON.parse((await req('GET', '/api/admin/feeding/stats', st)).body);
    expect(stats.counts.manual).toBeGreaterThanOrEqual(1);
    expect(stats.players.fed).toBeGreaterThanOrEqual(1);
    expect(stats.huntsPerCycle).toBe(3);
  });
});

describe('Storyteller undo', () => {
  it('undoes a ghoul feeding (Hunger back) and a player\'s whole cycle of feedings', async () => {
    await setSetting('ghoul_upkeep_last_cycle', '');
    const st = await makePlayer('Undo ST');
    await pool.query('UPDATE users SET role="admin" WHERE id=?', [st.user.id]);
    st.cookie = extractSessionCookie(await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: st.email, password: st.password } }));
    const fay = await makePlayer('Fay');
    const igor = await ghoul({ character_id: fay.characterId, name: 'Undo Igor' });

    await setHunger(fay, 2);
    expect((await req('POST', `/api/feeding/ghouls/${igor}/feed`, fay)).statusCode).toBe(200);
    expect((await req('POST', `/api/admin/feeding/ghouls/${igor}/undo`, st)).statusCode).toBe(200);
    expect(await hungerOf(fay)).toBe(2);
    expect(await rowFor(igor)).toBeUndefined();

    await setHunger(fay, 4);
    await req('POST', '/api/admin/feeding/manual', st, { character_id: fay.characterId, hunger: 3 });
    await req('POST', '/api/admin/feeding/manual', st, { character_id: fay.characterId, hunger: 1 });
    const res = JSON.parse((await req('POST', `/api/admin/feeding/character/${fay.characterId}/undo-cycle`, st)).body);
    expect(res.undone).toBe(2);
    expect(await hungerOf(fay)).toBe(4);
    expect(JSON.parse((await req('GET', '/api/feeding/status', fay)).body).fed).toBe(false);
  });
});

describe('Admin views a past cycle', () => {
  it('lists cycles, filters by ?cycle, and undoes a feeding from a past cycle', async () => {
    const st = await makePlayer('Past ST');
    await pool.query('UPDATE users SET role="admin" WHERE id=?', [st.user.id]);
    st.cookie = extractSessionCookie(await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: st.email, password: st.password } }));
    const gus = await makePlayer('Gus');
    await setHunger(gus, 2);
    const [ins] = await pool.query(
      `INSERT INTO feedings (character_id, division, predator_type, pool_label, dice_pool, difficulty, hunger_before, outcome, status, cycle_index, hunger_delta, safety_delta)
       VALUES (?, 39, 'Siren', 'x', 3, 3, 3, 'success', 'resolved', 5, -1, 0)`,
      [gus.characterId]
    );

    const { cycles, current } = JSON.parse((await req('GET', '/api/admin/feeding/cycles', st)).body);
    expect(current).toBe(CYCLE);
    expect(cycles.find((c) => c.cycleIndex === 5)).toMatchObject({ feedings: 1, isCurrent: false });

    const roster = JSON.parse((await req('GET', '/api/admin/feeding/roster?cycle=5', st)).body);
    expect(roster.isCurrent).toBe(false);
    expect(roster.characters.find((c) => c.id === gus.characterId)).toMatchObject({ fed: true, hunts: 1 });
    const log = JSON.parse((await req('GET', '/api/admin/feeding/log?cycle=5', st)).body).log;
    expect(log.map((f) => f.id)).toEqual([ins.insertId]);

    expect((await req('POST', `/api/admin/feeding/character/${gus.characterId}/undo-cycle?cycle=5`, st)).statusCode).toBe(200);
    expect(await hungerOf(gus)).toBe(3);
    expect(JSON.parse((await req('GET', '/api/admin/feeding/log?cycle=5', st)).body).log).toHaveLength(0);
  });
});
