// tests/feedingHerdCycles.test.js — Herd with the new hunt rules and the
// downtime cycles: a Herd feed unlocks downtime actions without using a hunt,
// repeats until the pool is empty, stops once Hunger can't drop further, and
// regains 1 point when the cycle turns over (once). Plus Mending from the
// Feeding page's status data.
const { buildTestApp } = require('./setup/testApp');
const { setupTestDatabase, getTestPool, truncateAll } = require('./setup/testDb');
const { registerUser, extractSessionCookie } = require('./setup/helpers');
const { setSetting } = require('../utils/settings');
const { parseSheet } = require('../utils/sheet');
const { runFeedingDecay } = require('../services/feedingDecay');

const day = (offset) => new Date(Date.now() + offset * 86400000).toISOString().slice(0, 10);
let app, pool, player;

const req = (method, url, payload) => app.inject({ method, url, headers: { cookie: player.cookie }, payload });
const sheetOf = async () => parseSheet((await pool.query('SELECT sheet FROM characters WHERE id=?', [player.characterId]))[0][0].sheet);
const setSheet = (sheet) => pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), player.characterId]);
const status = async () => JSON.parse((await req('GET', '/api/feeding/status')).body);
const herdFeed = () => req('POST', '/api/feeding/herd-feed', { division: 39 });

beforeAll(async () => {
  await setupTestDatabase();
  pool = getTestPool();
  await truncateAll();
  await pool.query('DELETE FROM feedings');
  app = buildTestApp(pool);
  await app.ready();
  await setSetting('feeding_enabled', 'true');
  await setSetting('downtime_active_phase', 'standard');
  await setSetting('downtime_opening', day(-2));
  await setSetting('downtime_deadline', day(2));
  await setSetting('downtime_cycles_schedule', JSON.stringify([
    { id: 'cycle_6', title: 'Last', opening_date: day(-30), closing_date: day(-10), status: 'closed' },
    { id: 'cycle_7', title: 'Now', opening_date: day(-2), closing_date: day(2), status: 'active' },
  ]));
  const u = await registerUser(app, { displayName: 'Herder' });
  const [r] = await pool.query('INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?,?,?,0,?)', [u.user.id, 'Herder', 'Toreador', '{}']);
  player = { ...u, characterId: r.insertId };
});
afterAll(async () => { if (app) await app.close(); });

describe('Herd across cycles', () => {
  it('unlocks actions, is not a hunt, repeats until the pool is empty', async () => {
    await setSheet({ hunger: 4, predator_type: 'Siren', advantages: { merits: [{ name: 'Herd', dots: 2 }] } });

    expect((await herdFeed()).statusCode).toBe(200);
    let s = await status();
    expect(s.fed).toBe(true);
    expect(s.huntsUsed).toBe(0);
    expect(s.herdCurrent).toBe(1);

    expect((await herdFeed()).statusCode).toBe(200);
    expect((await sheetOf()).hunger).toBe(2);
    expect((await herdFeed()).statusCode).toBe(400); // pool empty

    s = await status();
    expect(s.herdCurrent).toBe(0);
    expect(s.feedings.filter((f) => f.outcome === 'herd')).toHaveLength(2);
  });

  it('refuses a Herd feed that could not lower Hunger once fed', async () => {
    await setSheet({ ...(await sheetOf()), hunger: 1, herd_current: 2 });
    expect((await herdFeed()).statusCode).toBe(400);
    expect((await sheetOf()).herd_current).toBe(2);
  });

  it('regains 1 Herd point when the cycle turns over, only once', async () => {
    await setSheet({ ...(await sheetOf()), herd_current: 0 });
    await setSetting('feeding_last_decay_cycle_index', '5');

    const first = await runFeedingDecay(pool, null);
    expect(first.completedCycle).toBe(6);
    expect((await sheetOf()).herd_current).toBe(1);

    expect((await runFeedingDecay(pool, null)).skipped).toBe('already processed');
    expect((await sheetOf()).herd_current).toBe(1);
  });
});

describe('Mending from the Feeding page', () => {
  it('reports health and heals Superficial for one Rouse Check', async () => {
    await setSheet({ hunger: 2, blood_potency: 1, attributes: { Stamina: 2 }, health: { superficial: 2, aggravated: 1 } });
    const s = await status();
    expect(s.health).toEqual({ superficial: 2, aggravated: 1, max: 5 });
    expect(s.mendAmount).toBe(1);

    const res = JSON.parse((await req('POST', `/api/characters/${s.characterId}/mend`, { type: 'superficial' })).body);
    expect(res.healed).toBe(1);
    const after = await sheetOf();
    expect(after.health.superficial).toBe(1);
    expect(after.hunger).toBe(res.rolls[0].success ? 2 : 3);
  });
});

describe('Safe feeding paid with a downtime action', () => {
  it('lowers Hunger by 2, unlocks actions, uses a slot (not a hunt), and the ST undo returns the slot', async () => {
    await pool.query('DELETE FROM feedings WHERE character_id=?', [player.characterId]);
    await pool.query('DELETE FROM downtimes WHERE character_id=?', [player.characterId]);
    await setSheet({ hunger: 4, predator_type: 'Siren' });
    expect((await status()).safeFeedBlock).toBeNull();

    const res = await req('POST', '/api/feeding/downtime-feed');
    expect(res.statusCode).toBe(200);
    expect((await sheetOf()).hunger).toBe(2);
    const s = await status();
    expect(s.fed).toBe(true);
    expect(s.huntsUsed).toBe(0);
    const [[dt]] = await pool.query("SELECT status, is_released FROM downtimes WHERE character_id=? AND title='[Feeding] Safe feeding'", [player.characterId]);
    expect(dt).toMatchObject({ status: 'resolved', is_released: 1 });

    // Two more actions fill the cycle's 3: no slot left for another safe feeding.
    await pool.query("INSERT INTO downtimes (character_id, title, body) VALUES (?, 'a', 'x'), (?, 'b', 'x')", [player.characterId, player.characterId]);
    expect((await req('POST', '/api/feeding/downtime-feed')).statusCode).toBe(400);
    expect((await status()).safeFeedBlock).toMatch(/limit/i);

    const st = await registerUser(app, { displayName: 'ST' });
    await pool.query('UPDATE users SET role="admin" WHERE id=?', [st.user.id]);
    const cookie = extractSessionCookie(await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: st.email, password: st.password } }));
    const [[feeding]] = await pool.query("SELECT id FROM feedings WHERE character_id=? AND outcome='downtime'", [player.characterId]);
    expect((await app.inject({ method: 'POST', url: `/api/admin/feeding/${feeding.id}/allow-reroll`, headers: { cookie } })).statusCode).toBe(200);
    expect((await sheetOf()).hunger).toBe(4);
    const [left] = await pool.query("SELECT id FROM downtimes WHERE character_id=? AND title='[Feeding] Safe feeding'", [player.characterId]);
    expect(left).toHaveLength(0);
  });
});

describe('Vitals on top of the Feeding page', () => {
  it('always come back, even with the Feeding system switched off', async () => {
    await setSheet({ hunger: 3, attributes: { Composure: 2, Resolve: 3 }, willpower: { superficial: 1, aggravated: 0 } });
    await setSetting('feeding_enabled', 'false');
    try {
      const s = await status();
      expect(s.enabled).toBe(false);
      expect(s.hunger).toBe(3);
      expect(s.willpower).toEqual({ superficial: 1, aggravated: 0, max: 5 });
      expect(s.health.max).toBe(4);
    } finally {
      await setSetting('feeding_enabled', 'true');
    }
  });
});
