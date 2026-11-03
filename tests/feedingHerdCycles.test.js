// tests/feedingHerdCycles.test.js — Herd with the new hunt rules and the
// downtime cycles: a Herd feed unlocks downtime actions without using a hunt,
// repeats until the pool is empty, stops once Hunger can't drop further, and
// regains 1 point when the cycle turns over (once). Plus Mending from the
// Feeding page's status data.
const { buildTestApp } = require('./setup/testApp');
const { setupTestDatabase, getTestPool, truncateAll } = require('./setup/testDb');
const { registerUser, extractSessionCookie } = require('./setup/helpers');
const { setSetting, clearSettingCache } = require('../utils/settings');
const { parseSheet } = require('../utils/sheet');
const { runHerdRegen, runSafetyRecovery } = require('../services/feedingCycleEnd');

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

    const first = await runHerdRegen(pool);
    expect(first.completedCycle).toBe(6);
    expect((await sheetOf()).herd_current).toBe(1);

    expect((await runHerdRegen(pool)).skipped).toBe('already processed');
    expect((await sheetOf()).herd_current).toBe(1);
  });

  // 2026-11-02: a boot during a connection storm read the latch as "never ran" and decayed twice.
  it('fails instead of regrowing again when the latch cannot be read', async () => {
    const db = require('../db');
    const real = db.query.bind(db);
    clearSettingCache();
    const spy = vi.spyOn(db, 'query').mockImplementation((sql, params) => (
      Array.isArray(params) && params[0] === 'feeding_last_decay_cycle_index'
        ? Promise.reject(new Error('max_user_connections')) : real(sql, params)));
    try {
      await expect(runHerdRegen(pool)).rejects.toThrow('max_user_connections');
    } finally {
      spy.mockRestore();
    }
    expect((await sheetOf()).herd_current).toBe(1);
  });
});

// Safety never drops on its own: only failed hunts (or a Storyteller) lower it,
// and 3 months without a failed hunt give +1, up to 10.
describe('Domain Safety recovery', () => {
  const D = 70;
  const safety = async () => (await pool.query('SELECT safety_rating FROM domain_claims WHERE division=?', [D]))[0][0].safety_rating;
  const failedHunt = (resolvedAgo) => pool.query(
    `INSERT INTO feedings (character_id, division, predator_type, pool_label, dice_pool, difficulty, hunger_before,
       normal_dice, hunger_dice, outcome, status, cycle_index, hunger_delta, safety_delta, resolved_at)
     VALUES (?, ?, 'Alleycat', 'x', 1, 2, 2, '[]', '[]', 'failure', 'resolved', 0, 0, -1, NOW() - INTERVAL ${resolvedAgo})`,
    [player.characterId, D]
  );
  beforeEach(async () => {
    await pool.query('DELETE FROM feedings WHERE division=?', [D]);
    await pool.query('DELETE FROM domain_claims WHERE division=?', [D]);
  });

  it('does not touch a quiet division before 3 months, then gives +1 once', async () => {
    await pool.query("INSERT INTO domain_claims (division, color, safety_rating, safety_recovered_at) VALUES (?, '#888888', 6, NOW() - INTERVAL 2 MONTH)", [D]);
    await runSafetyRecovery(pool);
    expect(await safety()).toBe(6);

    await pool.query('UPDATE domain_claims SET safety_recovered_at = NOW() - INTERVAL 3 MONTH - INTERVAL 1 DAY WHERE division=?', [D]);
    await runSafetyRecovery(pool);
    await runSafetyRecovery(pool); // the clock restarted: no second point
    expect(await safety()).toBe(7);
  });

  it('a failed hunt in the last 3 months holds it; once 3 months old, it recovers', async () => {
    await pool.query("INSERT INTO domain_claims (division, color, safety_rating, safety_recovered_at) VALUES (?, '#888888', 4, NOW() - INTERVAL 1 YEAR)", [D]);
    await failedHunt('1 MONTH');
    await runSafetyRecovery(pool);
    expect(await safety()).toBe(4);

    await pool.query('DELETE FROM feedings WHERE division=?', [D]);
    await failedHunt('4 MONTH');
    await runSafetyRecovery(pool);
    expect(await safety()).toBe(5);
  });

  it('never goes above 10', async () => {
    await pool.query("INSERT INTO domain_claims (division, color, safety_rating, safety_recovered_at) VALUES (?, '#888888', 10, NOW() - INTERVAL 1 YEAR)", [D]);
    await runSafetyRecovery(pool);
    expect(await safety()).toBe(10);
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

describe('Safety before a hunt', () => {
  it('is stored when the hunt is accepted, so the admin tab shows before -> after -> now', async () => {
    await pool.query('DELETE FROM feedings WHERE character_id=?', [player.characterId]);
    await setSheet({ hunger: 3, predator_type: 'Alleycat', attributes: { Strength: 2 }, skills: { Brawl: 2 } });
    await pool.query('DELETE FROM domain_claims WHERE division=39');
    await pool.query("INSERT INTO domain_claims (division, owner_name, color, safety_rating) VALUES (39, NULL, '#888888', 6)");

    const roll = JSON.parse((await req('POST', '/api/feeding/roll', { division: 39, poolIndex: 0 })).body);
    expect((await req('POST', `/api/feeding/${roll.feeding.id}/confirm`)).statusCode).toBe(200);
    const [[f]] = await pool.query('SELECT safety_before, safety_delta FROM feedings WHERE id=?', [roll.feeding.id]);
    expect(f.safety_before).toBe(6);
    const [[claim]] = await pool.query('SELECT safety_rating FROM domain_claims WHERE division=39');
    expect(claim.safety_rating).toBe(Math.max(0, Math.min(10, 6 + f.safety_delta)));
  });
});

// 2026-11-03: a Roadside Killer's Herd is saved as "Herd (migrating)" (no id)
// and the exact-name match said "You do not have the Herd background"; and a
// deactivated (not yet activated) character got that same misleading answer.
// A fresh player with one character, for the blocks below.
const asNew = async (name, sheet, columns = {}) => {
  const u = await registerUser(app, { displayName: name });
  await pool.query('INSERT INTO characters SET ?', [{ user_id: u.user.id, name, clan: 'Brujah', xp: 0, sheet: JSON.stringify(sheet), ...columns }]);
  const call = (method, url, payload) => app.inject({ method, url, headers: { cookie: u.cookie }, payload });
  return { ...u, call, status: async () => JSON.parse((await call('GET', '/api/feeding/status')).body) };
};

describe('Herd names and deactivated characters', () => {
  const herd = (name) => ({ hunger: 4, predator_type: 'Roadside Killer', advantages: { merits: [{ name, dots: 2 }] } });

  it('a predator-type Herd with a note in its name is still Herd', async () => {
    const p = await asNew('Trucker', herd('Herd (migrating)'));
    expect((await p.status()).herdDots).toBe(2);
    expect((await p.call('POST', '/api/feeding/herd-feed', { division: 39 })).statusCode).toBe(200);
  });

  it('a deactivated character is told so, and nothing is spent', async () => {
    const p = await asNew('Newcomer', { ...herd('Herd'), is_active: false });
    expect((await p.status()).deactivated).toBe(true);
    const res = await p.call('POST', '/api/feeding/herd-feed', { division: 39 });
    expect(res.statusCode).toBe(403);
    expect(JSON.parse(res.body)).toMatchObject({ code: 'deactivated', error: expect.stringMatching(/deactivated/) });
    expect((await p.call('POST', '/api/feeding/roll', { division: 39 })).statusCode).toBe(403);
    expect((await p.status()).herdCurrent).toBe(2);
  });
});

// Scarce blood: Baggers and Graverobbers hunt at the division's difficulty plus
// the Storytellers' extra (Admin > Feeding, 0 to 10, admin only, uncapped total).
describe('Scarce blood (Baggers and Graverobbers)', () => {
  const { huntingDifficulty } = require('../data/huntingDifficulty');
  const hunter = (type) => ({ hunger: 2, predator_type: type, is_active: true, attributes: { Intelligence: 2, Resolve: 2, Charisma: 2 }, skills: { Streetwise: 2, Medicine: 2, Persuasion: 2 } });
  let admin;
  const setExtra = (who, extra) => who.call('POST', '/api/admin/feeding/scarce-blood', { extra });
  const card = async () => JSON.parse((await admin.call('GET', '/api/admin/feeding/stats')).body).scarceBlood;

  beforeAll(async () => {
    admin = await asNew('Scarce ST', {});
    await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
    const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
    const cookie = extractSessionCookie(login);
    admin.call = (method, url, payload) => app.inject({ method, url, headers: { cookie }, payload });
  });
  afterAll(async () => { await setSetting('feeding_scarce_blood_extra', '0'); });

  it('only a Storyteller sets it, as a whole number from 0 to 10', async () => {
    const player = await asNew('Nosy', hunter('Bagger'));
    expect((await setExtra(player, 2)).statusCode).toBe(403);
    for (const bad of [11, -1, '2', 1.5, null]) expect((await setExtra(admin, bad)).statusCode).toBe(400);
    const ok = await setExtra(admin, 3);
    expect([ok.statusCode, JSON.parse(ok.body)]).toEqual([200, { extra: 3 }]);
  });

  it('a Bagger rolls at the division difficulty + the extra; other predators at the division', async () => {
    const base = huntingDifficulty(39);
    const bagger = await asNew('Blood Bank', hunter('Bagger'));
    const siren = await asNew('Singer', hunter('Siren'));
    expect((await bagger.status()).scarceBloodExtra).toBe(3);
    expect((await siren.status()).scarceBloodExtra).toBe(0);
    const roll = async (p) => JSON.parse((await p.call('POST', '/api/feeding/roll', { division: 39 })).body).feeding.difficulty;
    expect(await roll(bagger)).toBe(base + 3);
    expect(await roll(siren)).toBe(base);
  });

  it('counts Baggers and Graverobbers who can hunt, and suggests +1 for each beyond 2', async () => {
    const before = (await card()).count;
    await asNew('Digger 1', hunter('Graverobber'));
    await asNew('Digger 2', hunter('Graverobber'));
    await asNew('Not Yet', { ...hunter('Bagger'), is_active: false }); // deactivated: can't hunt
    await asNew('Gone', hunter('Bagger'), { is_deceased: 1 }); // dead
    const c = await card();
    expect(c).toMatchObject({ count: before + 2, extra: 3, max: 10, types: ['Bagger', 'Graverobber'] });
    expect(c.suggested).toBe(Math.min(10, Math.max(0, c.count - 2)));
  });
});
