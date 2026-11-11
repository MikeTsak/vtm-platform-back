// tests/coterieLifecycle.test.js — a member leaving play takes their contributions
// with them; a coterie under the floor goes dormant, wakes at the floor, and
// dissolves at its deadline (services/coterieLifecycle.js).
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');
const { sweepCoteries } = require('../services/coterieLifecycle');

let pool, app, admin, ana, bas, cyr, dea, coterieId;

const call = (who, method, url, payload) => app.inject({ method, url, payload, headers: { cookie: who.cookie } });
const body = (res) => JSON.parse(res.body);
const asObj = (v) => (typeof v === 'string' ? JSON.parse(v) : v);
const row = async (id = coterieId) => (await pool.query('SELECT * FROM coteries WHERE id = ?', [id]))[0][0];
const memberIds = async (id = coterieId) =>
  (await pool.query('SELECT user_id FROM coterie_members WHERE coterie_id = ? ORDER BY user_id', [id]))[0].map((r) => r.user_id);
const logOf = async (kind, id = coterieId) =>
  (await pool.query('SELECT * FROM coterie_xp_log WHERE coterie_id = ? AND kind = ? ORDER BY id', [id, kind]))[0];
const herd = (co) => (asObj(co.backgrounds_json) || []).find((b) => b.key === 'herd')?.dots || 0;

async function player(name, { role = null, sheet = {} } = {}) {
  const u = await registerUser(app, { displayName: `${name} Account` });
  const [c] = await pool.query('INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?, ?, ?, 0, ?)',
    [u.user.id, name, 'Brujah', JSON.stringify(sheet)]);
  u.charId = c.insertId;
  if (role) {
    await pool.query('UPDATE users SET role = ? WHERE id = ?', [role, u.user.id]);
    const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: u.email, password: u.password } });
    u.cookie = login.cookies.map((k) => `${k.name}=${k.value}`).join('; ');
  }
  return u;
}

async function makeCoterie(name, members, extra = {}) {
  const [r] = await pool.query('INSERT INTO coteries (name, created_by, backgrounds_json) VALUES (?, ?, ?)',
    [name, members[0].user.id, JSON.stringify(extra.backgrounds || [])]);
  for (const m of members) {
    await pool.query('INSERT INTO coterie_members (coterie_id, user_id, character_id) VALUES (?, ?, ?)', [r.insertId, m.user.id, m.charId]);
  }
  return r.insertId;
}

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();

  admin = await player('Storyteller', { role: 'admin' });
  ana = await player('Ana', { sheet: { disciplines: { Potence: 2 } } });
  bas = await player('Bas', { sheet: { disciplines: { Celerity: 2 }, backgrounds: [{ id: 'backgrounds_resources__resources', name: 'Resources', dots: 1 }] } });
  cyr = await player('Cyr', { sheet: { backgrounds: [{ id: 'backgrounds_herd__herd', name: 'Herd', dots: 2 }] } });
  dea = await player('Dea');
  coterieId = await makeCoterie('The Ashen Choir', [ana, bas, cyr], { backgrounds: [{ key: 'herd', name: 'Herd', dots: 1 }] });
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

describe('a member leaving play', () => {
  it('a death marked at court removes them and takes back what they contributed', async () => {
    const given = await call(cyr, 'POST', `/api/coteries/${coterieId}/contribute`, { character_entry_id: 'backgrounds_herd__herd' });
    expect(given.statusCode).toBe(200);
    expect(herd(await row())).toBe(3);
    expect((await row()).advancement_dots).toBe(2);

    const died = await call(admin, 'PATCH', '/api/admin/camarilla/update', { id: cyr.charId, type: 'player', field: 'is_deceased', value: true });
    expect(died.statusCode).toBe(200);

    const co = await row();
    expect(await memberIds()).toEqual([ana.user.id, bas.user.id].sort((a, b) => a - b));
    expect(herd(co)).toBe(1);
    expect(co.advancement_dots).toBe(0);
    expect((await logOf('member_left')).at(-1).note).toBe('Cyr met Final Death');
    expect((await logOf('revoked'))[0]).toMatchObject({ target_key: 'herd', from_dots: 3, to_dots: 1 });

    // Two members left: dormant for 60 days, merits untouched otherwise.
    expect(co.status).toBe('dormant');
    const days = (new Date(co.dissolve_at) - Date.now()) / 86400000;
    expect(days).toBeGreaterThan(59.9);
    expect(days).toBeLessThan(60.1);
  });

  it('marking them dead again takes nothing twice', async () => {
    await call(admin, 'PATCH', '/api/admin/camarilla/update', { id: cyr.charId, type: 'player', field: 'is_deceased', value: true });
    expect(herd(await row())).toBe(1);
    expect(await logOf('revoked')).toHaveLength(1);
  });
});

describe('dormancy', () => {
  it('a dormant coterie still shows its merits to its members, and wakes when a third member joins', async () => {
    const seen = body(await call(ana, 'GET', `/api/coteries/${coterieId}`)).coterie;
    expect(seen).toMatchObject({ status: 'dormant' });
    expect(seen.backgrounds.find((b) => b.key === 'herd').dots).toBe(1);

    // Frozen meanwhile: the rules engine refuses contributions below the floor.
    const frozen = await call(bas, 'POST', `/api/coteries/${coterieId}/contribute`, { character_entry_id: 'backgrounds_resources__resources' });
    expect(frozen.statusCode).toBe(400);
    expect(body(frozen).error).toMatch(/At least 3 members/);

    const set = await call(admin, 'POST', `/api/coteries/${coterieId}/members/set`,
      { members: [ana, bas, dea].map((u) => ({ user_id: u.user.id })) });
    expect(set.statusCode).toBe(200);
    expect(await row()).toMatchObject({ status: 'active', dormant_since: null, dissolve_at: null });
  });

  it('only a Storyteller moves the deadline, and only into the future', async () => {
    expect((await call(dea, 'POST', `/api/coteries/${coterieId}/leave`)).statusCode).toBe(200);
    expect((await row()).status).toBe('dormant');

    const later = new Date(Date.now() + 90 * 86400000).toISOString();
    expect((await call(ana, 'PATCH', `/api/coteries/${coterieId}/dissolve-at`, { dissolve_at: later })).statusCode).toBe(403);
    expect((await call(admin, 'PATCH', `/api/coteries/${coterieId}/dissolve-at`, { dissolve_at: '2020-01-01' })).statusCode).toBe(400);
    expect((await call(admin, 'PATCH', `/api/coteries/${coterieId}/dissolve-at`, { dissolve_at: later })).statusCode).toBe(200);
    expect(Math.abs(new Date((await row()).dissolve_at) - new Date(later))).toBeLessThan(1000);
  });
});

describe('the deadline passing', () => {
  let ghoulId, mortalId;

  it('dissolves the coterie: ghouls go home without others\' blood, the rest are released', async () => {
    const ghoul = {
      isGhoul: true,
      disciplines: { Potence: 1, Celerity: 1 },
      powers: [{ discipline: 'Potence', name: 'Lethal Body' }, { discipline: 'Celerity', name: "Cat's Grace" }],
      bloodSources: { Celerity: bas.charId },
    };
    ghoulId = (await pool.query('INSERT INTO retainers (coterie_id, domitor_character_id, name, tier, sheet, xp) VALUES (?, ?, ?, 2, ?, 0)',
      [coterieId, ana.charId, 'Marta', JSON.stringify(ghoul)]))[0].insertId;
    mortalId = (await pool.query('INSERT INTO retainers (coterie_id, name, tier, sheet, xp) VALUES (?, ?, 1, ?, 0)',
      [coterieId, 'Old Yannis', JSON.stringify({ isGhoul: false })]))[0].insertId;
    await pool.query('UPDATE coteries SET domain_id = 7, dissolve_at = NOW() - INTERVAL 1 MINUTE WHERE id = ?', [coterieId]);

    await sweepCoteries(pool);

    expect(await row()).toMatchObject({ status: 'dissolved', domain_id: null });
    expect(await memberIds()).toEqual([]);
    const [[g]] = await pool.query('SELECT * FROM retainers WHERE id = ?', [ghoulId]);
    expect(g).toMatchObject({ coterie_id: null, character_id: ana.charId, domitor_character_id: null });
    expect(asObj(g.sheet).disciplines).toEqual({ Potence: 1 });
    expect(asObj(g.sheet).bloodSources).toBeUndefined();
    expect((await pool.query('SELECT id FROM retainers WHERE id = ?', [mortalId]))[0]).toHaveLength(0);
  });

  it('players no longer see it anywhere', async () => {
    const all = body(await call(ana, 'GET', '/api/coteries/all')).coteries;
    expect(all.some((c) => c.id === coterieId)).toBe(false);
    const { entities } = body(await call(ana, 'GET', '/api/boons/entities'));
    expect(entities.some((e) => e.type === 'coterie' && e.id === coterieId)).toBe(false);
    expect((await call(ana, 'GET', `/api/coteries/${coterieId}`)).statusCode).toBe(403);
  });
});

describe('the coterie job', () => {
  let shortId;

  it('catches members already dead and coteries already short', async () => {
    const [eve, fil, gus] = [await player('Eve'), await player('Fil'), await player('Gus')];
    shortId = await makeCoterie('The Red Inquiry', [eve, fil, gus]);
    // Marked dead some other way: no court hook ran.
    await pool.query('UPDATE characters SET is_deceased = 1 WHERE id = ?', [gus.charId]);

    await sweepCoteries(pool);

    expect(await memberIds(shortId)).toEqual([eve.user.id, fil.user.id].sort((a, b) => a - b));
    expect((await logOf('member_left', shortId))[0].note).toBe('Gus met Final Death');
    expect((await row(shortId)).status).toBe('dormant');
  });

  it('reminds the members once, a week before the deadline', async () => {
    await pool.query('UPDATE coteries SET dissolve_at = NOW() + INTERVAL 3 DAY WHERE id = ?', [shortId]);
    await sweepCoteries(pool);
    await sweepCoteries(pool);
    const reminders = (await logOf('status', shortId)).filter((l) => l.target_type === 'reminder');
    expect(reminders).toHaveLength(1);
    expect((await row(shortId)).status).toBe('dormant');
  });
});
