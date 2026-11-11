// tests/boons.test.js — boons owed by bodies (court, coteries), push to the
// parties on record and transfer, transfers, and orphaned boons after Final Death.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app, harpy, marcus, selene, dorian;

const call = (who, method, url, payload) => app.inject({ method, url, payload, headers: { cookie: who.cookie } });
const body = (res) => JSON.parse(res.body);
const pushedTo = () => app.testPushNotifications.map(p => p.userId).sort();
// Pushes are fire-and-forget after the reply; give them a moment to land.
const settle = () => new Promise(r => setTimeout(r, 150));

async function player(name, { court = false, deceased = false } = {}) {
  const u = await registerUser(app, { displayName: `${name} Account` });
  await pool.query('INSERT INTO characters (user_id, name, clan, xp, is_deceased) VALUES (?, ?, ?, 0, ?)', [u.user.id, name, 'Toreador', deceased ? 1 : 0]);
  if (court) {
    await pool.query("UPDATE users SET role='courtuser' WHERE id=?", [u.user.id]);
    const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: u.email, password: u.password } });
    u.cookie = login.cookies.map(c => `${c.name}=${c.value}`).join('; ');
  }
  return u;
}

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();

  harpy = await player('Livia', { court: true });
  marcus = await player('Marcus');
  selene = await player('Selene');
  dorian = await player('Dorian', { deceased: true });

  const [c] = await pool.query("INSERT INTO coteries (name, created_by) VALUES ('The Night Watch', ?)", [selene.user.id]);
  await pool.query('INSERT INTO coterie_members (coterie_id, user_id) VALUES (?, ?)', [c.insertId, selene.user.id]);
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

beforeEach(() => { app.testPushNotifications.length = 0; });

describe('boons between bodies', () => {
  let boonId;

  it('offers institutions and coteries, flagging the viewer\'s own coterie', async () => {
    const { entities } = body(await call(selene, 'GET', '/api/boons/entities'));
    const names = entities.filter(e => e.type === 'institution').map(e => e.name.split(' (')[0]);
    expect(names).toEqual(expect.arrayContaining(['The Court of Athens', "The Sheriff's Office", 'The Harpies', 'Elysium', 'The Camarilla']));
    // Other suites leave their coteries in the test DB: look ours up by name.
    expect(entities.some(e => e.type === 'coterie' && e.name === 'The Night Watch (Coterie)' && e.mine)).toBe(true);
    expect(entities.some(e => e.type === 'coterie' && e.mine && e.name !== 'The Night Watch (Coterie)')).toBe(false);
    expect(entities.some(e => e.type === 'clan' && e.name === 'Clan Toreador (Clan)')).toBe(true);
  });

  it('pushes a recorded boon to the debtor and every coterie member, not the recorder', async () => {
    const res = await call(harpy, 'POST', '/api/boons', { from_name: 'Marcus', to_name: 'The Night Watch', level: 'minor', status: 'owed' });
    expect(res.statusCode).toBe(201);
    boonId = body(res).boon.id;
    await settle();
    expect(pushedTo()).toEqual([marcus.user.id, selene.user.id].sort());
    expect(app.testPushNotifications[0]).toMatchObject({ category: 'court', body: 'Marcus owes The Night Watch a Minor boon.' });
  });

  it('only the court can transfer', async () => {
    const res = await call(marcus, 'POST', `/api/boons/${boonId}/transfer`, { side: 'to', name: 'Elysium' });
    expect(res.statusCode).toBe(403);
  });

  it('refuses a transfer to the current holder or to the debtor', async () => {
    expect((await call(harpy, 'POST', `/api/boons/${boonId}/transfer`, { side: 'to', name: 'The Night Watch' })).statusCode).toBe(400);
    expect((await call(harpy, 'POST', `/api/boons/${boonId}/transfer`, { side: 'to', name: 'marcus' })).statusCode).toBe(400);
    expect((await call(harpy, 'POST', `/api/boons/${boonId}/transfer`, { side: 'sideways', name: 'Elysium' })).statusCode).toBe(400);
  });

  it('passes the holding on and tells the old holder and the debtor', async () => {
    const res = await call(harpy, 'POST', `/api/boons/${boonId}/transfer`, { side: 'to', name: 'Elysium' });
    expect(res.statusCode).toBe(200);
    expect(body(res).boon).toMatchObject({ from_name: 'Marcus', to_name: 'Elysium' });
    await settle();
    expect(pushedTo()).toEqual([marcus.user.id, selene.user.id].sort());
  });

  it('will not move a settled boon', async () => {
    await call(harpy, 'PATCH', `/api/boons/${boonId}`, { status: 'paid' });
    const res = await call(harpy, 'POST', `/api/boons/${boonId}/transfer`, { side: 'to', name: 'Selene' });
    expect(res.statusCode).toBe(409);
  });
});

describe('orphaned boons', () => {
  it('flags a side that met Final Death until the debt passes to the living', async () => {
    const created = body(await call(harpy, 'POST', '/api/boons', { from_name: 'Dorian', to_name: 'Selene', level: 'major', status: 'owed' })).boon;
    expect(Boolean(created.from_dead)).toBe(true);
    expect(Boolean(created.to_dead)).toBe(false);
    await settle();
    expect(pushedTo()).toEqual([selene.user.id]); // the dead get no pushes

    const res = await call(harpy, 'POST', `/api/boons/${created.id}/transfer`, { side: 'from', name: 'Marcus' });
    expect(body(res).boon).toMatchObject({ from_name: 'Marcus' });
    expect(Boolean(body(res).boon.from_dead)).toBe(false);
  });
});
