// tests/anonymousNotes.test.js — anonymous notes: admin-only sending, sanitised
// storage, double-send guard, per-player read state, and the read receipt that
// goes out to subscribed admins (but not for a debug-login session).
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app, player, other, admin;
const json = (res) => JSON.parse(res.body);
const send = (payload, who = admin) => app.inject({ method: 'POST', url: '/api/admin/notes', headers: { cookie: who.cookie }, payload });

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  player = await registerUser(app, { displayName: 'Reader' });
  other = await registerUser(app, { displayName: 'Bystander' });
  admin = await registerUser(app, { displayName: 'Boss' });
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = login.cookies.map(c => `${c.name}=${c.value}`).join('; ');
});

afterAll(async () => { await app.close(); await teardownTestDatabase(); });

test('players cannot send; bad input is rejected', async () => {
  expect((await send({ user_ids: [other.user.id], body: 'hi' }, player)).statusCode).toBe(403);
  expect((await send({ user_ids: [], body: 'hi' })).statusCode).toBe(400);
  expect((await send({ user_ids: [player.user.id], body: '<p> </p>' })).statusCode).toBe(400);
  expect((await send({ user_ids: [999999], body: 'hi' })).statusCode).toBe(400);
  expect((await send({ user_ids: [player.user.id], images: ['javascript:alert(1)'] })).statusCode).toBe(400);
});

test('send sanitises, dedupes a repeat, and only the recipient sees it', async () => {
  const payload = { user_ids: [player.user.id], body: '<p>boo</p><script>alert(1)</script>' };
  expect(json(await send(payload)).count).toBe(1);
  expect(json(await send(payload))).toMatchObject({ count: 0, duplicates: 1 }); // double-click

  const mine = json(await app.inject({ method: 'GET', url: '/api/notes/mine', headers: { cookie: player.cookie } })).notes;
  expect(mine).toHaveLength(1);
  expect(mine[0].body).toBe('<p>boo</p>');
  expect(mine[0]).not.toHaveProperty('sender_id');
  expect(json(await app.inject({ method: 'GET', url: '/api/notes/mine', headers: { cookie: other.cookie } })).notes).toHaveLength(0);
  expect(json(await app.inject({ method: 'GET', url: '/api/notes/summary', headers: { cookie: player.cookie } }))).toEqual({ total: 1, unread: 1 });
});

test('read receipt fires once, only for the owner', async () => {
  const [{ id }] = json(await app.inject({ method: 'GET', url: '/api/notes/mine', headers: { cookie: player.cookie } })).notes;
  const read = (who) => app.inject({ method: 'POST', url: `/api/notes/${id}/read`, headers: { cookie: who.cookie } });

  await read(other); // not theirs
  expect(app.testNtfyAlerts).toHaveLength(0);
  await read(player);
  await read(player); // reopen
  await new Promise(r => setTimeout(r, 100)); // receipt is fire-and-forget
  expect(app.testNtfyAlerts).toHaveLength(1);
  expect(app.testNtfyAlerts[0].options.requiresSubscription).toBe('notes');
  expect(app.testNtfyAlerts[0].message).toContain('sent by **Boss**');

  const adminList = json(await app.inject({ method: 'GET', url: '/api/admin/notes', headers: { cookie: admin.cookie } })).notes;
  expect(adminList[0].read_at).toBeTruthy();
  expect(adminList[0].sender_name).toBe('Boss');
  expect((await app.inject({ method: 'GET', url: '/api/admin/notes', headers: { cookie: player.cookie } })).statusCode).toBe(403);
});
