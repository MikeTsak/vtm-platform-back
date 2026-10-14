// tests/characterRetirement.test.js — one account, several characters over
// time (migration 0057, services/characterRetirement.js): a dead character is
// retired when its player creates the next one, stays readable to them, and
// a Storyteller can restore it.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser, extractSessionCookie } = require('./setup/helpers');

let pool, app, player, other, admin, firstId;

const req = (who, method, url, payload) =>
  app.inject({ method, url, payload, headers: { cookie: who.cookie } });

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  player = await registerUser(app);
  other = await registerUser(app);
  admin = await registerUser(app);
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = extractSessionCookie(login);

  const [r] = await pool.query("INSERT INTO characters (user_id, name, clan, xp) VALUES (?, 'Marcus', 'Ventrue', 50)", [player.user.id]);
  firstId = r.insertId;
  await pool.query("UPDATE users SET avatar_url='https://cdn/marcus.webp', avatar_url_thumb='https://cdn/marcus_t.webp' WHERE id=?", [player.user.id]);
  const [co] = await pool.query("INSERT INTO coteries (name, created_by) VALUES ('Night Watch', ?)", [player.user.id]);
  await pool.query('INSERT INTO coterie_members (coterie_id, user_id, character_id) VALUES (?, ?, ?)', [co.insertId, player.user.id, firstId]);
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

const newChar = { name: 'Elena', clan: 'Toreador', sheet: {} };

it('refuses a second character while the current one lives', async () => {
  expect((await req(player, 'POST', '/api/characters', newChar)).statusCode).toBe(409);
});

it('retires a deceased character when the player creates the next one', async () => {
  await pool.query('UPDATE characters SET is_deceased=1 WHERE id=?', [firstId]);
  const res = await req(player, 'POST', '/api/characters', newChar);
  expect(res.statusCode).toBe(200);
  expect(res.json().character.name).toBe('Elena');

  const [[old]] = await pool.query('SELECT user_id, retired_user_id, retired_at FROM characters WHERE id=?', [firstId]);
  expect(old.user_id).toBeNull();
  expect(old.retired_user_id).toBe(player.user.id);
  expect(old.retired_at).not.toBeNull();
  // Marcus keeps his portrait; Elena starts without one.
  const [[saved]] = await pool.query('SELECT avatar_url, avatar_url_thumb FROM characters WHERE id=?', [firstId]);
  expect(saved).toEqual({ avatar_url: 'https://cdn/marcus.webp', avatar_url_thumb: 'https://cdn/marcus_t.webp' });
  const [[acct]] = await pool.query('SELECT avatar_url FROM users WHERE id=?', [player.user.id]);
  expect(acct.avatar_url).toBeNull();
  // The dead character's coterie seat does not pass to the new one.
  const [members] = await pool.query('SELECT 1 FROM coterie_members WHERE user_id=?', [player.user.id]);
  expect(members).toHaveLength(0);

  expect((await req(player, 'GET', '/api/characters/me')).json().character.name).toBe('Elena');
  const mine = (await req(player, 'GET', '/api/characters/mine')).json().characters;
  expect(mine.map(c => [c.name, !!c.is_current])).toEqual([['Elena', true], ['Marcus', false]]);
});

it('lets only the owner read a retired sheet', async () => {
  expect((await req(player, 'GET', `/api/characters/archive/${firstId}`)).json().character.name).toBe('Marcus');
  expect((await req(other, 'GET', `/api/characters/archive/${firstId}`)).statusCode).toBe(404);
});

it('lets a Storyteller restore it, retiring the current one', async () => {
  expect((await req(player, 'POST', `/api/admin/characters/${firstId}/restore`)).statusCode).toBe(403);
  expect((await req(admin, 'POST', `/api/admin/characters/${firstId}/restore`)).statusCode).toBe(200);
  const me = (await req(player, 'GET', '/api/characters/me')).json().character;
  expect(me.id).toBe(firstId);
  expect(me.is_deceased).toBe(0);
  // His portrait is the account's again, and is no longer stored on him.
  expect(me.avatar_url).toBeNull();
  const [[acct]] = await pool.query('SELECT avatar_url FROM users WHERE id=?', [player.user.id]);
  expect(acct.avatar_url).toBe('https://cdn/marcus.webp');
  const retired = (await req(admin, 'GET', '/api/admin/characters?retired=1')).json().characters;
  expect(retired.map(c => c.name)).toEqual(['Elena']);
  // The current roster leaves retired characters out.
  const roster = (await req(admin, 'GET', '/api/admin/characters')).json().characters;
  expect(roster.map(c => c.name)).toEqual(['Marcus']);
});

it('lets a Storyteller retire a living character', async () => {
  expect((await req(admin, 'POST', `/api/admin/characters/${firstId}/retire`)).statusCode).toBe(200);
  expect((await req(player, 'GET', '/api/characters/me')).json().character).toBeNull();
  expect((await req(admin, 'POST', `/api/admin/characters/${firstId}/retire`)).statusCode).toBe(404);
});
