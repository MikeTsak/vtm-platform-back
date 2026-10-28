// tests/downtimeReleaseNow.test.js - Mass Downtime Release Now endpoint tests
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app, player, admin, characterId, downtimeId;
const json = (res) => JSON.parse(res.body);

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();

  player = await registerUser(app, { displayName: 'Player Downtime' });
  admin = await registerUser(app, { displayName: 'Storyteller Admin' });
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = login.cookies.map(c => `${c.name}=${c.value}`).join('; ');

  const [cRes] = await pool.query(
    "INSERT INTO characters (user_id, name, clan, xp) VALUES (?, 'Vladislav', 'Brujah', 0)",
    [player.user.id]
  );
  characterId = cRes.insertId;

  const [dtRes] = await pool.query(
    "INSERT INTO downtimes (character_id, title, body, status, gm_resolution, is_released) VALUES (?, 'Action Release Test', 'Details', 'approved', 'You succeeded', 0)",
    [characterId]
  );
  downtimeId = dtRes.insertId;
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

test('non-admin is rejected from POST /api/admin/downtimes/release-now', async () => {
  const playerLogin = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: player.email, password: player.password } });
  const playerCookie = playerLogin.cookies.map(c => `${c.name}=${c.value}`).join('; ');

  const res = await app.inject({
    method: 'POST',
    url: '/api/admin/downtimes/release-now',
    headers: { cookie: playerCookie }
  });

  expect([401, 403]).toContain(res.statusCode);
});

test('admin can trigger POST /api/admin/downtimes/release-now and it releases downtimes', async () => {
  // Check downtime is initially unreleased
  const [[beforeRow]] = await pool.query('SELECT is_released FROM downtimes WHERE id=?', [downtimeId]);
  expect(beforeRow.is_released).toBe(0);

  const res = await app.inject({
    method: 'POST',
    url: '/api/admin/downtimes/release-now',
    headers: { cookie: admin.cookie }
  });

  expect(res.statusCode).toBe(200);
  const data = json(res);
  expect(data.ok).toBe(true);
  expect(data.releasedCount).toBeGreaterThanOrEqual(1);

  // Check downtime is now released in db
  const [[afterRow]] = await pool.query('SELECT is_released FROM downtimes WHERE id=?', [downtimeId]);
  expect(afterRow.is_released).toBe(1);

  // Check app_settings updated
  const [[dateRow]] = await pool.query("SELECT setting_value FROM app_settings WHERE setting_key = 'downtime_mass_release_date'");
  expect(dateRow?.setting_value).toBeTruthy();

  const [[notifiedRow]] = await pool.query("SELECT setting_value FROM app_settings WHERE setting_key = 'downtime_mass_release_notified'");
  expect(notifiedRow?.setting_value).toBe('true');
});
