// tests/commsSwitch.test.js — the admin master switch over HTTP: flipping it
// against the calendar is an override, flipping it back (or "follow the
// calendar") hands control back, and a calendar edit re-anchors the override.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');
const { clearSettingCache } = require('../utils/settings');
const { getAthensDate } = require('../utils/athensTime');

let pool, app, player, admin;
const json = (res) => JSON.parse(res.body);
const as = (who, method, url, payload) => app.inject({ method, url, headers: { cookie: who.cookie }, payload });
const today = getAthensDate(new Date());
const tomorrow = getAthensDate(new Date(Date.now() + 86400000));

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  player = await registerUser(app, { displayName: 'Player' });
  admin = await registerUser(app, { displayName: 'Storyteller' });
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = login.cookies.map(c => `${c.name}=${c.value}`).join('; ');
  await as(admin, 'POST', '/api/admin/comms/schedule', { schedule: { [today]: true, [tomorrow]: false } });
});

afterAll(async () => {
  await pool.query("DELETE FROM app_settings WHERE setting_key IN ('chat_schedule', 'comms_override')");
  clearSettingCache();
  await app.close();
  await teardownTestDatabase();
});

test('the switch shows the calendar when nobody overrides it', async () => {
  const status = json(await as(player, 'GET', '/api/comms/status'));
  expect(status).toMatchObject({ comms_enabled: true, master_enabled: true, calendar_enabled: true, override: null });
  expect(status.next_closing).toMatchObject({ time: '00:01' });
});

test('players cannot flip it; bad input is rejected', async () => {
  expect((await as(player, 'POST', '/api/admin/comms/status', { comms_enabled: false })).statusCode).toBe(403);
  expect((await as(admin, 'POST', '/api/admin/comms/status', { comms_enabled: 'off' })).statusCode).toBe(400);
});

test('emergency OFF lasts until the calendar next changes, then hands back', async () => {
  const off = json(await as(admin, 'POST', '/api/admin/comms/status', { comms_enabled: false }));
  expect(off).toMatchObject({ comms_enabled: false, calendar_enabled: true, override: { state: false } });
  expect(new Date(off.override.until).getTime()).toBeGreaterThan(Date.now());
  expect(json(await as(player, 'GET', '/api/comms/status')).comms_enabled).toBe(false);

  // Flipping it back to what the calendar says is "follow the calendar".
  const back = json(await as(admin, 'POST', '/api/admin/comms/status', { comms_enabled: true }));
  expect(back).toMatchObject({ comms_enabled: true, override: null });
});

test('follow_calendar clears an override; a calendar edit that agrees ends it', async () => {
  await as(admin, 'POST', '/api/admin/comms/status', { comms_enabled: false });
  expect(json(await as(admin, 'POST', '/api/admin/comms/status', { follow_calendar: true }))).toMatchObject({ comms_enabled: true, override: null });

  await as(admin, 'POST', '/api/admin/comms/status', { comms_enabled: false });
  const saved = json(await as(admin, 'POST', '/api/admin/comms/schedule', { schedule: { [today]: false } }));
  expect(saved).toMatchObject({ comms_enabled: false, calendar_enabled: false, override: null });
});
