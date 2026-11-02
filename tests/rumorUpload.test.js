// back/tests/rumorUpload.test.js — players attach pictures to rumors through
// /api/news/upload: anyone who may post a rumor (an active character) may upload;
// a player without one still may not (2026-11-02: active players got 403).
const { setupTestDatabase, getTestPool, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app, active, inactive;

// A multipart body with no file in it: past the permission check the route answers 400.
const emptyUpload = (who) => app.inject({
  method: 'POST', url: '/api/news/upload',
  headers: { cookie: who.cookie, 'content-type': 'multipart/form-data; boundary=X' },
  payload: '--X\r\nContent-Disposition: form-data; name="note"\r\n\r\nhi\r\n--X--\r\n',
});

beforeAll(async () => {
  await setupTestDatabase();
  pool = getTestPool();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  active = await registerUser(app, { displayName: 'Whisperer' });
  inactive = await registerUser(app, { displayName: 'Newcomer' });
  await pool.query('INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?,?,?,0,?), (?,?,?,0,?)', [
    active.user.id, 'Whisperer', 'Nosferatu', JSON.stringify({ is_active: true }),
    inactive.user.id, 'Newcomer', 'Toreador', JSON.stringify({ is_active: false }),
  ]);
});
afterAll(async () => { if (app) await app.close(); });

describe('rumor picture upload', () => {
  it('lets a player with an active character upload', async () => {
    expect((await emptyUpload(active)).statusCode).toBe(400);
  });

  it('still refuses a player without an active character or news permission', async () => {
    expect((await emptyUpload(inactive)).statusCode).toBe(403);
  });
});
