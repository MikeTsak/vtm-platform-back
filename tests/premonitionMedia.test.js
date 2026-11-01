// tests/premonitionMedia.test.js — GET /api/premonitions/media/:id must only
// serve a vision to its recipients (or an admin). Media ids are sequential, so
// the route used to let anyone walk through every player's private premonitions.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser, extractSessionCookie } = require('./setup/helpers');

let pool, app, recipient, intruder, admin, mediaId, premId;

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();

  recipient = await registerUser(app);
  intruder = await registerUser(app);
  admin = await registerUser(app);
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = extractSessionCookie(login);

  const [m] = await pool.query("INSERT INTO premonition_media (mime, size, data) VALUES ('image/png', 3, 'abc')");
  mediaId = m.insertId;
  const [p] = await pool.query(
    "INSERT INTO premonitions (sender_id, content_type, content_url) VALUES (?, 'image', ?)",
    [admin.user.id, `/api/premonitions/media/${mediaId}`]
  );
  premId = p.insertId;
  await pool.query('INSERT INTO premonition_recipients (premonition_id, user_id) VALUES (?, ?)', [premId, recipient.user.id]);
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

const get = (who, id = mediaId) =>
  app.inject({ method: 'GET', url: `/api/premonitions/media/${id}`, headers: who ? { cookie: who.cookie } : {} });

describe('GET /api/premonitions/media/:id', () => {
  it('requires a session', async () => {
    expect((await get(null)).statusCode).toBe(401);
  });

  it('hides another player\'s vision behind a 404', async () => {
    expect((await get(intruder)).statusCode).toBe(404);
    expect((await get(intruder, premId)).statusCode).toBe(404);
  });

  it('serves the recipient and the admin', async () => {
    const res = await get(recipient);
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('abc');
    expect((await get(admin)).statusCode).toBe(200);
  });
});
