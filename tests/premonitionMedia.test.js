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

  it('resolves premonitions.id even when premonition_media.id shares the same numeric id', async () => {
    const [[{ nextId }]] = await pool.query(
      'SELECT GREATEST(COALESCE((SELECT MAX(id) FROM premonitions),0), COALESCE((SELECT MAX(id) FROM premonition_media),0)) + 1 AS nextId'
    );
    // Old premonition owning premonition_media.id = nextId (for `recipient` only).
    await pool.query("INSERT INTO premonition_media (id, mime, size, data) VALUES (?, 'image/png', 3, 'xyz')", [nextId]);
    const [oldP] = await pool.query(
      "INSERT INTO premonitions (id, sender_id, content_type, content_url) VALUES (?, ?, 'image', ?)",
      [nextId + 1, admin.user.id, `/api/premonitions/media/${nextId}`]
    );
    await pool.query('INSERT INTO premonition_recipients (premonition_id, user_id) VALUES (?, ?)', [oldP.insertId, recipient.user.id]);

    // New premonition whose premonitions.id collides numerically with nextId (for `otherRecipient`).
    const otherRecipient = await registerUser(app);
    await pool.query(
      "INSERT INTO premonitions (id, sender_id, content_type, content_url) VALUES (?, ?, 'video', 'https://img.miketsak.gr/uploads/sha_colliding.mp4')",
      [nextId, admin.user.id]
    );
    await pool.query('INSERT INTO premonition_recipients (premonition_id, user_id) VALUES (?, ?)', [nextId, otherRecipient.user.id]);

    const resDefault = await app.inject({
      method: 'GET',
      url: `/api/premonitions/media/${nextId}?info=1`,
      headers: { cookie: otherRecipient.cookie },
    });
    expect(resDefault.statusCode).toBe(200);
    expect(resDefault.json().url).toBe('https://img.miketsak.gr/uploads/sha_colliding.mp4');

    const resExplicit = await app.inject({
      method: 'GET',
      url: `/api/premonitions/media/${nextId}?info=1&by=premonition`,
      headers: { cookie: admin.cookie },
    });
    expect(resExplicit.statusCode).toBe(200);
    expect(resExplicit.json().url).toBe('https://img.miketsak.gr/uploads/sha_colliding.mp4');

    const resIntruder = await app.inject({
      method: 'GET',
      url: `/api/premonitions/media/${nextId}?info=1&by=premonition`,
      headers: { cookie: intruder.cookie },
    });
    expect(resIntruder.statusCode).toBe(404);
  });
});
