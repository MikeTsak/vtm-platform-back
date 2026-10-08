// tests/newsReads.test.js — logged-in readers of a public news article are
// recorded (once per user, counting reopens); anonymous visitors are not.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app, player, admin, newsId;

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  player = await registerUser(app, { displayName: 'Reader' });
  admin = await registerUser(app, { displayName: 'Boss' });
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = login.cookies.map(c => `${c.name}=${c.value}`).join('; ');
  const [r] = await pool.query("INSERT INTO news_entries (author_id, type, title, body, theme) VALUES (?, 'news', 'T', 'B', 'ERT')", [admin.user.id]);
  newsId = r.insertId;
});

afterAll(async () => { await app.close(); await teardownTestDatabase(); });

test('records logged-in reads, ignores anonymous and admins', async () => {
  const url = `/api/news/public/${newsId}`;
  await app.inject({ method: 'GET', url });
  await app.inject({ method: 'GET', url, headers: { cookie: admin.cookie } });
  await app.inject({ method: 'GET', url, headers: { cookie: player.cookie } });
  await app.inject({ method: 'GET', url, headers: { cookie: player.cookie } });
  await new Promise(r => setTimeout(r, 100)); // read is recorded fire-and-forget

  const res = await app.inject({ method: 'GET', url: `/api/admin/news/${newsId}/reads`, headers: { cookie: admin.cookie } });
  const { readers } = JSON.parse(res.body);
  expect(readers).toHaveLength(1);
  expect(readers[0].user_id).toBe(player.user.id);
  expect(readers[0].open_count).toBe(2);

  const denied = await app.inject({ method: 'GET', url: `/api/admin/news/${newsId}/reads`, headers: { cookie: player.cookie } });
  expect(denied.statusCode).toBe(403);
});
