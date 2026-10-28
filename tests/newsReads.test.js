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

test('records logged-in reads and tracks public views, ignores admin previews and bots', async () => {
  const url = `/api/news/public/${newsId}`;
  // 1. Anonymous visitor (e.g. from Discord)
  await app.inject({ method: 'GET', url });
  // 2. Admin preview (should not increment views or player reads)
  await app.inject({ method: 'GET', url, headers: { cookie: admin.cookie } });
  // 3. Search crawler bot (should not increment views)
  await app.inject({ method: 'GET', url, headers: { 'user-agent': 'Discordbot/2.0; +https://discordapp.com' } });
  // 4. Logged-in player first visit
  await app.inject({ method: 'GET', url, headers: { cookie: player.cookie } });
  // 5. Logged-in player second visit
  await app.inject({ method: 'GET', url, headers: { cookie: player.cookie } });
  await new Promise(r => setTimeout(r, 100)); // recorded fire-and-forget

  const res = await app.inject({ method: 'GET', url: `/api/admin/news/${newsId}/reads`, headers: { cookie: admin.cookie } });
  const body = JSON.parse(res.body);
  expect(body.readers).toHaveLength(1);
  expect(body.readers[0].user_id).toBe(player.user.id);
  expect(body.readers[0].open_count).toBe(2);
  // Views: 1 anonymous + 2 player visits = 3 total views (admin and bot skipped)
  expect(body.views).toBe(3);

  // Verify admin news list also returns views
  const adminNewsRes = await app.inject({ method: 'GET', url: '/api/admin/news', headers: { cookie: admin.cookie } });
  const adminNews = JSON.parse(adminNewsRes.body);
  const entry = adminNews.items.find(i => i.id === newsId);
  expect(entry).toBeDefined();
  expect(Number(entry.views)).toBe(3);

  const denied = await app.inject({ method: 'GET', url: `/api/admin/news/${newsId}/reads`, headers: { cookie: player.cookie } });
  expect(denied.statusCode).toBe(403);
});
