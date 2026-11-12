// tests/printTool.test.js — the admin print tool: items by kind and period,
// anonymity kept, admin only, and pictures only from the image host.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app, admin, player;

const call = (who, url) => app.inject({ method: 'GET', url, headers: { cookie: who.cookie } });
const body = (res) => JSON.parse(res.body);

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  for (const t of ['rumors', 'news_entries', 'boons']) await pool.query(`DELETE FROM ${t}`);
  app = buildTestApp(pool);
  await app.ready();

  player = await registerUser(app, { displayName: 'Player' });
  admin = await registerUser(app, { displayName: 'Storyteller' });
  await pool.query("UPDATE users SET role = 'admin' WHERE id = ?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = login.cookies.map((c) => `${c.name}=${c.value}`).join('; ');

  await pool.query(
    "INSERT INTO rumors (author_id, title, body, created_at) VALUES (?, 'Old whisper', 'x', '2026-09-01 20:00:00'), (?, 'New whisper', 'y', '2026-11-05 20:00:00')",
    [player.user.id, player.user.id]
  );
  await pool.query(
    `INSERT INTO news_entries (author_id, type, title, body, theme, journalist_name, is_private, created_at) VALUES
       (?, 'news', 'Fire at the port', 'b', 'Neutral', 'A. Reporter', 0, '2026-11-06 10:00:00'),
       (?, 'news', 'Secret draft', 'b', 'Neutral', NULL, 1, '2026-11-06 11:00:00'),
       (?, 'announcement', 'Elysium is closed', 'b', 'Neutral', NULL, 0, '2026-11-07 10:00:00')`,
    [player.user.id, player.user.id, admin.user.id]
  );
  await pool.query(
    "INSERT INTO boons (from_name, to_name, boon_level, level, status, date_incurred, created_at) VALUES ('Marcus', 'Livia', 'Minor', 'minor', 'Owed', '2026-11-08', '2026-11-08 12:00:00')"
  );
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

describe('print items', () => {
  it('lists each kind asked for, oldest first, skipping private articles', async () => {
    const { items } = body(await call(admin, '/api/admin/print/items?kinds=rumors,news,decrees,boons'));
    expect(items.map((i) => `${i.kind}:${i.title || i.to_name}`)).toEqual([
      'rumor:Old whisper', 'rumor:New whisper', 'news:Fire at the port', 'decree:Elysium is closed', 'boon:Livia',
    ]);
    expect(items[4]).toMatchObject({ from_name: 'Marcus', level: 'minor', status: 'owed' });
  });

  it('keeps rumours and articles anonymous', async () => {
    const { items } = body(await call(admin, '/api/admin/print/items?kinds=rumors,news'));
    for (const i of items) expect(i).not.toHaveProperty('author_id');
    expect(items.find((i) => i.kind === 'news')).toMatchObject({ journalist_name: 'A. Reporter' });
    expect(items.find((i) => i.kind === 'news')).not.toHaveProperty('author_name');
  });

  it('filters by period', async () => {
    const { items } = body(await call(admin, '/api/admin/print/items?kinds=rumors&from=2026-11-01T00:00:00Z&to=2026-11-30T23:59:59Z'));
    expect(items.map((i) => i.title)).toEqual(['New whisper']);
  });

  it('is for admins only, and refuses nonsense', async () => {
    expect((await call(player, '/api/admin/print/items?kinds=rumors')).statusCode).toBe(403);
    expect((await call(admin, '/api/admin/print/items?kinds=gossip')).statusCode).toBe(400);
    expect((await call(admin, '/api/admin/print/items?kinds=rumors&from=yesterday')).statusCode).toBe(400);
  });
});

describe('thermal pictures', () => {
  it('fetches nothing outside the image host', async () => {
    for (const src of ['http://127.0.0.1:3306/', 'https://example.com/a.png', 'http://img.miketsak.gr/a.png', 'file:///etc/passwd']) {
      const res = await call(admin, `/api/admin/print/dither?src=${encodeURIComponent(src)}`);
      expect(res.statusCode).toBe(400);
    }
    expect((await call(player, '/api/admin/print/dither?src=x')).statusCode).toBe(403);
  });
});
