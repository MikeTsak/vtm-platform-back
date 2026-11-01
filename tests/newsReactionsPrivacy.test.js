// tests/newsReactionsPrivacy.test.js — the public article page shows reaction
// counts to anonymous visitors; who reacted (user ids, names) is for players only.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app, player, entryId;

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  player = await registerUser(app);
  const [r] = await pool.query("INSERT INTO news_entries (author_id, title, body, type) VALUES (?, 't', 'b', 'news')", [player.user.id]);
  entryId = r.insertId;
  await pool.query("INSERT INTO announcement_reactions (announcement_id, user_id, emoji) VALUES (?, ?, 'fang')", [entryId, player.user.id]);
});

afterAll(async () => {
  await pool.query('DELETE FROM announcement_reactions');
  await pool.query('DELETE FROM news_entries');
  await app.close();
  await teardownTestDatabase();
});

const get = (headers = {}) => app.inject({ method: 'GET', url: `/api/news/${entryId}/reactions`, headers });

describe('GET /api/news/:id/reactions', () => {
  it('gives anonymous visitors counts only', async () => {
    const res = await get();
    expect(res.statusCode).toBe(200);
    const [fang] = JSON.parse(res.body).reactions;
    expect(fang.count).toBe(1);
    expect(fang.users).toEqual([]);
    expect(fang.reactors).toEqual([]);
  });

  it('shows signed-in players who reacted', async () => {
    const [fang] = JSON.parse((await get({ cookie: player.cookie })).body).reactions;
    expect(fang.users).toEqual([player.user.id]);
    expect(fang.reactors).toHaveLength(1);
  });
});
