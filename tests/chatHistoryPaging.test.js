// tests/chatHistoryPaging.test.js — SchreckNet loads a DM's history in pages
// as the user scrolls up, jumps to old messages with ?from=, and keeps shared
// conversation settings. Guards the paging cursor and the settings access rule.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool;
let app;

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

describe('DM history paging + conversation settings', () => {
  it('pages older messages without gaps or overlap, and jumps with ?from', async () => {
    const a = await registerUser(app);
    const b = await registerUser(app);
    // 12 messages; several share a timestamp so the id tie-break is exercised.
    for (let i = 0; i < 12; i++) {
      await pool.query(
        'INSERT INTO chat_messages (sender_id, recipient_id, body, created_at) VALUES (?, ?, ?, ?)',
        [i % 2 ? a.user.id : b.user.id, i % 2 ? b.user.id : a.user.id, `m${i}`, `2026-01-01 00:00:0${Math.floor(i / 3)}`]
      );
    }
    const get = async (qs) => JSON.parse((await app.inject({
      method: 'GET', url: `/api/chat/history/${b.user.id}?${qs}`, headers: { cookie: a.cookie },
    })).body);

    const latest = await get('limit=5');
    expect(latest.messages.map(m => m.body)).toEqual(['m7', 'm8', 'm9', 'm10', 'm11']);
    expect(latest.has_more).toBe(true);

    const older = await get(`limit=5&before=${latest.messages[0].id}`);
    expect(older.messages.map(m => m.body)).toEqual(['m2', 'm3', 'm4', 'm5', 'm6']);

    const oldest = await get(`limit=5&before=${older.messages[0].id}`);
    expect(oldest.messages.map(m => m.body)).toEqual(['m0', 'm1']);
    expect(oldest.has_more).toBe(false);

    // Jump: everything from m3 up to the oldest loaded message (m7).
    const m3 = older.messages.find(m => m.body === 'm3');
    const jump = await get(`from=${m3.id}&before=${latest.messages[0].id}`);
    expect(jump.messages.map(m => m.body)).toEqual(['m3', 'm4', 'm5', 'm6']);
  });

  it('shares theme/emoji between both sides and rejects outsiders of a group', async () => {
    const a = await registerUser(app);
    const b = await registerUser(app);
    const put = (who, payload) => app.inject({ method: 'PUT', url: '/api/chat/settings', headers: { cookie: who.cookie }, payload });

    expect((await put(a, { kind: 'user', id: b.user.id, theme: 'Toreador', emoji: '🔥' })).statusCode).toBe(200);
    const seenByB = JSON.parse((await app.inject({
      method: 'GET', url: `/api/chat/history/${a.user.id}?limit=5`, headers: { cookie: b.cookie },
    })).body);
    expect(seenByB.settings).toEqual({ theme: 'Toreador', emoji: '🔥' });
    expect(seenByB.messages.map(m => ({ body: m.body, type: m.type }))).toEqual([
      { body: `${a.user.display_name} changed the theme to Toreador`, type: 'system' },
      { body: `${a.user.display_name} set the conversation emoji to 🔥`, type: 'system' }
    ]);

    expect((await put(a, { kind: 'user', id: b.user.id, theme: '<script>' })).statusCode).toBe(400);

    const [g] = await pool.query('INSERT INTO chat_groups (name, created_by) VALUES (?, ?)', ['Coterie', a.user.id]);
    await pool.query('INSERT INTO chat_group_members (group_id, user_id) VALUES (?, ?)', [g.insertId, a.user.id]);
    expect((await put(b, { kind: 'group', id: g.insertId, theme: 'Brujah' })).statusCode).toBe(403);
    expect((await put(a, { kind: 'group', id: g.insertId, theme: 'Brujah' })).statusCode).toBe(200);

    const groupHistory = JSON.parse((await app.inject({
      method: 'GET', url: `/api/chat/groups/${g.insertId}/history`, headers: { cookie: a.cookie },
    })).body);
    expect(groupHistory.messages.some(m => m.type === 'system' && m.body.includes('changed the theme to Brujah'))).toBe(true);
  });

  it('stores a hold-to-grow emoji size, and ignores it on ordinary text', async () => {
    const a = await registerUser(app);
    const b = await registerUser(app);
    const send = (payload) => app.inject({ method: 'POST', url: '/api/chat/messages', headers: { cookie: a.cookie }, payload: { recipient_id: b.user.id, ...payload } });

    expect(JSON.parse((await send({ body: '👍', emoji_size: 3 })).body).message.emoji_size).toBe(3);
    await send({ body: 'this is a normal sentence that is longer than an emoji', emoji_size: 3 });
    await send({ body: '👍', emoji_size: 9 });

    const history = JSON.parse((await app.inject({ method: 'GET', url: `/api/chat/history/${b.user.id}?limit=5`, headers: { cookie: a.cookie } })).body);
    expect(history.messages.map(m => m.emoji_size)).toEqual([3, null, null]);
  });

  it('serves contacts with court standing, search and media for a conversation', async () => {
    const a = await registerUser(app);
    const b = await registerUser(app);
    await pool.query('INSERT INTO chat_messages (sender_id, recipient_id, body) VALUES (?, ?, ?)', [a.user.id, b.user.id, 'meet at Elysium 100%']);
    const get = (url) => app.inject({ method: 'GET', url, headers: { cookie: a.cookie } });

    const users = await get('/api/chat/users');
    expect(users.statusCode).toBe(200);
    expect(JSON.parse(users.body).users[0]).toHaveProperty('titles');
    expect((await get('/api/chat/npcs')).statusCode).toBe(200);

    const found = JSON.parse((await get(`/api/chat/search?kind=user&id=${b.user.id}&q=elysium`)).body).results;
    expect(found.map(r => r.body)).toEqual(['meet at Elysium 100%']);
    // LIKE wildcards in the query are literal.
    expect(JSON.parse((await get(`/api/chat/search?kind=user&id=${b.user.id}&q=${encodeURIComponent('%%')}`)).body).results).toEqual([]);

    const media = await get(`/api/chat/media-list?kind=user&id=${b.user.id}`);
    expect(JSON.parse(media.body)).toEqual({ media: [], has_more: false });
  });
});
