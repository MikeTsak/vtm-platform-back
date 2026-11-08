// tests/chatPin.test.js — pinned chat messages across DMs, Groups, and NPC chats
const { setupTestDatabase, teardownTestDatabase, truncateAll, getTestPool } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app, livia, marcus, outsider, npcId, groupId;
const as = (who) => (method, url, payload) => app.inject({ method, url, payload, headers: { cookie: who.cookie } });
const body = (res) => JSON.parse(res.body);

beforeAll(async () => {
  await setupTestDatabase();
  pool = getTestPool();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();

  const player = async (name, clan = 'Toreador') => {
    const u = await registerUser(app, { displayName: `${name} Account` });
    await pool.query('INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?, ?, ?, 0, ?)', [
      u.user.id, name, clan, JSON.stringify({ is_active: true })
    ]);
    return u;
  };

  livia = await player('Livia', 'Toreador');
  marcus = await player('Marcus', 'Ventrue');
  outsider = await player('Outsider', 'Nosferatu');

  npcId = (await pool.query("INSERT INTO npcs (name, clan) VALUES ('The Primogen', 'Ventrue')"))[0].insertId;
  groupId = (await pool.query("INSERT INTO chat_groups (name, created_by) VALUES ('Elysium Council', ?)", [marcus.user.id]))[0].insertId;
  await pool.query('INSERT INTO chat_group_members (group_id, user_id) VALUES (?, ?), (?, ?)', [groupId, marcus.user.id, groupId, livia.user.id]);
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

describe('pinned messages', () => {
  let dmMsgId;
  let groupMsgId;
  let npcMsgId;

  it('pins and unpins a 1-on-1 direct message', async () => {
    // Send a DM from Livia to Marcus
    const sendRes = await as(livia)('POST', '/api/chat/messages', { recipient_id: marcus.user.id, body: 'Secret rendezvous at dawn.' });
    expect(sendRes.statusCode).toBe(201);
    dmMsgId = body(sendRes).message.id;

    // Pin the message as Marcus
    const pinRes = await as(marcus)('POST', `/api/chat/messages/${dmMsgId}/pin`, { table: 'chat_messages', is_pinned: true });
    expect(pinRes.statusCode).toBe(200);
    expect(body(pinRes).ok).toBe(true);
    expect(body(pinRes).is_pinned).toBe(true);

    const [[pinnedRow]] = await pool.query('SELECT is_pinned, pinned_by FROM chat_messages WHERE id = ?', [dmMsgId]);
    expect(pinnedRow.is_pinned).toBe(1);
    expect(pinnedRow.pinned_by).toBe(marcus.user.id);

    // Fetch via GET /api/chat/pinned
    const listRes = await as(livia)('GET', `/api/chat/pinned?kind=user&id=${marcus.user.id}`);
    expect(listRes.statusCode).toBe(200);
    const pinnedList = body(listRes).messages;
    expect(pinnedList.some(m => m.id === dmMsgId)).toBe(true);
    expect(pinnedList[0].body).toBe('Secret rendezvous at dawn.');

    // Unpin the message as Livia
    const unpinRes = await as(livia)('POST', `/api/chat/messages/${dmMsgId}/pin`, { table: 'chat_messages', is_pinned: false });
    expect(unpinRes.statusCode).toBe(200);
    expect(body(unpinRes).is_pinned).toBe(false);

    const [[unpinnedRow]] = await pool.query('SELECT is_pinned, pinned_by FROM chat_messages WHERE id = ?', [dmMsgId]);
    expect(unpinnedRow.is_pinned).toBe(0);
    expect(unpinnedRow.pinned_by).toBeNull();
  });

  it('pins and unpins a group chat message', async () => {
    // Send a group message from Marcus
    const sendRes = await as(marcus)('POST', `/api/chat/groups/${groupId}/messages`, { body: 'Council sits at midnight.' });
    expect(sendRes.statusCode).toBe(201);
    groupMsgId = body(sendRes).message.id;

    // Pin as Livia
    const pinRes = await as(livia)('POST', `/api/chat/messages/${groupMsgId}/pin`, { table: 'chat_group_messages', is_pinned: true });
    expect(pinRes.statusCode).toBe(200);
    expect(body(pinRes).is_pinned).toBe(true);

    const [[pinnedRow]] = await pool.query('SELECT is_pinned FROM chat_group_messages WHERE id = ?', [groupMsgId]);
    expect(pinnedRow.is_pinned).toBe(1);

    // Fetch via GET /api/chat/pinned
    const listRes = await as(marcus)('GET', `/api/chat/pinned?kind=group&id=${groupId}`);
    expect(listRes.statusCode).toBe(200);
    expect(body(listRes).messages.some(m => m.id === groupMsgId)).toBe(true);
  });

  it('pins and unpins an NPC chat message', async () => {
    // Send message to NPC as Marcus
    const sendRes = await as(marcus)('POST', '/api/chat/npc/messages', { npc_id: npcId, body: 'I seek an audience.' });
    expect(sendRes.statusCode).toBe(201);
    npcMsgId = body(sendRes).message.id;

    // Pin as Marcus
    const pinRes = await as(marcus)('POST', `/api/chat/messages/${npcMsgId}/pin`, { table: 'npc_messages', is_pinned: true });
    expect(pinRes.statusCode).toBe(200);
    expect(body(pinRes).is_pinned).toBe(true);

    const [[pinnedRow]] = await pool.query('SELECT is_pinned FROM npc_messages WHERE id = ?', [npcMsgId]);
    expect(pinnedRow.is_pinned).toBe(1);

    // Fetch via GET /api/chat/pinned
    const listRes = await as(marcus)('GET', `/api/chat/pinned?kind=npc&id=${npcId}`);
    expect(listRes.statusCode).toBe(200);
    expect(body(listRes).messages.some(m => m.id === npcMsgId)).toBe(true);
  });

  it('rejects pinning for an unauthorized outsider', async () => {
    // Outsider tries to pin Marcus-Livia DM
    const res = await as(outsider)('POST', `/api/chat/messages/${dmMsgId}/pin`, { table: 'chat_messages', is_pinned: true });
    expect(res.statusCode).toBe(403);
  });

  it('rejects pinning system messages', async () => {
    const [sys] = await pool.query("INSERT INTO chat_messages (sender_id, recipient_id, body, type) VALUES (?, ?, 'System event', 'system')", [livia.user.id, marcus.user.id]);
    const sysId = sys.insertId;

    const res = await as(marcus)('POST', `/api/chat/messages/${sysId}/pin`, { table: 'chat_messages', is_pinned: true });
    expect(res.statusCode).toBe(400);
  });
});
