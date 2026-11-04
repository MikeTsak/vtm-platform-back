// tests/chatForward.test.js — forwarding a chat message (services/chatForward.js,
// migration 0080): the copy is labelled with its original author by the
// server, only messages the sender can see can be forwarded, a forward can't
// be edited, and an attachment must be one the sender may see.
const { setupTestDatabase, teardownTestDatabase, truncateAll, getTestPool } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app, livia, marcus, outsider, npcId, groupId;
const as = (who) => (method, url, payload) => app.inject({ method, url, payload, headers: { cookie: who.cookie } });
const body = (res) => JSON.parse(res.body);
const lastDm = async (from, to) => (await pool.query(
  'SELECT * FROM chat_messages WHERE sender_id=? AND recipient_id=? ORDER BY id DESC LIMIT 1', [from.user.id, to.user.id]))[0][0];

beforeAll(async () => {
  await setupTestDatabase();
  pool = getTestPool();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  const player = async (name) => {
    const u = await registerUser(app, { displayName: `${name} (account)` });
    await pool.query('INSERT INTO characters (user_id, name, clan, xp) VALUES (?, ?, ?, 0)', [u.user.id, name, 'Toreador']);
    return u;
  };
  livia = await player('Livia');
  marcus = await player('Marcus');
  outsider = await player('Nosy');
  npcId = (await pool.query("INSERT INTO npcs (name, clan) VALUES ('The Harpy', 'Toreador')"))[0].insertId;
  groupId = (await pool.query("INSERT INTO chat_groups (name, created_by) VALUES ('Coterie', ?)", [marcus.user.id]))[0].insertId;
  await pool.query('INSERT INTO chat_group_members (group_id, user_id) VALUES (?, ?), (?, ?)', [groupId, marcus.user.id, groupId, outsider.user.id]);
});
afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

describe('forwarding', () => {
  let secret;

  it('copies the message and labels it with its author, by name', async () => {
    secret = body(await as(livia)('POST', '/api/chat/messages', { recipient_id: marcus.user.id, body: 'Meet me at the Plaka.' })).message.id;
    const res = await as(marcus)('POST', `/api/chat/groups/${groupId}/messages`, { forward_of: { kind: 'dm', id: secret } });
    expect(res.statusCode).toBe(201);
    const [[copy]] = await pool.query('SELECT body, forwarded_from, sender_id FROM chat_group_messages WHERE group_id=? ORDER BY id DESC LIMIT 1', [groupId]);
    expect(copy).toEqual({ body: 'Meet me at the Plaka.', forwarded_from: 'Livia', sender_id: marcus.user.id });
  });

  it('a forward of a forward keeps the first author', async () => {
    const [[copy]] = await pool.query('SELECT id FROM chat_group_messages WHERE group_id=? ORDER BY id DESC LIMIT 1', [groupId]);
    await as(outsider)('POST', '/api/chat/messages', { recipient_id: livia.user.id, forward_of: { kind: 'group', id: copy.id } });
    expect((await lastDm(outsider, livia)).forwarded_from).toBe('Livia');
  });

  it("refuses a message the sender can't see", async () => {
    const res = await as(outsider)('POST', '/api/chat/messages', { recipient_id: marcus.user.id, forward_of: { kind: 'dm', id: secret } });
    expect(res.statusCode).toBe(404);
  });

  it("can't be faked: a label sent by the client is ignored", async () => {
    await as(outsider)('POST', '/api/chat/messages', { recipient_id: marcus.user.id, body: 'I yield.', forwarded_from: 'The Prince' });
    expect((await lastDm(outsider, marcus)).forwarded_from).toBeNull();
  });

  it("can't be edited", async () => {
    const fwd = (await lastDm(outsider, livia)).id;
    const res = await as(outsider)('PUT', `/api/chat/messages/${fwd}`, { body: 'Different words', table: 'chat_messages' });
    expect(res.statusCode).toBe(403);
  });

  it("names an NPC by the NPC's name", async () => {
    const [n] = await pool.query("INSERT INTO npc_messages (npc_id, user_id, from_side, body) VALUES (?, ?, 'npc', 'Whispers say...')", [npcId, livia.user.id]);
    await as(livia)('POST', '/api/chat/messages', { recipient_id: marcus.user.id, forward_of: { kind: 'npc', id: n.insertId } });
    expect(await lastDm(livia, marcus)).toMatchObject({ body: 'Whispers say...', forwarded_from: 'The Harpy' });
  });
});

describe('attachments', () => {
  const media = async (owner) => (await pool.query(
    "INSERT INTO chat_media (uploader_id, filename, mime, size, data_url) VALUES (?, 'p.webp', 'image/webp', 1, 'https://img.test/p.webp')", [owner.user.id]))[0].insertId;

  it("refuses someone else's attachment (it used to be readable this way)", async () => {
    const private_ = await media(livia);
    const res = await as(outsider)('POST', '/api/chat/messages', { recipient_id: marcus.user.id, attachment_id: private_ });
    expect(res.statusCode).toBe(403);
    expect((await as(outsider)('GET', `/api/chat/media/${private_}`)).statusCode).toBe(404);
  });

  it('sends your own, and a forward shares the attachment with the new chat', async () => {
    const mine = await media(livia);
    expect((await as(livia)('POST', '/api/chat/messages', { recipient_id: marcus.user.id, attachment_id: mine })).statusCode).toBe(201);
    const msg = (await lastDm(livia, marcus)).id;
    await as(marcus)('POST', `/api/chat/groups/${groupId}/messages`, { forward_of: { kind: 'dm', id: msg } });
    expect((await as(outsider)('GET', `/api/chat/media/${mine}`)).statusCode).toBe(302);
  });
});
