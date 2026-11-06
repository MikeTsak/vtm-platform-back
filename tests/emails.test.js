// tests/emails.test.js — Surface Web.
// Images (migration 0082): an email can carry one, as a SchreckNet message can:
// a chat_media id the sender may see, visible afterwards to the thread's player
// and the Storytellers only, and to the player only once a queued identity
// email has actually been sent.
// Storyteller edit / delete (0083): any message, marked edited; a thread left
// empty goes with its last message.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app, player, stranger, admin;
const as = (who, method, url, payload) => app.inject({ method, url, headers: { cookie: who.cookie }, payload });
const image = async (uploader) => (await pool.query(
  "INSERT INTO chat_media (uploader_id, filename, mime, size, data, data_url) VALUES (?, 'x.webp', 'image/webp', 0, NULL, 'https://img.test/uploads/x.webp')",
  [uploader.user.id]))[0].insertId;
const canSee = async (who, id) => (await as(who, 'GET', `/api/chat/media/${id}/info`)).statusCode === 200;
const send = (who, payload) => as(who, 'POST', '/api/emails/send', payload);

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  player = await registerUser(app, { displayName: 'Player' });
  stranger = await registerUser(app, { displayName: 'Stranger' });
  admin = await registerUser(app, { displayName: 'Storyteller' });
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = login.cookies.map(c => `${c.name}=${c.value}`).join('; ');
  await pool.query("INSERT IGNORE INTO email_identities (email_address, display_name) VALUES ('prince@court.test', 'The Prince')"); // truncateAll keeps it
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

let threadId;

it('a player can email an image alone, and only the thread sees it', async () => {
  const id = await image(player);
  const res = await send(player, { to_email: 'prince@court.test', subject: 'Look', body: '', attachment_id: id });
  expect(res.statusCode).toBe(200);
  threadId = JSON.parse(res.body).thread_id;

  const { messages } = JSON.parse((await as(player, 'GET', `/api/emails/thread/${threadId}`)).body);
  expect(messages.map(m => m.attachment_id)).toEqual([id]);
  expect(await canSee(admin, id)).toBe(true);
  expect(await canSee(stranger, id)).toBe(false);
});

it("refuses someone else's image, and an email with neither text nor image", async () => {
  const theirs = await image(stranger);
  expect((await send(player, { thread_id: threadId, body: 'see', attachment_id: theirs })).statusCode).toBe(403);
  expect((await send(player, { thread_id: threadId, body: '  ' })).statusCode).toBe(400);
  const [[{ n }]] = await pool.query('SELECT COUNT(*) AS n FROM email_messages WHERE thread_id = ?', [threadId]);
  expect(Number(n)).toBe(1);
});

it("the Storyteller's queued image reaches the player only once it is sent", async () => {
  const id = await image(admin);
  const res = await as(admin, 'POST', '/api/admin/emails/reply', { thread_id: threadId, body: '', queue: true, attachment_id: id });
  expect(res.statusCode).toBe(200);
  expect(await canSee(player, id)).toBe(false);

  await pool.query("UPDATE email_messages SET status = 'sent' WHERE attachment_id = ?", [id]);
  expect(await canSee(player, id)).toBe(true);
  expect(await canSee(stranger, id)).toBe(false);
});

describe('a Storyteller edits and deletes messages', () => {
  let thread, first, second;
  const ids = async () => (await pool.query('SELECT id, body, edited FROM email_messages WHERE thread_id = ? ORDER BY id', [thread]))[0];

  beforeAll(async () => {
    thread = JSON.parse((await send(player, { to_email: 'prince@court.test', subject: 'Edits', body: 'tpyo' })).body).thread_id;
    const img = await image(admin);
    await as(admin, 'POST', '/api/admin/emails/reply', { thread_id: thread, body: '', attachment_id: img });
    [first, second] = (await ids()).map(m => m.id);
  });

  it('players may do neither', async () => {
    expect((await as(player, 'PUT', `/api/admin/emails/messages/${first}`, { body: 'mine' })).statusCode).toBe(403);
    expect((await as(player, 'DELETE', `/api/admin/emails/messages/${first}`)).statusCode).toBe(403);
  });

  it('an edit is marked; only a message with an image may be left without text', async () => {
    expect((await as(admin, 'PUT', `/api/admin/emails/messages/${first}`, { body: 'typo' })).statusCode).toBe(200);
    expect((await as(admin, 'PUT', `/api/admin/emails/messages/${first}`, { body: ' ' })).statusCode).toBe(400);
    expect((await as(admin, 'PUT', `/api/admin/emails/messages/${second}`, { body: '' })).statusCode).toBe(200);
    expect((await as(admin, 'PUT', '/api/admin/emails/messages/999999', { body: 'x' })).statusCode).toBe(404);
    expect((await ids()).map(m => [m.body, m.edited])).toEqual([['typo', 1], ['', 1]]);
  });

  it('deleting takes the image from the player, and the last message takes the thread', async () => {
    const [[{ attachment_id: img }]] = await pool.query('SELECT attachment_id FROM email_messages WHERE id = ?', [second]);
    expect(await canSee(player, img)).toBe(true);
    expect(JSON.parse((await as(admin, 'DELETE', `/api/admin/emails/messages/${second}`)).body)).toEqual({ ok: true, thread_deleted: false });
    expect(await canSee(player, img)).toBe(false);

    expect(JSON.parse((await as(admin, 'DELETE', `/api/admin/emails/messages/${first}`)).body)).toEqual({ ok: true, thread_deleted: true });
    const [rows] = await pool.query('SELECT 1 FROM email_threads WHERE id = ?', [thread]);
    expect(rows).toEqual([]);
  });
});
