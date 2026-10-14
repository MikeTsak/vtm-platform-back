// tests/commsDrafts.test.js — comms drafts: only reachable conversations,
// private to their author, email bodies sanitised, summary counts decoded
// back to { kind, id }, and an undone delete keeps its original timestamp.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app, alice, bob, carol, groupId, threadId;
const json = (res) => JSON.parse(res.body);
const as = (who, method, url, payload) => app.inject({ method, url, headers: { cookie: who.cookie }, payload });

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  alice = await registerUser(app, { displayName: 'Alice' });
  bob = await registerUser(app, { displayName: 'Bob' });
  carol = await registerUser(app, { displayName: 'Carol' });

  const [g] = await pool.query("INSERT INTO chat_groups (name, created_by) VALUES ('Coterie', ?)", [alice.user.id]);
  groupId = g.insertId;
  await pool.query('INSERT INTO chat_group_members (group_id, user_id) VALUES (?, ?), (?, ?)', [groupId, alice.user.id, groupId, bob.user.id]);
  const [i] = await pool.query("INSERT INTO email_identities (email_address, display_name) VALUES (?, 'Fixer')", [`fixer${Date.now()}@net`]);
  const [t] = await pool.query("INSERT INTO email_threads (user_id, identity_id, subject) VALUES (?, ?, 'Job')", [alice.user.id, i.insertId]);
  threadId = t.insertId;
});

afterAll(async () => {
  await pool.query('DELETE FROM comms_drafts');
  await app.close();
  await teardownTestDatabase();
});

test('drafts only go where the author can write', async () => {
  expect((await as(alice, 'POST', '/api/drafts', { kind: 'user', id: bob.user.id, body: 'later' })).statusCode).toBe(200);
  expect((await as(alice, 'POST', '/api/drafts', { kind: 'user', id: alice.user.id, body: 'me' })).statusCode).toBe(400);
  expect((await as(alice, 'POST', '/api/drafts', { kind: 'user', id: bob.user.id, body: '   ' })).statusCode).toBe(400);
  expect((await as(carol, 'POST', '/api/drafts', { kind: 'group', id: groupId, body: 'x' })).statusCode).toBe(403);
  expect((await as(carol, 'POST', '/api/drafts', { kind: 'email', id: threadId, body: 'x' })).statusCode).toBe(404);
  expect((await as(alice, 'POST', '/api/drafts', { kind: 'nope', id: 1, body: 'x' })).statusCode).toBe(400);
});

test('a DM draft is private and shared by both directions of the key', async () => {
  const mine = json(await as(alice, 'GET', `/api/drafts?kind=user&id=${bob.user.id}`)).drafts;
  expect(mine).toHaveLength(1);
  expect(mine[0]).toMatchObject({ kind: 'user', target_id: bob.user.id, body: 'later' });
  // Bob's view of the same conversation holds only Bob's drafts.
  expect(json(await as(bob, 'GET', `/api/drafts?kind=user&id=${alice.user.id}`)).drafts).toHaveLength(0);
  // Nobody else can edit or delete it.
  expect((await as(bob, 'PUT', `/api/drafts/${mine[0].id}`, { body: 'hijack' })).statusCode).toBe(404);
  expect((await as(bob, 'DELETE', `/api/drafts/${mine[0].id}`)).statusCode).toBe(404);
});

test('email drafts are sanitised; a new email keeps to + subject', async () => {
  const reply = json(await as(alice, 'POST', '/api/drafts', { kind: 'email', id: threadId, body: '<p>ok</p><script>x()</script>' })).draft;
  expect(reply.body).toBe('<p>ok</p>');
  const fresh = json(await as(alice, 'POST', '/api/drafts', { kind: 'email-new', to_address: 'a@b.c', subject: 'Hi', body: '' })).draft;
  expect(fresh).toMatchObject({ kind: 'email-new', subject: 'Hi', to_address: 'a@b.c' });
  const edited = json(await as(alice, 'PUT', `/api/drafts/${fresh.id}`, { to_address: 'z@b.c', subject: 'Re', body: '<b>yo</b>' })).draft;
  expect(edited).toMatchObject({ subject: 'Re', to_address: 'z@b.c', body: '<b>yo</b>' });
});

test('summary counts per conversation', async () => {
  await as(alice, 'POST', '/api/drafts', { kind: 'group', id: groupId, body: 'plan' });
  const { counts, total } = json(await as(alice, 'GET', '/api/drafts/summary'));
  expect(total).toBe(4);
  expect(counts).toEqual(expect.arrayContaining([
    expect.objectContaining({ kind: 'user', id: bob.user.id, count: 1 }),
    expect.objectContaining({ kind: 'group', id: groupId, count: 1 }),
    expect.objectContaining({ kind: 'email', id: threadId, count: 1 }),
    expect.objectContaining({ kind: 'email-new', count: 1 }),
  ]));
});

test('undoing a delete restores the original order', async () => {
  await pool.query("UPDATE comms_drafts SET created_at = created_at - INTERVAL 1 MINUTE WHERE body='later'");
  const [first] = json(await as(alice, 'GET', `/api/drafts?kind=user&id=${bob.user.id}`)).drafts;
  await as(alice, 'POST', '/api/drafts', { kind: 'user', id: bob.user.id, body: 'second' });
  expect((await as(alice, 'DELETE', `/api/drafts/${first.id}`)).statusCode).toBe(200);
  await as(alice, 'POST', '/api/drafts', { kind: 'user', id: bob.user.id, body: first.body, created_at: first.created_at });
  const bodies = json(await as(alice, 'GET', `/api/drafts?kind=user&id=${bob.user.id}`)).drafts.map(d => d.body);
  expect(bodies).toEqual(['later', 'second']);
});
