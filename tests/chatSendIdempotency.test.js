// tests/chatSendIdempotency.test.js — regression guard for duplicated chat
// messages: when a send request reached the server but the client never saw
// the answer, the user sent again and the message was stored twice. The
// client now sends the same Idempotency-Key when it re-sends, and the server
// must replay the first message instead of inserting a second row.
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

describe('POST /api/chat/messages — idempotency', () => {
  it('stores a re-sent message once when it reuses the key', async () => {
    const sender = await registerUser(app);
    const recipient = await registerUser(app);
    const send = (key) => app.inject({
      method: 'POST',
      url: '/api/chat/messages',
      headers: { cookie: sender.cookie, 'idempotency-key': key },
      payload: { recipient_id: recipient.user.id, body: 'test' },
    });

    const first = await send('draft-1');
    const retry = await send('draft-1');
    expect(first.statusCode).toBe(201);
    expect(retry.statusCode).toBe(201);
    expect(retry.headers['x-idempotent-replay']).toBe('true');
    expect(JSON.parse(retry.body).message.id).toBe(JSON.parse(first.body).message.id);

    // Same text as a genuinely new message (new key) must still go through.
    const again = await send('draft-2');
    expect(again.statusCode).toBe(201);

    const [rows] = await pool.query('SELECT id FROM chat_messages WHERE sender_id=?', [sender.user.id]);
    expect(rows).toHaveLength(2);
  });

  it('stores it once when the re-send arrives while the first is still running', async () => {
    const sender = await registerUser(app);
    const recipient = await registerUser(app);
    const send = () => app.inject({
      method: 'POST',
      url: '/api/chat/messages',
      headers: { cookie: sender.cookie, 'idempotency-key': 'concurrent' },
      payload: { recipient_id: recipient.user.id, body: 'test' },
    });

    const results = await Promise.all([send(), send(), send()]);
    for (const r of results) expect(r.statusCode).toBe(201);
    const ids = new Set(results.map((r) => JSON.parse(r.body).message.id));
    expect(ids.size).toBe(1);

    const [rows] = await pool.query('SELECT id FROM chat_messages WHERE sender_id=?', [sender.user.id]);
    expect(rows).toHaveLength(1);
  });

  it('takes over a claim left unfinished by a crashed request', async () => {
    const sender = await registerUser(app);
    const recipient = await registerUser(app);
    await pool.query(
      `INSERT INTO idempotency_keys (idempotency_key, user_id, request_path, request_method, created_at)
       VALUES ('crashed', ?, '/api/chat/messages', 'POST', NOW() - INTERVAL 2 MINUTE)`,
      [sender.user.id]
    );

    const res = await app.inject({
      method: 'POST',
      url: '/api/chat/messages',
      headers: { cookie: sender.cookie, 'idempotency-key': 'crashed' },
      payload: { recipient_id: recipient.user.id, body: 'test' },
    });
    expect(res.statusCode).toBe(201);
    expect(res.headers['x-idempotent-replay']).toBeUndefined();
  });
});
