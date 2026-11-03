// tests/idempotency.test.js — regression guard for the scoped idempotency
// fix: a retried request with the same Idempotency-Key must replay the
// cached response instead of re-executing (no double XP deduction), but
// that scoping must never let one user's cached response leak to another
// user or a different endpoint that happens to reuse the same key string.
const { setupTestDatabase, teardownTestDatabase, truncateAll, getTestPool } = require('./setup/testDb');
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

async function createCharacter(userId, xp = 100) {
  const [r] = await getTestPool().query(
    'INSERT INTO characters (user_id, name, clan, xp) VALUES (?, ?, ?, ?)',
    [userId, 'Idem Test Character', 'Ventrue', xp]
  );
  return r.insertId;
}

describe('POST /api/characters/xp/spend — idempotency', () => {
  it('replays the cached response for a repeated key instead of double-spending', async () => {
    const { cookie, user } = await registerUser(app);
    await createCharacter(user.id, 100);

    const payload = { type: 'attribute', target: 'Strength', currentLevel: 1, newLevel: 2 }; // cost 10
    const key = 'test-key-' + user.id + '-strength-2';

    const first = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie, 'idempotency-key': key },
      payload,
    });
    expect(first.statusCode).toBe(200);
    expect(JSON.parse(first.body).spent).toBe(10);
    expect(first.headers['x-idempotent-replay']).toBeUndefined();

    const second = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie, 'idempotency-key': key },
      payload,
    });
    expect(second.statusCode).toBe(200);
    expect(second.headers['x-idempotent-replay']).toBe('true');
    // Same cached response, including the SAME post-spend balance — proves
    // the second call never touched the database.
    expect(JSON.parse(second.body)).toEqual(JSON.parse(first.body));

    const [[row]] = await pool.query('SELECT xp FROM characters WHERE user_id=?', [user.id]);
    expect(row.xp).toBe(90); // 100 - 10, deducted exactly once
  });

  it('does not replay across two different keys — a genuinely new purchase still spends', async () => {
    const { cookie, user } = await registerUser(app);
    await createCharacter(user.id, 100);

    const res1 = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie, 'idempotency-key': 'key-a' },
      payload: { type: 'attribute', target: 'Strength', newLevel: 2 }, // cost 10
    });
    expect(res1.statusCode).toBe(200);

    const res2 = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie, 'idempotency-key': 'key-b' },
      payload: { type: 'skill', target: 'Brawl', newLevel: 1 }, // cost 3, a different purchase
    });
    expect(res2.statusCode).toBe(200);
    expect(res2.headers['x-idempotent-replay']).toBeUndefined();

    const [[row]] = await pool.query('SELECT xp FROM characters WHERE user_id=?', [user.id]);
    expect(row.xp).toBe(87); // 100 - 10 - 3, both charged
  });

  it('never replays a different user\'s cached response for the same literal key string', async () => {
    const a = await registerUser(app);
    const b = await registerUser(app);
    await createCharacter(a.user.id, 100);
    await createCharacter(b.user.id, 100);

    const sharedKey = 'literally-the-same-string';

    const resA = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie: a.cookie, 'idempotency-key': sharedKey },
      payload: { type: 'attribute', target: 'Strength', newLevel: 2 }, // cost 10
    });
    expect(resA.statusCode).toBe(200);

    // User B sends the exact same key string. If the lookup weren't scoped
    // by user_id, this would incorrectly come back as a replay of A's
    // response (A's character data, A's balance) instead of processing B's
    // own request.
    const resB = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie: b.cookie, 'idempotency-key': sharedKey },
      payload: { type: 'attribute', target: 'Strength', newLevel: 2 },
    });
    expect(resB.statusCode).toBe(200);
    expect(resB.headers['x-idempotent-replay']).toBeUndefined();
    expect(JSON.parse(resB.body).character.user_id).toBe(b.user.id);

    const [[rowA]] = await pool.query('SELECT xp FROM characters WHERE user_id=?', [a.user.id]);
    const [[rowB]] = await pool.query('SELECT xp FROM characters WHERE user_id=?', [b.user.id]);
    expect(rowA.xp).toBe(90);
    expect(rowB.xp).toBe(90); // B was charged independently, not served A's cached result
  });

  it('processes normally with no key at all (idempotency is opt-in)', async () => {
    const { cookie, user } = await registerUser(app);
    await createCharacter(user.id, 100);

    const res = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie }, // no Idempotency-Key header
      payload: { type: 'attribute', target: 'Strength', newLevel: 2 },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['x-idempotent-replay']).toBeUndefined();
  });

  it('recovers and parses legacy Buffer payload stored in idempotency_keys on replay', async () => {
    const { cookie, user } = await registerUser(app);
    await createCharacter(user.id, 100);

    const key = 'test-buffer-replay-' + user.id;
    const testJson = JSON.stringify({ character: { id: 999, name: 'Buffer Test' }, spent: 0 });
    const zlib = require('zlib');
    const compressed = zlib.brotliCompressSync(Buffer.from(testJson, 'utf8'));

    // Insert legacy serialized Buffer structure directly into DB
    await pool.query(
      'INSERT INTO idempotency_keys (idempotency_key, user_id, request_path, request_method, response_code, response_body) VALUES (?, ?, ?, ?, ?, ?)',
      [key, user.id, '/api/characters/xp/spend', 'POST', 200, JSON.stringify(compressed.toJSON())]
    );

    const res = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie, 'idempotency-key': key },
      payload: { type: 'attribute', target: 'Strength', newLevel: 2 },
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['x-idempotent-replay']).toBe('true');
    const parsed = JSON.parse(res.body);
    expect(parsed.character.name).toBe('Buffer Test');
    expect(parsed.character.id).toBe(999);
  });
});

// Every POST route honours a key now (utils/idempotency.js installIdempotency).
// Under lag a request timed out in the browser, the player clicked again, and
// the server later ran every copy: a downtime filed 3 times, items twice.
describe('lag double-submits', () => {
  const post = (cookie, url, payload, key) =>
    app.inject({ method: 'POST', url, headers: { cookie, 'idempotency-key': key }, payload });

  it('files a downtime once when the same submission arrives three times at once', async () => {
    const { cookie, user } = await registerUser(app);
    const [c] = await getTestPool().query(
      'INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?, ?, ?, ?, ?)',
      [user.id, 'Lag Victim', 'Brujah', 0, JSON.stringify({ is_active: true })]
    );
    const payload = { title: 'Hunt the Sheriff', body: 'Same text, three clicks' };
    const { setSetting } = require('../utils/settings');
    await setSetting('feeding_enabled', 'false'); // no feeding step before downtimes here
    let res;
    try {
      res = await Promise.all([1, 2, 3].map(() => post(cookie, '/api/downtimes', payload, 'dt-attempt-1')));
    } finally {
      await setSetting('feeding_enabled', 'true');
    }
    expect(res.map((r) => r.statusCode)).toEqual([200, 200, 200]);
    const [rows] = await getTestPool().query('SELECT id FROM downtimes WHERE character_id=?', [c.insertId]);
    expect(rows).toHaveLength(1);
  });

  it('creates an item once per attempt, and again on a new attempt', async () => {
    const admin = await registerUser(app);
    await getTestPool().query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
    const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
    admin.cookie = login.cookies.map((c) => `${c.name}=${c.value}`).join('; ');
    const item = { name: 'Lag Test Relic' };
    const first = await post(admin.cookie, '/api/admin/inventory', item, 'item-attempt-1');
    const retry = await post(admin.cookie, '/api/admin/inventory', item, 'item-attempt-1');
    expect([first.statusCode, retry.statusCode]).toEqual([201, 201]);
    expect(retry.headers['x-idempotent-replay']).toBe('true');
    expect(JSON.parse(retry.body).item.id).toBe(JSON.parse(first.body).item.id);
    await post(admin.cookie, '/api/admin/inventory', item, 'item-attempt-2'); // a deliberate second copy
    const [rows] = await getTestPool().query('SELECT id FROM inventory_items WHERE name=?', [item.name]);
    expect(rows).toHaveLength(2);
  });
});
