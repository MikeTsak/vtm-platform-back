// tests/xpSpend.test.js — integration tests against the real, extracted
// routes/characterXp.js plugin (POST /api/characters/xp/spend).
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

async function createCharacter(userId, xp = 50) {
  const [r] = await getTestPool().query(
    'INSERT INTO characters (user_id, name, clan, xp) VALUES (?, ?, ?, ?)',
    [userId, 'Test Character', 'Brujah', xp]
  );
  return r.insertId;
}

describe('POST /api/characters/xp/spend', () => {
  it('rejects an unauthenticated request', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      payload: { type: 'attribute', newLevel: 2 },
    });
    expect(res.statusCode).toBe(401);
  });

  it("rejects spending before the user has created a character", async () => {
    const { cookie } = await registerUser(app);

    const res = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie },
      payload: { type: 'attribute', newLevel: 2 },
    });

    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/create a character/i);
  });

  it('deducts the correct cost and persists it against the caller\'s own character', async () => {
    const { cookie, user } = await registerUser(app);
    await createCharacter(user.id, 50);

    // attribute newLevel=3 -> cost 15 (see tests/xpCost.test.js for the pricing table itself)
    const res = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie },
      payload: { type: 'attribute', target: 'Strength', currentLevel: 2, newLevel: 3 },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.spent).toBe(15);
    expect(body.character.xp).toBe(35); // 50 - 15

    const [[row]] = await getTestPool().query('SELECT xp FROM characters WHERE user_id=?', [user.id]);
    expect(row.xp).toBe(35);
  });

  it('rejects spending more XP than the character has', async () => {
    const { cookie, user } = await registerUser(app);
    await createCharacter(user.id, 5); // not enough for anything but a specialty

    const res = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie },
      payload: { type: 'attribute', newLevel: 3 }, // costs 15, only has 5
    });

    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/not enough xp/i);

    const [[row]] = await getTestPool().query('SELECT xp FROM characters WHERE user_id=?', [user.id]);
    expect(row.xp).toBe(5); // unchanged — the rejected spend must not touch the balance
  });

  it('assigning a discipline power at an already-owned dot is free', async () => {
    const { cookie, user } = await registerUser(app);
    await createCharacter(user.id, 20);

    const res = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie },
      payload: { type: 'discipline', disciplineKind: 'select', currentLevel: 1, newLevel: 1 },
    });

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).spent).toBe(0);

    const [[row]] = await getTestPool().query('SELECT xp FROM characters WHERE user_id=?', [user.id]);
    expect(row.xp).toBe(20); // unchanged
  });

  it("only ever spends the caller's own character, never one selected by request body", async () => {
    // Two separate users; make sure spending as user A can never touch user B's XP
    // even if the request tried to imply a different target (there's no :id param
    // on this route at all — this pins that down as a regression guard).
    const a = await registerUser(app);
    const b = await registerUser(app);
    await createCharacter(a.user.id, 50);
    await createCharacter(b.user.id, 50);

    const res = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie: a.cookie },
      payload: { type: 'attribute', newLevel: 2, character_id: 999999 }, // ignored — no such param exists
    });

    expect(res.statusCode).toBe(200);

    const [[rowA]] = await getTestPool().query('SELECT xp FROM characters WHERE user_id=?', [a.user.id]);
    const [[rowB]] = await getTestPool().query('SELECT xp FROM characters WHERE user_id=?', [b.user.id]);
    expect(rowA.xp).toBe(40); // 50 - 10 (attribute lvl 2)
    expect(rowB.xp).toBe(50); // untouched
  });
});
