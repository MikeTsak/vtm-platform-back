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

async function createCharacter(userId, xp = 50, sheet = null) {
  const [r] = await getTestPool().query(
    'INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?, ?, ?, ?, ?)',
    [userId, 'Test Character', 'Brujah', xp, sheet && JSON.stringify(sheet)]
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
    await createCharacter(user.id, 50, { attributes: { Strength: 2 } });

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
      payload: { type: 'attribute', target: 'Strength', newLevel: 2 }, // costs 10, only has 5
    });

    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/not enough xp/i);

    const [[row]] = await getTestPool().query('SELECT xp FROM characters WHERE user_id=?', [user.id]);
    expect(row.xp).toBe(5); // unchanged — the rejected spend must not touch the balance
  });

  it('assigning a discipline power at an already-owned dot is free', async () => {
    const { cookie, user } = await registerUser(app);
    await createCharacter(user.id, 20, { disciplines: { Celerity: 1 }, disciplinePowers: { Celerity: [] } });

    const res = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie },
      payload: { type: 'discipline', disciplineKind: 'select', target: 'Celerity', powerId: 'cats_grace' },
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
      payload: { type: 'attribute', target: 'Strength', newLevel: 2, character_id: 999999 }, // ignored — no such param exists
    });

    expect(res.statusCode).toBe(200);

    const [[rowA]] = await getTestPool().query('SELECT xp FROM characters WHERE user_id=?', [a.user.id]);
    const [[rowB]] = await getTestPool().query('SELECT xp FROM characters WHERE user_id=?', [b.user.id]);
    expect(rowA.xp).toBe(40); // 50 - 10 (attribute lvl 2)
    expect(rowB.xp).toBe(50); // untouched
  });
});

// House rule: an activated character's Attribute / Discipline / Blood Potency dot also files a
// resolved downtime action this cycle; with no action available the purchase is refused.
describe('XP purchases that need a downtime action', () => {
  const { setSetting } = require('../utils/settings');
  beforeAll(async () => {
    await setSetting('feeding_enabled', 'false');
    await setSetting('feeding_cycle_anchor', '2026-01-01T00:00:00Z'); // a cycle that started before these rows
  });
  afterAll(async () => {
    await setSetting('feeding_enabled', 'true');
    await setSetting('feeding_cycle_anchor', '');
  });

  const buy = (cookie, payload) => app.inject({ method: 'POST', url: '/api/characters/xp/spend', headers: { cookie }, payload });
  const downtimes = async (charId) => (await getTestPool().query('SELECT title, status FROM downtimes WHERE character_id=?', [charId]))[0];

  it("files a resolved downtime with an activated character's attribute dot", async () => {
    const { cookie, user } = await registerUser(app);
    const id = await createCharacter(user.id, 50, { is_active: true, attributes: { Strength: 2 } });
    expect((await buy(cookie, { type: 'attribute', target: 'Strength', newLevel: 3 })).statusCode).toBe(200);
    expect(await downtimes(id)).toEqual([{ title: '[XP] Training: Strength 2 → 3', status: 'resolved' }]);
  });

  it("refuses the dot, keeping the XP, when the cycle's 3 actions are used; skills still go through", async () => {
    const { cookie, user } = await registerUser(app);
    const id = await createCharacter(user.id, 50, { is_active: true, attributes: { Strength: 2 } });
    for (let i = 0; i < 3; i++) {
      await getTestPool().query("INSERT INTO downtimes (character_id, title, body) VALUES (?, 'a', 'b')", [id]);
    }
    const res = await buy(cookie, { type: 'attribute', target: 'Strength', newLevel: 3 });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/downtime limit reached/i);
    expect((await buy(cookie, { type: 'blood_potency', target: 'Blood Potency' })).statusCode).toBe(400);
    expect((await buy(cookie, { type: 'skill', target: 'Brawl', newLevel: 1 })).statusCode).toBe(200);
    const [[row]] = await getTestPool().query('SELECT xp FROM characters WHERE id=?', [id]);
    expect(row.xp).toBe(47); // only the skill (3 XP) was charged
    expect(await downtimes(id)).toHaveLength(3);
  });

  it('refuses the dot until the character has fed, and the quota says why', async () => {
    const { cookie, user } = await registerUser(app);
    const id = await createCharacter(user.id, 50, { is_active: true, attributes: { Strength: 2 } });
    await setSetting('feeding_enabled', 'true');
    try {
      const res = await buy(cookie, { type: 'attribute', target: 'Strength', newLevel: 3 });
      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).error).toMatch(/must feed/i);
      const quota = JSON.parse((await app.inject({ method: 'GET', url: '/api/downtimes/quota', headers: { cookie } })).body);
      expect(quota.submit_block.code).toBe('not_fed');
      // A normal submission goes through the same check.
      const dt = await app.inject({ method: 'POST', url: '/api/downtimes', headers: { cookie }, payload: { title: 't', body: 'b' } });
      expect(JSON.parse(dt.body).error).toMatch(/must feed/i);
    } finally {
      await setSetting('feeding_enabled', 'false');
    }
    expect(await downtimes(id)).toHaveLength(0);
  });

  it('reports the used-up cycle through the quota and refuses a 4th normal submission', async () => {
    const { cookie, user } = await registerUser(app);
    const id = await createCharacter(user.id, 50, { is_active: true, attributes: { Strength: 2 } });
    expect((await buy(cookie, { type: 'attribute', target: 'Strength', newLevel: 3 })).statusCode).toBe(200);
    for (let i = 0; i < 2; i++) {
      const r = await app.inject({ method: 'POST', url: '/api/downtimes', headers: { cookie }, payload: { title: `t${i}`, body: 'b' } });
      expect(r.statusCode).toBe(200);
    }
    const quota = JSON.parse((await app.inject({ method: 'GET', url: '/api/downtimes/quota', headers: { cookie } })).body);
    expect([quota.used, quota.limit, quota.submit_block?.code]).toEqual([3, 3, 'limit']);
    const fourth = await app.inject({ method: 'POST', url: '/api/downtimes', headers: { cookie }, payload: { title: 'x', body: 'b' } });
    expect(JSON.parse(fourth.body).error).toMatch(/limit reached/i);
    expect(await downtimes(id)).toHaveLength(3);
  });

  it('leaves characters that are not activated yet free to spend', async () => {
    const { cookie, user } = await registerUser(app);
    const id = await createCharacter(user.id, 50, { attributes: { Strength: 2 } });
    expect((await buy(cookie, { type: 'attribute', target: 'Strength', newLevel: 3 })).statusCode).toBe(200);
    expect(await downtimes(id)).toHaveLength(0);
  });
});
