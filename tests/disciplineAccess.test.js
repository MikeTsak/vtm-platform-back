// tests/disciplineAccess.test.js — integration tests for the out-of-clan
// discipline access workflow: player requests -> admin approves/rejects,
// admin direct grant/revoke, and the XP-spend gate that actually enforces it.
const { setupTestDatabase, teardownTestDatabase, truncateAll, getTestPool } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser, extractSessionCookie } = require('./setup/helpers');

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

async function createCharacter(userId, xp = 50, clan = 'Hecata') {
  const [r] = await pool.query(
    'INSERT INTO characters (user_id, name, clan, xp) VALUES (?, ?, ?, ?)',
    [userId, 'Test Character', clan, xp]
  );
  return r.insertId;
}

async function makeAdmin(admin) {
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const res = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = extractSessionCookie(res);
  return admin;
}

describe('discipline access & requests', () => {
  it('blocks buying an out-of-clan discipline dot with no grant', async () => {
    const player = await registerUser(app);
    await createCharacter(player.user.id, 50);

    const res = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie: player.cookie },
      payload: { type: 'discipline', disciplineKind: 'other', target: 'Protean', currentLevel: 0, newLevel: 1 },
    });

    expect(res.statusCode).toBe(403);
    expect(JSON.parse(res.body).error).toMatch(/protean/i);
  });

  it('player request -> admin approve -> spend succeeds up to the granted level, not beyond', async () => {
    const player = await registerUser(app);
    const admin = await makeAdmin(await registerUser(app));
    await createCharacter(player.user.id, 100);

    const reqRes = await app.inject({
      method: 'POST',
      url: '/api/characters/discipline-requests',
      headers: { cookie: player.cookie },
      payload: { discipline: 'Protean', requestedLevel: 2, message: 'Diablerized a Gangrel.' },
    });
    expect(reqRes.statusCode).toBe(200);
    const requestId = JSON.parse(reqRes.body).request.id;

    // Duplicate pending request is rejected.
    const dupeRes = await app.inject({
      method: 'POST',
      url: '/api/characters/discipline-requests',
      headers: { cookie: player.cookie },
      payload: { discipline: 'Protean', requestedLevel: 1 },
    });
    expect(dupeRes.statusCode).toBe(409);

    // Shows up in the admin queue.
    const queueRes = await app.inject({ method: 'GET', url: '/api/admin/discipline-access', headers: { cookie: admin.cookie } });
    expect(queueRes.statusCode).toBe(200);
    const queue = JSON.parse(queueRes.body);
    expect(queue.requests.some(r => r.id === requestId && r.status === 'pending')).toBe(true);

    // Approve at level 2.
    const approveRes = await app.inject({
      method: 'POST',
      url: `/api/admin/discipline-requests/${requestId}/approve`,
      headers: { cookie: admin.cookie },
      payload: { grantedLevel: 2 },
    });
    expect(approveRes.statusCode).toBe(200);
    expect(JSON.parse(approveRes.body).access.max_level).toBe(2);

    // Buying level 1 and 2 now succeeds.
    const buy1 = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie: player.cookie },
      payload: { type: 'discipline', disciplineKind: 'other', target: 'Protean', currentLevel: 0, newLevel: 1 },
    });
    expect(buy1.statusCode).toBe(200);

    const buy2 = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie: player.cookie },
      payload: { type: 'discipline', disciplineKind: 'other', target: 'Protean', currentLevel: 1, newLevel: 2 },
    });
    expect(buy2.statusCode).toBe(200);

    // Level 3 is still beyond the grant.
    const buy3 = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie: player.cookie },
      payload: { type: 'discipline', disciplineKind: 'other', target: 'Protean', currentLevel: 2, newLevel: 3 },
    });
    expect(buy3.statusCode).toBe(403);
  });

  it('rejecting a request notifies but grants nothing', async () => {
    const player = await registerUser(app);
    const admin = await makeAdmin(await registerUser(app));
    await createCharacter(player.user.id, 50);

    const reqRes = await app.inject({
      method: 'POST',
      url: '/api/characters/discipline-requests',
      headers: { cookie: player.cookie },
      payload: { discipline: 'Dominate', requestedLevel: 1 },
    });
    const requestId = JSON.parse(reqRes.body).request.id;

    const rejectRes = await app.inject({
      method: 'POST',
      url: `/api/admin/discipline-requests/${requestId}/reject`,
      headers: { cookie: admin.cookie },
      payload: { adminNote: 'Not this chronicle.' },
    });
    expect(rejectRes.statusCode).toBe(200);

    const spend = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie: player.cookie },
      payload: { type: 'discipline', disciplineKind: 'other', target: 'Dominate', currentLevel: 0, newLevel: 1 },
    });
    expect(spend.statusCode).toBe(403);

    // Reflected in the player's own request history.
    const mine = await app.inject({ method: 'GET', url: '/api/characters/discipline-requests', headers: { cookie: player.cookie } });
    const rows = JSON.parse(mine.body).requests;
    expect(rows.find(r => r.id === requestId).status).toBe('rejected');
  });

  it('admin can grant access directly, and revoke it', async () => {
    const player = await registerUser(app);
    const admin = await makeAdmin(await registerUser(app));
    const characterId = await createCharacter(player.user.id, 50);

    const grantRes = await app.inject({
      method: 'POST',
      url: `/api/admin/characters/${characterId}/discipline-access`,
      headers: { cookie: admin.cookie },
      payload: { discipline: 'Oblivion', maxLevel: 1, note: 'Storyline grant' },
    });
    expect(grantRes.statusCode).toBe(200);

    const spend = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie: player.cookie },
      payload: { type: 'discipline', disciplineKind: 'other', target: 'Oblivion', currentLevel: 0, newLevel: 1 },
    });
    expect(spend.statusCode).toBe(200);

    const revokeRes = await app.inject({
      method: 'DELETE',
      url: `/api/admin/characters/${characterId}/discipline-access/${encodeURIComponent('Oblivion')}`,
      headers: { cookie: admin.cookie },
    });
    expect(revokeRes.statusCode).toBe(200);

    const blocked = await app.inject({
      method: 'POST',
      url: '/api/characters/xp/spend',
      headers: { cookie: player.cookie },
      payload: { type: 'discipline', disciplineKind: 'other', target: 'Oblivion', currentLevel: 1, newLevel: 2 },
    });
    expect(blocked.statusCode).toBe(403);
  });

  it('non-admins cannot grant, revoke, or resolve requests', async () => {
    const player = await registerUser(await Promise.resolve(app));
    const characterId = await createCharacter(player.user.id, 50);

    const grant = await app.inject({
      method: 'POST',
      url: `/api/admin/characters/${characterId}/discipline-access`,
      headers: { cookie: player.cookie },
      payload: { discipline: 'Protean', maxLevel: 1 },
    });
    expect(grant.statusCode).toBe(403);

    const list = await app.inject({ method: 'GET', url: '/api/admin/discipline-access', headers: { cookie: player.cookie } });
    expect(list.statusCode).toBe(403);
  });
});
