// tests/feedingAdmin.test.js
// Integration test for GET /api/admin/feeding/stats ensuring robustness against null/empty anchor settings and 'herd' outcome.
const { setupTestDatabase, teardownTestDatabase, truncateAll, getTestPool } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser, extractSessionCookie } = require('./setup/helpers');

let pool;
let app;
let admin;

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();

  admin = await registerUser(app, { displayName: 'Admin User' });
  await pool.query('UPDATE users SET role="admin" WHERE id=?', [admin.user.id]);
  const adminLogin = await app.inject({
    method: 'POST',
    url: '/api/auth/login',
    payload: { email: admin.email, password: admin.password },
  });
  admin.cookie = extractSessionCookie(adminLogin);
});

beforeEach(async () => {
  await pool.query('DELETE FROM feedings');
  await pool.query('DELETE FROM characters');
  await pool.query('DELETE FROM domain_claims');
});

afterAll(async () => {
  if (app) await app.close();
  await teardownTestDatabase();
});

describe('GET /api/admin/feeding/stats', () => {
  it('returns 200 and valid stats even when feeding_cycle_anchor is empty in app_settings', async () => {
    // Deliberately set empty or corrupt anchor in DB
    await pool.query(
      'INSERT INTO app_settings (setting_key, setting_value) VALUES ("feeding_cycle_anchor", "") ON DUPLICATE KEY UPDATE setting_value = ""'
    );

    const res = await app.inject({
      method: 'GET',
      url: '/api/admin/feeding/stats',
      headers: { cookie: admin.cookie },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(Number.isInteger(body.cycleIndex)).toBe(true);
    expect(body.cycleIndex).toBeGreaterThanOrEqual(0);
    expect(body.counts).toBeDefined();
    expect(body.counts.total).toBe(0);
  });

  it('correctly tallies resolved feedings including herd feedings', async () => {
    // Create a character
    const [charRow] = await pool.query(
      'INSERT INTO characters (user_id, name, clan, xp) VALUES (?, ?, ?, ?)',
      [admin.user.id, 'Feeder Char', 'Ventrue', 10]
    );
    const charId = charRow.insertId;

    // Get current cycle index from the endpoint
    const statsRes = await app.inject({
      method: 'GET',
      url: '/api/admin/feeding/stats',
      headers: { cookie: admin.cookie },
    });
    const { cycleIndex } = JSON.parse(statsRes.body);

    // Insert resolved feedings with different outcomes including herd
    await pool.query(
      `INSERT INTO feedings
        (character_id, division, predator_type, pool_label, dice_pool, difficulty, hunger_before, outcome, status, cycle_index)
       VALUES
        (?, 1, 'Alleycat', 'Brawl', 4, 2, 2, 'success', 'resolved', ?),
        (?, 1, 'Farmer', 'Herd', 0, 0, 2, 'herd', 'resolved', ?),
        (?, 1, 'Alleycat', 'Brawl', 4, 2, 2, 'failure', 'resolved', ?)`,
      [charId, cycleIndex, charId, cycleIndex, charId, cycleIndex]
    );

    const res = await app.inject({
      method: 'GET',
      url: '/api/admin/feeding/stats',
      headers: { cookie: admin.cookie },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.cycleIndex).toBe(cycleIndex);
    expect(body.counts.total).toBe(3);
    expect(body.counts.herd).toBe(1);
    expect(body.counts.failure).toBe(1);
    expect(body.counts.success).toBe(2); // success + herd
    expect(body.successPct).toBe(67); // 2/3 = 66.6% -> 67%
  });

  it('GET /api/admin/feeding/log returns current_hunger and domain_owner', async () => {
    const sheetData = JSON.stringify({ hunger: 3 });
    const [charRow] = await pool.query(
      'INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?, ?, ?, ?, ?)',
      [admin.user.id, 'Log Char', 'Brujah', 5, sheetData]
    );
    const charId = charRow.insertId;

    const princeUser = await registerUser(app, { displayName: 'Prince User' });
    const [claimOwnerRow] = await pool.query(
      'INSERT INTO characters (user_id, name, clan, xp) VALUES (?, ?, ?, ?)',
      [princeUser.user.id, 'Domain Prince', 'Ventrue', 15]
    );
    const domainOwnerCharId = claimOwnerRow.insertId;

    await pool.query(
      'INSERT INTO domain_claims (division, owner_character_id, owner_name, color, safety_rating) VALUES (?, ?, ?, ?, ?)',
      [29, domainOwnerCharId, 'Legacy Name', '#3b82f6', 8]
    );

    await pool.query(
      `INSERT INTO feedings
        (character_id, division, predator_type, pool_label, dice_pool, difficulty, hunger_before, hunger_delta, safety_delta, outcome, status, cycle_index)
       VALUES
        (?, 29, 'Alleycat', 'Strength + Brawl', 6, 2, 4, -1, 0, 'success', 'resolved', 1)`,
      [charId]
    );

    const res = await app.inject({
      method: 'GET',
      url: '/api/admin/feeding/log',
      headers: { cookie: admin.cookie },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(Array.isArray(body.log)).toBe(true);
    expect(body.log.length).toBeGreaterThanOrEqual(1);

    const entry = body.log.find(l => l.character_id === charId);
    expect(entry).toBeDefined();
    expect(entry.character_name).toBe('Log Char');
    expect(entry.current_hunger).toBe(3);
    expect(entry.domain_owner).toBe('Domain Prince');
    expect(entry.division).toBe(29);
  });
});
