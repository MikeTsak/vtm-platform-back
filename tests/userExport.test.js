// tests/userExport.test.js — GDPR personal data export must query existing columns across user/character/downtime/premonition tables.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app;

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
});

afterAll(async () => {
  await app?.close();
  await teardownTestDatabase();
});

describe('GET /api/users/me/export', () => {
  it('returns the caller user, active and retired characters, downtimes, and premonitions without SQL errors', async () => {
    const player = await registerUser(app);
    const other = await registerUser(app);

    const [activeChar] = await pool.query(
      "INSERT INTO characters (user_id, name, clan, sheet) VALUES (?, 'Active Kid', 'Toreador', ?)",
      [player.user.id, JSON.stringify({ attributes: { Charisma: 3 } })]
    );
    await pool.query(
      "INSERT INTO characters (user_id, retired_user_id, retired_at, name, clan, sheet) VALUES (NULL, ?, NOW(), 'Retired Elder', 'Brujah', ?)",
      [player.user.id, JSON.stringify({ attributes: { Strength: 4 } })]
    );
    await pool.query(
      "INSERT INTO downtimes (character_id, title, body, status) VALUES (?, 'Test Action', 'Scouting the port', 'pending')",
      [activeChar.insertId]
    );
    const [prem] = await pool.query(
      "INSERT INTO premonitions (sender_id, content_type, content_text) VALUES (?, 'text', 'Blood moon rising')",
      [other.user.id]
    );
    await pool.query(
      'INSERT INTO premonition_recipients (premonition_id, user_id) VALUES (?, ?)',
      [prem.insertId, player.user.id]
    );

    const res = await app.inject({
      method: 'GET',
      url: '/api/users/me/export',
      headers: { cookie: player.cookie },
    });
    expect(res.statusCode).toBe(200);

    const data = JSON.parse(res.body);
    expect(data.user.id).toBe(player.user.id);
    expect(data.characters.map((c) => c.name).sort()).toEqual(['Active Kid', 'Retired Elder']);
    expect(data.downtimes).toHaveLength(1);
    expect(data.downtimes[0].title).toBe('Test Action');
    expect(data.premonitions_received).toHaveLength(1);
    expect(data.premonitions_received[0].content_text).toBe('Blood moon rising');
  });

  it('rejects unauthenticated callers', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/users/me/export' });
    expect(res.statusCode).toBe(401);
  });
});
