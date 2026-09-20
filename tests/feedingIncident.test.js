// tests/feedingIncident.test.js
//
// Integration coverage for POST /api/feeding/:id/confirm's domain-incident
// side effect (routes/feeding.js): when a hunt goes badly wrong in a
// division someone ELSE owns, the owner should get a persisted
// domain_incidents row + a push notification. Previously untested — the
// existing feeding suites only cover cycle math and admin stats.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool;
let app;
let owner;
let hunter;
let ownerCharId;
let hunterCharId;

const DIVISION = 5; // any division present in data/huntingDifficulty.js

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();

  owner = await registerUser(app, { displayName: 'Domain Owner' });
  hunter = await registerUser(app, { displayName: 'Hunter' });

  const [ownerCharRow] = await pool.query(
    'INSERT INTO characters (user_id, name, clan) VALUES (?, ?, ?)',
    [owner.user.id, 'Owner Char', 'Ventrue']
  );
  ownerCharId = ownerCharRow.insertId;

  const [hunterCharRow] = await pool.query(
    'INSERT INTO characters (user_id, name, clan) VALUES (?, ?, ?)',
    [hunter.user.id, 'Hunter Char', 'Nosferatu']
  );
  hunterCharId = hunterCharRow.insertId;
});

beforeEach(async () => {
  await pool.query('DELETE FROM domain_incidents');
  await pool.query('DELETE FROM feedings');
  await pool.query('DELETE FROM domain_claims');
  app.testPushNotifications.length = 0;

  await pool.query(
    'INSERT INTO domain_claims (division, owner_character_id, owner_name, color, safety_rating) VALUES (?, ?, ?, ?, ?)',
    [DIVISION, ownerCharId, 'Owner Char', '#ff0000', 10]
  );
});

afterAll(async () => {
  if (app) await app.close();
  await teardownTestDatabase();
});

async function insertPendingFeeding(characterId, outcome) {
  const [row] = await pool.query(
    `INSERT INTO feedings
      (character_id, division, predator_type, pool_label, dice_pool, difficulty, hunger_before, normal_dice, hunger_dice, outcome, status, cycle_index)
     VALUES (?, ?, 'Alleycat', 'Brawl', 4, 2, 2, '[]', '[]', ?, 'pending', 0)`,
    [characterId, DIVISION, outcome]
  );
  return row.insertId;
}

describe('POST /api/feeding/:id/confirm — domain incident notification', () => {
  it("logs an incident and notifies the owner when a bad outcome happens in someone else's domain", async () => {
    const feedingId = await insertPendingFeeding(hunterCharId, 'bestial_failure');

    const res = await app.inject({
      method: 'POST',
      url: `/api/feeding/${feedingId}/confirm`,
      headers: { cookie: hunter.cookie },
    });
    expect(res.statusCode).toBe(200);

    const [incidents] = await pool.query('SELECT * FROM domain_incidents WHERE feeding_id=?', [feedingId]);
    expect(incidents).toHaveLength(1);
    expect(incidents[0].owner_user_id).toBe(owner.user.id);
    expect(incidents[0].owner_character_id).toBe(ownerCharId);
    expect(incidents[0].intruder_character_id).toBe(hunterCharId);
    expect(incidents[0].outcome).toBe('bestial_failure');
    expect(incidents[0].flavor_text).toBeTruthy();

    expect(app.testPushNotifications).toHaveLength(1);
    expect(app.testPushNotifications[0].userId).toBe(owner.user.id);
    expect(app.testPushNotifications[0].category).toBe('court');
  });

  it("also notifies on 'failure' and 'messy_critical', the other two incident-worthy outcomes", async () => {
    for (const outcome of ['failure', 'messy_critical']) {
      const feedingId = await insertPendingFeeding(hunterCharId, outcome);
      const res = await app.inject({
        method: 'POST',
        url: `/api/feeding/${feedingId}/confirm`,
        headers: { cookie: hunter.cookie },
      });
      expect(res.statusCode).toBe(200);
    }

    const [incidents] = await pool.query('SELECT outcome FROM domain_incidents ORDER BY id');
    expect(incidents.map((i) => i.outcome)).toEqual(['failure', 'messy_critical']);
    expect(app.testPushNotifications).toHaveLength(2);
  });

  it('does NOT log an incident or notify when the failure happens in your own domain', async () => {
    const feedingId = await insertPendingFeeding(ownerCharId, 'bestial_failure');

    const res = await app.inject({
      method: 'POST',
      url: `/api/feeding/${feedingId}/confirm`,
      headers: { cookie: owner.cookie },
    });
    expect(res.statusCode).toBe(200);

    const [incidents] = await pool.query('SELECT * FROM domain_incidents WHERE feeding_id=?', [feedingId]);
    expect(incidents).toHaveLength(0);
    expect(app.testPushNotifications).toHaveLength(0);
  });

  it("does NOT log an incident or notify on a clean success in someone else's domain", async () => {
    const feedingId = await insertPendingFeeding(hunterCharId, 'success');

    const res = await app.inject({
      method: 'POST',
      url: `/api/feeding/${feedingId}/confirm`,
      headers: { cookie: hunter.cookie },
    });
    expect(res.statusCode).toBe(200);

    const [incidents] = await pool.query('SELECT * FROM domain_incidents WHERE feeding_id=?', [feedingId]);
    expect(incidents).toHaveLength(0);
    expect(app.testPushNotifications).toHaveLength(0);
  });

  it('does NOT log an incident when the division has no player owner (unclaimed territory)', async () => {
    await pool.query('DELETE FROM domain_claims WHERE division=?', [DIVISION]);
    const feedingId = await insertPendingFeeding(hunterCharId, 'bestial_failure');

    const res = await app.inject({
      method: 'POST',
      url: `/api/feeding/${feedingId}/confirm`,
      headers: { cookie: hunter.cookie },
    });
    expect(res.statusCode).toBe(200);

    const [incidents] = await pool.query('SELECT * FROM domain_incidents WHERE feeding_id=?', [feedingId]);
    expect(incidents).toHaveLength(0);
    expect(app.testPushNotifications).toHaveLength(0);

    // Confirm still auto-creates the domain_claims row (unclaimed division
    // gets NULL owner), same as the existing non-incident behavior.
    const [claims] = await pool.query('SELECT owner_character_id FROM domain_claims WHERE division=?', [DIVISION]);
    expect(claims).toHaveLength(1);
    expect(claims[0].owner_character_id).toBeNull();
  });
});
