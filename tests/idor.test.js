// tests/idor.test.js — regression guards for the IDOR fixes in
// routes/characters.js: GET /api/characters/user/:id, GET/POST
// /api/characters/:id/inventory, and GET/POST /api/characters/:id/retainers
// must never let one user read or write another user's character data.
const { setupTestDatabase, teardownTestDatabase, truncateAll, getTestPool } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser, extractSessionCookie } = require('./setup/helpers');

let pool;
let app;
let owner; // owns characterId
let intruder; // a second, unrelated authenticated user
let admin;
let characterId;

// A minimal but genuinely-valid Tier 1 retainer sheet — utils/retainerValidation.js
// enforces an exact point-buy (2 attributes at 2 + the implied 7 at 1; 3
// skills at 2 + 5 at 1), so an empty/arbitrary sheet is correctly rejected.
const VALID_TIER1_SHEET = {
  attributes: { strength: 2, dexterity: 2 },
  skills: { athletics: 2, brawl: 2, stealth: 2, alertness: 1, drive: 1, firearms: 1, medicine: 1, survival: 1 },
};

async function createCharacter(userId) {
  const [r] = await getTestPool().query(
    'INSERT INTO characters (user_id, name, clan, xp) VALUES (?, ?, ?, ?)',
    [userId, "Owner's Character", 'Toreador', 50]
  );
  return r.insertId;
}

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();

  owner = await registerUser(app);
  intruder = await registerUser(app);
  admin = await registerUser(app);
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  // The session cookie from registerUser() was minted with the *old* role
  // claim — a JWT doesn't change after issuance, so re-authenticate to get
  // one that actually says 'admin'.
  const adminLogin = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = extractSessionCookie(adminLogin);

  characterId = await createCharacter(owner.user.id);
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

describe('GET /api/characters/user/:id', () => {
  it('is admin-only — an ordinary authenticated user (even the owner) is forbidden', async () => {
    for (const requester of [intruder, owner]) {
      const res = await app.inject({
        method: 'GET',
        url: `/api/characters/user/${characterId}`,
        headers: { cookie: requester.cookie },
      });
      expect(res.statusCode).toBe(403);
    }
  });

  it('allows an admin to read any character', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/characters/user/${characterId}`,
      headers: { cookie: admin.cookie },
    });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).character.id).toBe(characterId);
  });

  it('rejects an unauthenticated request', async () => {
    const res = await app.inject({ method: 'GET', url: `/api/characters/user/${characterId}` });
    expect(res.statusCode).toBe(401);
  });
});

describe('GET /api/characters/:id/inventory', () => {
  it("forbids reading another user's inventory", async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/characters/${characterId}/inventory`,
      headers: { cookie: intruder.cookie },
    });
    expect(res.statusCode).toBe(403);
  });

  it('allows the owner to read their own inventory', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/characters/${characterId}/inventory`,
      headers: { cookie: owner.cookie },
    });
    expect(res.statusCode).toBe(200);
  });

  it("allows an admin to read anyone's inventory", async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/characters/${characterId}/inventory`,
      headers: { cookie: admin.cookie },
    });
    expect(res.statusCode).toBe(200);
  });
});

describe('POST /api/characters/:id/retainers', () => {
  it("forbids creating a retainer on another user's character", async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/characters/${characterId}/retainers`,
      headers: { cookie: intruder.cookie },
      payload: { name: 'Sneaky Ghoul', tier: 1, sheet: {} },
    });
    expect(res.statusCode).toBe(403);

    const [rows] = await pool.query('SELECT id FROM retainers WHERE character_id=? AND name=?', [characterId, 'Sneaky Ghoul']);
    expect(rows.length).toBe(0); // nothing was actually created
  });

  it('allows the owner to create a retainer on their own character', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/characters/${characterId}/retainers`,
      headers: { cookie: owner.cookie },
      payload: { name: "Owner's Ghoul", tier: 1, sheet: VALID_TIER1_SHEET },
    });
    expect(res.statusCode).toBe(200);
  });

  it('allows an admin to create a retainer on any character', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/characters/${characterId}/retainers`,
      headers: { cookie: admin.cookie },
      payload: { name: "Admin-granted Retainer", tier: 1, sheet: VALID_TIER1_SHEET },
    });
    expect(res.statusCode).toBe(200);
  });
});

describe('GET /api/characters/:id/retainers', () => {
  it("forbids listing another user's retainers", async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/characters/${characterId}/retainers`,
      headers: { cookie: intruder.cookie },
    });
    expect(res.statusCode).toBe(403);
  });

  it('allows the owner to list their own retainers', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/characters/${characterId}/retainers`,
      headers: { cookie: owner.cookie },
    });
    expect(res.statusCode).toBe(200);
    const list = JSON.parse(res.body);
    expect(Array.isArray(list)).toBe(true);
    expect(list.length).toBeGreaterThanOrEqual(2); // created in the POST tests above
  });

  it("allows an admin to list anyone's retainers", async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/characters/${characterId}/retainers`,
      headers: { cookie: admin.cookie },
    });
    expect(res.statusCode).toBe(200);
  });
});
