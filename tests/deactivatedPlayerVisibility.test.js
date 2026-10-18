// tests/deactivatedPlayerVisibility.test.js
const { buildTestApp } = require('./setup/testApp');
const { setupTestDatabase, getTestPool, truncateAll, teardownTestDatabase } = require('./setup/testDb');
const { registerUser, extractSessionCookie } = require('./setup/helpers');

let app;
let pool;
let adminUser;

async function makeCharacter(userId, name, { clan = 'Toreador', isActive = true } = {}) {
  const sheet = JSON.stringify({ is_active: isActive });
  const [r] = await pool.query(
    'INSERT INTO characters (user_id, name, clan, sheet, xp, camarilla_titles) VALUES (?, ?, ?, ?, ?, ?)',
    [userId, name, clan, sheet, 50, JSON.stringify(['Primogen'])]
  );
  return r.insertId;
}

beforeAll(async () => {
  await setupTestDatabase();
  pool = getTestPool();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();

  adminUser = await registerUser(app, { displayName: 'Storyteller Admin' });
  await pool.query("UPDATE users SET role = 'admin' WHERE id = ?", [adminUser.user.id]);
  const adminLogin = await app.inject({
    method: 'POST',
    url: '/api/auth/login',
    payload: { email: adminUser.email, password: adminUser.password },
  });
  adminUser.cookie = extractSessionCookie(adminLogin);
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

describe('Deactivated player visibility in Court Hierarchy and Comms', () => {
  it('excludes deactivated players from /api/camarilla/roster and /api/chat/users', async () => {
    // 1. Create an active player
    const activePlayer = await registerUser(app, { displayName: 'Active Player' });
    await makeCharacter(activePlayer.user.id, 'Active Kindred', { isActive: true });

    // 2. Create a deactivated player
    const deactivatedPlayer = await registerUser(app, { displayName: 'Deactivated Player' });
    await makeCharacter(deactivatedPlayer.user.id, 'Deactivated Kindred', { isActive: false });

    // 3. Create a deactivated but bloodhunted player
    const bloodhuntedPlayer = await registerUser(app, { displayName: 'Bloodhunted Player' });
    const bhCharId = await makeCharacter(bloodhuntedPlayer.user.id, 'Bloodhunted Kindred', { isActive: false });
    await pool.query('UPDATE characters SET is_bloodhunted = 1 WHERE id = ?', [bhCharId]);

    // 4. Create a deactivated but deceased player
    const deceasedPlayer = await registerUser(app, { displayName: 'Deceased Player' });
    const decCharId = await makeCharacter(deceasedPlayer.user.id, 'Deceased Kindred', { isActive: false });
    await pool.query('UPDATE characters SET is_deceased = 1 WHERE id = ?', [decCharId]);

    // 5. Create a deactivated but missing player
    const missingPlayer = await registerUser(app, { displayName: 'Missing Player' });
    const misCharId = await makeCharacter(missingPlayer.user.id, 'Missing Kindred', { isActive: false });
    await pool.query('UPDATE characters SET is_missing = 1 WHERE id = ?', [misCharId]);

    // 6. Test public Camarilla roster
    const pubRosterRes = await app.inject({
      method: 'GET',
      url: '/api/camarilla/roster',
      headers: { cookie: activePlayer.cookie },
    });
    expect(pubRosterRes.statusCode).toBe(200);
    const pubRoster = JSON.parse(pubRosterRes.body).roster;
    const pubNames = pubRoster.map(r => r.name);
    expect(pubNames).toContain('Active Kindred');
    expect(pubNames).not.toContain('Deactivated Kindred');
    expect(pubNames).toContain('Bloodhunted Kindred');
    expect(pubNames).toContain('Deceased Kindred');
    expect(pubNames).toContain('Missing Kindred');

    // 7. Test admin Camarilla roster
    const admRosterRes = await app.inject({
      method: 'GET',
      url: '/api/admin/camarilla/roster',
      headers: { cookie: adminUser.cookie },
    });
    expect(admRosterRes.statusCode).toBe(200);
    const admRoster = JSON.parse(admRosterRes.body).roster;
    const admNames = admRoster.map(r => r.name);
    expect(admNames).toContain('Active Kindred');
    expect(admNames).not.toContain('Deactivated Kindred');
    expect(admNames).toContain('Bloodhunted Kindred');
    expect(admNames).toContain('Deceased Kindred');
    expect(admNames).toContain('Missing Kindred');

    // 8. Test Comms /api/chat/users from adminUser (bloodhunted/deceased/missing deactivated players excluded from comms)
    const chatUsersRes = await app.inject({
      method: 'GET',
      url: '/api/chat/users',
      headers: { cookie: adminUser.cookie },
    });
    expect(chatUsersRes.statusCode).toBe(200);
    const chatUsers = JSON.parse(chatUsersRes.body).users;
    const chatCharNames = chatUsers.map(u => u.char_name).filter(Boolean);
    const chatDisplayNames = chatUsers.map(u => u.display_name);
    expect(chatCharNames).toContain('Active Kindred');
    expect(chatCharNames).not.toContain('Deactivated Kindred');
    expect(chatCharNames).not.toContain('Bloodhunted Kindred');
    expect(chatCharNames).not.toContain('Deceased Kindred');
    expect(chatCharNames).not.toContain('Missing Kindred');
    expect(chatDisplayNames).not.toContain('Deactivated Player');
    expect(chatDisplayNames).not.toContain('Bloodhunted Player');
    expect(chatDisplayNames).not.toContain('Deceased Player');
    expect(chatDisplayNames).not.toContain('Missing Player');

    // 9. Test Comms /api/chat/users from activePlayer with include_self=1
    const chatSelfRes = await app.inject({
      method: 'GET',
      url: '/api/chat/users?include_self=1',
      headers: { cookie: activePlayer.cookie },
    });
    expect(chatSelfRes.statusCode).toBe(200);
    const selfUsers = JSON.parse(chatSelfRes.body).users;
    const selfCharNames = selfUsers.map(u => u.char_name).filter(Boolean);
    expect(selfCharNames).toContain('Active Kindred');
    expect(selfCharNames).not.toContain('Deactivated Kindred');
    expect(selfCharNames).not.toContain('Bloodhunted Kindred');
    expect(selfCharNames).not.toContain('Deceased Kindred');
    expect(selfCharNames).not.toContain('Missing Kindred');
  });
});
