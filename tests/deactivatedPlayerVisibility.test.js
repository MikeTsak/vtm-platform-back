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

    // 3. Test public Camarilla roster
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

    // 4. Test admin Camarilla roster
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

    // 5. Test Comms /api/chat/users from adminUser
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
    expect(chatDisplayNames).not.toContain('Deactivated Player');

    // 6. Test Comms /api/chat/users from activePlayer with include_self=1
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
  });
});
