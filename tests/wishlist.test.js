// tests/wishlist.test.js — integration tests for character wishlists
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
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

async function createCharacter(userId, name = 'Test Vampire', clan = 'Ventrue', xp = 30) {
  const [r] = await pool.query(
    'INSERT INTO characters (user_id, name, clan, xp) VALUES (?, ?, ?, ?)',
    [userId, name, clan, xp]
  );
  return r.insertId;
}

async function makeAdmin(userObj) {
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [userObj.user.id]);
  const res = await app.inject({
    method: 'POST',
    url: '/api/auth/login',
    payload: { email: userObj.email, password: userObj.password },
  });
  userObj.cookie = extractSessionCookie(res);
  return userObj;
}

describe('character wishlists', () => {
  it('allows a player to add, toggle, and view wishlist items', async () => {
    const player = await registerUser(app);
    await createCharacter(player.user.id, 'Lucian', 'Ventrue', 25);

    // Initial wishlist should be empty
    const initial = await app.inject({
      method: 'GET',
      url: '/api/characters/me/wishlist',
      headers: { cookie: player.cookie },
    });
    expect(initial.statusCode).toBe(200);
    expect(JSON.parse(initial.body).wishlist).toEqual([]);

    // Add a power
    const addRes = await app.inject({
      method: 'POST',
      url: '/api/characters/me/wishlist',
      headers: { cookie: player.cookie },
      payload: {
        item_type: 'power',
        item_id: 'mesmerize',
        name: 'Mesmerize',
        discipline: 'Dominate',
        level: 2,
        note: 'High priority for Court discussions',
      },
    });
    expect(addRes.statusCode).toBe(200);
    const addedItem = JSON.parse(addRes.body).item;
    expect(addedItem.name).toBe('Mesmerize');
    expect(addedItem.level).toBe(2);

    // Add a ritual via toggle
    const toggleAdd = await app.inject({
      method: 'POST',
      url: '/api/characters/me/wishlist/toggle',
      headers: { cookie: player.cookie },
      payload: {
        item_type: 'ritual',
        item_id: 'astromancy',
        name: 'Astromancy',
        discipline: 'Blood Sorcery',
        level: 1,
      },
    });
    expect(toggleAdd.statusCode).toBe(200);
    expect(JSON.parse(toggleAdd.body).action).toBe('added');

    // Fetch wishlist
    const getRes = await app.inject({
      method: 'GET',
      url: '/api/characters/me/wishlist',
      headers: { cookie: player.cookie },
    });
    expect(getRes.statusCode).toBe(200);
    const wishlist = JSON.parse(getRes.body).wishlist;
    expect(wishlist.length).toBe(2);

    // Toggle same ritual off
    const toggleRemove = await app.inject({
      method: 'POST',
      url: '/api/characters/me/wishlist/toggle',
      headers: { cookie: player.cookie },
      payload: {
        item_type: 'ritual',
        item_id: 'astromancy',
      },
    });
    expect(toggleRemove.statusCode).toBe(200);
    expect(JSON.parse(toggleRemove.body).action).toBe('removed');

    // Delete power by ID
    const delRes = await app.inject({
      method: 'DELETE',
      url: `/api/characters/me/wishlist/${addedItem.id}`,
      headers: { cookie: player.cookie },
    });
    expect(delRes.statusCode).toBe(200);

    const afterDel = await app.inject({
      method: 'GET',
      url: '/api/characters/me/wishlist',
      headers: { cookie: player.cookie },
    });
    expect(JSON.parse(afterDel.body).wishlist).toEqual([]);
  });

  it('allows an admin to view all character wishlists', async () => {
    const adminUser = await registerUser(app);
    await makeAdmin(adminUser);

    const player = await registerUser(app);
    await createCharacter(player.user.id, 'Cassandra', 'Tremere', 40);

    // Player adds power
    await app.inject({
      method: 'POST',
      url: '/api/characters/me/wishlist',
      headers: { cookie: player.cookie },
      payload: {
        item_type: 'power',
        item_id: 'blood_of_potency',
        name: 'Blood of Potency',
        discipline: 'Blood Sorcery',
        level: 3,
      },
    });

    // Admin fetches all wishlists
    const adminRes = await app.inject({
      method: 'GET',
      url: '/api/admin/wishlists',
      headers: { cookie: adminUser.cookie },
    });
    expect(adminRes.statusCode).toBe(200);
    const allWishlists = JSON.parse(adminRes.body).wishlists;
    expect(allWishlists.length).toBeGreaterThanOrEqual(1);
    const found = allWishlists.find(w => w.item_id === 'blood_of_potency');
    expect(found).toBeTruthy();
    expect(found.character_name).toBe('Cassandra');
  });
});
