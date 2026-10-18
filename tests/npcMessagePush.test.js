// tests/npcMessagePush.test.js — a player's message to an NPC pushes only the
// admins who ticked that NPC under "My NPCs" (users.ntfy_subscribed_npcs),
// titled with the NPC's name and showing the player's avatar.
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
  await app.close();
  await teardownTestDatabase();
});

async function makeAdmin(name, npcIds) {
  const a = await registerUser(app, { displayName: name });
  await pool.query("UPDATE users SET role='admin', ntfy_subscribed_npcs=? WHERE id=?", [npcIds && JSON.stringify(npcIds), a.user.id]);
  return a;
}

it('pushes only the admins who picked this NPC, with the NPC name and the player avatar', async () => {
  const [r1] = await pool.query("INSERT INTO npcs (name, clan) VALUES ('Prince Vorena', 'Ventrue')");
  const [r2] = await pool.query("INSERT INTO npcs (name, clan) VALUES ('Other NPC', 'Brujah')");
  const npc1 = r1.insertId, npc2 = r2.insertId;

  const picked = await makeAdmin('Picked', [npc1]);
  const otherNpc = await makeAdmin('OtherNpc', [npc2]);
  const noList = await makeAdmin('NoList', null);
  const player = await registerUser(app, { displayName: 'Player' });

  app.testPushNotifications.length = 0;
  const res = await app.inject({
    method: 'POST', url: '/api/chat/npc/messages',
    headers: { cookie: player.cookie },
    payload: { npc_id: npc1, body: 'Greetings, my prince' },
  });
  expect(res.statusCode).toBe(201);

  const pushes = app.testPushNotifications;
  expect(pushes.map(p => p.userId)).toEqual([picked.user.id]);
  expect(pushes[0].title.startsWith('Prince Vorena')).toBe(true);
  expect(pushes[0].body).toBe('Greetings, my prince');
  expect(pushes[0].category).toBe('chat');
  expect(pushes[0].data.icon).toBe(`/api/users/${player.user.id}/avatar`);
  expect([otherNpc, noList].some(a => pushes.some(p => p.userId === a.user.id))).toBe(false);
});
