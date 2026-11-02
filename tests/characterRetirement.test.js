// tests/characterRetirement.test.js — one account, several characters over
// time (migration 0057, services/characterRetirement.js): a dead character is
// retired when its player creates the next one, stays readable to them, and
// a Storyteller can restore it.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser, extractSessionCookie } = require('./setup/helpers');

let pool, app, player, other, admin, firstId;

const req = (who, method, url, payload) =>
  app.inject({ method, url, payload, headers: { cookie: who.cookie } });

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  player = await registerUser(app);
  other = await registerUser(app);
  admin = await registerUser(app);
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = extractSessionCookie(login);

  const [r] = await pool.query("INSERT INTO characters (user_id, name, clan, xp) VALUES (?, 'Marcus', 'Ventrue', 50)", [player.user.id]);
  firstId = r.insertId;
  await pool.query("UPDATE users SET avatar_url='https://cdn/marcus.webp', avatar_url_thumb='https://cdn/marcus_t.webp' WHERE id=?", [player.user.id]);
  const [co] = await pool.query("INSERT INTO coteries (name, created_by) VALUES ('Night Watch', ?)", [player.user.id]);
  await pool.query('INSERT INTO coterie_members (coterie_id, user_id, character_id) VALUES (?, ?, ?)', [co.insertId, player.user.id, firstId]);

  // Marcus's comms, court seats and domains.
  const [o] = await pool.query("INSERT INTO characters (user_id, name, clan, xp) VALUES (?, 'Livia', 'Brujah', 50)", [other.user.id]);
  otherCharId = o.insertId;
  await pool.query("INSERT INTO chat_messages (sender_id, recipient_id, body) VALUES (?, ?, 'from Marcus'), (?, ?, 'to Marcus')",
    [player.user.id, other.user.id, other.user.id, player.user.id]);
  const [g] = await pool.query("INSERT INTO chat_groups (name, created_by) VALUES ('Cabal', ?)", [other.user.id]);
  groupId = g.insertId;
  await pool.query('INSERT INTO chat_group_members (group_id, user_id) VALUES (?, ?), (?, ?)', [groupId, player.user.id, groupId, other.user.id]);
  await pool.query("INSERT INTO chat_group_messages (group_id, sender_id, body) VALUES (?, ?, 'Marcus in the cabal')", [groupId, player.user.id]);
  const [pr] = await pool.query("INSERT INTO premonitions (sender_id, content_type, content_text) VALUES (?, 'text', 'a vision')", [admin.user.id]);
  await pool.query('INSERT INTO premonition_recipients (premonition_id, user_id) VALUES (?, ?)', [pr.insertId, player.user.id]);
  await pool.query("INSERT INTO comms_drafts (user_id, conv_key, body) VALUES (?, ?, 'unsent')",
    [other.user.id, `u:${Math.min(player.user.id, other.user.id)}:${Math.max(player.user.id, other.user.id)}`]);
  await pool.query('DELETE FROM domain_claims WHERE division IN (901, 902)');
  await pool.query('DELETE FROM domain_claim_requests WHERE division = 903');
  await pool.query("INSERT INTO domain_claims (division, owner_character_id, owner_name, color) VALUES (901, ?, 'Marcus', '#aa0000')", [firstId]);
  await pool.query("INSERT INTO domain_claims (division, owner_character_id, owner_name, color) VALUES (902, ?, 'Livia', '#00aa00')", [otherCharId]);
  await pool.query('INSERT INTO domain_guests (division, character_id) VALUES (902, ?)', [firstId]);
  await pool.query('INSERT INTO domain_claim_requests (division, user_id, character_id) VALUES (903, ?, ?)', [player.user.id, firstId]);
});

let otherCharId, groupId, archiveId;
const dmCount = async (a, b) => (await pool.query(
  'SELECT COUNT(*) AS n FROM chat_messages WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)', [a, b, b, a]))[0][0].n;

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

const newChar = { name: 'Elena', clan: 'Toreador', sheet: {} };

it('refuses a second character while the current one lives', async () => {
  expect((await req(player, 'POST', '/api/characters', newChar)).statusCode).toBe(409);
});

it('retires a deceased character when the player creates the next one', async () => {
  await pool.query('UPDATE characters SET is_deceased=1 WHERE id=?', [firstId]);
  const res = await req(player, 'POST', '/api/characters', newChar);
  expect(res.statusCode).toBe(200);
  expect(res.json().character.name).toBe('Elena');

  const [[old]] = await pool.query('SELECT user_id, retired_user_id, retired_at FROM characters WHERE id=?', [firstId]);
  expect(old.user_id).toBeNull();
  expect(old.retired_user_id).toBe(player.user.id);
  expect(old.retired_at).not.toBeNull();
  // Marcus keeps his portrait; Elena starts without one.
  const [[saved]] = await pool.query('SELECT avatar_url, avatar_url_thumb FROM characters WHERE id=?', [firstId]);
  expect(saved).toEqual({ avatar_url: 'https://cdn/marcus.webp', avatar_url_thumb: 'https://cdn/marcus_t.webp' });
  const [[acct]] = await pool.query('SELECT avatar_url FROM users WHERE id=?', [player.user.id]);
  expect(acct.avatar_url).toBeNull();
  // The dead character's coterie seat does not pass to the new one.
  const [members] = await pool.query('SELECT 1 FROM coterie_members WHERE user_id=?', [player.user.id]);
  expect(members).toHaveLength(0);

  expect((await req(player, 'GET', '/api/characters/me')).json().character.name).toBe('Elena');
  const mine = (await req(player, 'GET', '/api/characters/mine')).json().characters;
  expect(mine.map(c => [c.name, !!c.is_current])).toEqual([['Elena', true], ['Marcus', false]]);
});

it("gives the new character fresh comms; Marcus's stay under his name", async () => {
  const [[arch]] = await pool.query('SELECT id, display_name, avatar_url FROM users WHERE archived_character_id=?', [firstId]);
  archiveId = arch.id;
  expect(arch.display_name).toBe('Marcus');
  expect(arch.avatar_url).toBe('https://cdn/marcus.webp');

  // Elena's thread with Livia's player is empty, on both sides.
  expect((await req(player, 'GET', `/api/chat/history/${other.user.id}`)).json().messages).toHaveLength(0);
  expect((await req(other, 'GET', `/api/chat/history/${player.user.id}`)).json().messages).toHaveLength(0);
  // The old thread is Livia's thread with Marcus.
  expect(await dmCount(archiveId, other.user.id)).toBe(2);
  const old = (await req(other, 'GET', `/api/chat/history/${archiveId}`)).json().messages;
  expect(old.map(m => m.body).sort()).toEqual(['from Marcus', 'to Marcus']);
  // Livia's player finds him under past contacts; Elena's player does not.
  const contacts = (await req(other, 'GET', '/api/chat/users')).json().users;
  expect(contacts.find(u => u.id === archiveId)).toMatchObject({ char_name: 'Marcus', is_archived: true, is_active: false });
  expect((await req(player, 'GET', '/api/chat/users')).json().users.some(u => u.id === archiveId)).toBe(false);
  // Admin chat logs: old messages under Marcus, new ones under Elena.
  await pool.query("INSERT INTO chat_messages (sender_id, recipient_id, body) VALUES (?, ?, 'from Elena')", [player.user.id, other.user.id]);
  const logs = (await req(admin, 'GET', '/api/admin/chat/all')).json().messages;
  const byBody = Object.fromEntries(logs.map(m => [m.body, m]));
  expect(byBody['from Marcus']).toMatchObject({ sender_id: archiveId, sender_char_name: 'Marcus', sender_clan: 'Ventrue' });
  expect(byBody['to Marcus']).toMatchObject({ recipient_id: archiveId, recipient_char_name: 'Marcus' });
  expect(byBody['from Elena']).toMatchObject({ sender_id: player.user.id, sender_char_name: 'Elena' });
  await pool.query("DELETE FROM chat_messages WHERE body='from Elena'");
  const groupLog = (await req(admin, 'GET', `/api/admin/chat/groups/${groupId}/history`)).json().messages;
  expect(groupLog[0]).toMatchObject({ body: 'Marcus in the cabal', char_name: 'Marcus' });
  // Nobody can write to him or log in as him.
  expect((await req(other, 'POST', '/api/chat/messages', { recipient_id: archiveId, body: 'hello?' })).statusCode).toBe(409);
  const [[a]] = await pool.query('SELECT email FROM users WHERE id=?', [archiveId]);
  expect((await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: a.email, password: '!' } })).statusCode).toBe(401);
  const users = (await req(admin, 'GET', '/api/admin/users')).json().users;
  expect(users.some(u => u.id === archiveId)).toBe(false);

  // Marcus keeps his group seat and his message there; Elena is not in it
  // until someone adds her, and then both sit in the group.
  const seats = async () => (await pool.query('SELECT user_id FROM chat_group_members WHERE group_id=? ORDER BY user_id', [groupId]))[0].map(s => s.user_id);
  expect(await seats()).toEqual([other.user.id, archiveId].sort((a, b) => a - b));
  expect((await req(player, 'GET', '/api/chat/groups')).json().groups).toHaveLength(0);
  const [[gm]] = await pool.query('SELECT sender_id FROM chat_group_messages WHERE group_id=?', [groupId]);
  expect(gm.sender_id).toBe(archiveId);
  expect((await req(other, 'POST', `/api/chat/groups/${groupId}/members`, { members: [player.user.id] })).statusCode).toBe(200);
  const members = (await req(other, 'GET', `/api/chat/groups/${groupId}/members`)).json().members;
  expect(members.find(m => m.id === archiveId)).toMatchObject({ char_name: 'Marcus', is_archived: 1 });
  expect(members.find(m => m.id === player.user.id)).toMatchObject({ char_name: 'Elena', is_archived: 0 });
  // The dead cannot be seated anew.
  await pool.query('DELETE FROM chat_group_members WHERE group_id=? AND user_id=?', [groupId, archiveId]);
  await req(other, 'POST', `/api/chat/groups/${groupId}/members`, { members: [archiveId] });
  expect(await seats()).not.toContain(archiveId);
  await pool.query('INSERT INTO chat_group_members (group_id, user_id) VALUES (?, ?)', [groupId, archiveId]);

  // His visions and the draft addressed to him go with him.
  expect((await req(player, 'GET', '/api/premonitions/mine')).json().premonitions || []).toHaveLength(0);
  const [[d]] = await pool.query('SELECT conv_key FROM comms_drafts WHERE user_id=?', [other.user.id]);
  expect(d.conv_key).toBe(`u:${Math.min(archiveId, other.user.id)}:${Math.max(archiveId, other.user.id)}`);
});

it('vacates his domain and ends his hospitality elsewhere', async () => {
  const [[claim]] = await pool.query('SELECT owner_character_id, owner_name, previous_owner_character_id, previous_owner_name FROM domain_claims WHERE division=901');
  expect(claim).toEqual({ owner_character_id: null, owner_name: null, previous_owner_character_id: firstId, previous_owner_name: 'Marcus' });
  const [guests] = await pool.query('SELECT 1 FROM domain_guests WHERE character_id=?', [firstId]);
  expect(guests).toHaveLength(0);
  // His pending claim can no longer be approved into a dead man's hands.
  const [[reqRow]] = await pool.query('SELECT status FROM domain_claim_requests WHERE character_id=?', [firstId]);
  expect(reqRow.status).toBe('rejected');
});

it('lets only the owner read a retired sheet', async () => {
  expect((await req(player, 'GET', `/api/characters/archive/${firstId}`)).json().character.name).toBe('Marcus');
  expect((await req(other, 'GET', `/api/characters/archive/${firstId}`)).statusCode).toBe(404);
});

it('lets a Storyteller restore it, retiring the current one', async () => {
  expect((await req(player, 'POST', `/api/admin/characters/${firstId}/restore`)).statusCode).toBe(403);
  expect((await req(admin, 'POST', `/api/admin/characters/${firstId}/restore`)).statusCode).toBe(200);
  const me = (await req(player, 'GET', '/api/characters/me')).json().character;
  expect(me.id).toBe(firstId);
  expect(me.is_deceased).toBe(0);
  // His portrait is the account's again, and is no longer stored on him.
  expect(me.avatar_url).toBeNull();
  const [[acct]] = await pool.query('SELECT avatar_url FROM users WHERE id=?', [player.user.id]);
  expect(acct.avatar_url).toBe('https://cdn/marcus.webp');
  const retired = (await req(admin, 'GET', '/api/admin/characters?retired=1')).json().characters;
  expect(retired.map(c => c.name)).toEqual(['Elena']);
  // The current roster leaves retired characters out.
  const roster = (await req(admin, 'GET', '/api/admin/characters')).json().characters;
  expect(roster.map(c => c.name).sort()).toEqual(['Livia', 'Marcus']);
  // His comms come back with him.
  expect(await dmCount(player.user.id, other.user.id)).toBe(2);
  expect(await dmCount(archiveId, other.user.id)).toBe(0);
  // Both had a seat in the cabal: Marcus's comes back to the account, Elena's
  // goes to her archive.
  const [[elenaArchive]] = await pool.query(
    "SELECT u.id FROM users u JOIN characters c ON c.id = u.archived_character_id WHERE c.name = 'Elena'");
  const [seats] = await pool.query('SELECT user_id FROM chat_group_members WHERE group_id=? ORDER BY user_id', [groupId]);
  expect(seats.map(s => s.user_id)).toEqual([other.user.id, player.user.id, elenaArchive.id].sort((a, b) => a - b));
});

it('lets a player who left the city start a new character', async () => {
  await pool.query('UPDATE characters SET is_left=1 WHERE id=?', [otherCharId]);
  const res = await req(other, 'POST', '/api/characters', { name: 'Quintus', clan: 'Gangrel', sheet: {} });
  expect(res.statusCode).toBe(200);
  const [[old]] = await pool.query('SELECT retired_user_id FROM characters WHERE id=?', [otherCharId]);
  expect(old.retired_user_id).toBe(other.user.id);
});

it('has no hard delete', async () => {
  expect((await req(admin, 'DELETE', `/api/admin/characters/${firstId}`)).statusCode).toBe(404);
});

it('lets a Storyteller retire a living character', async () => {
  expect((await req(admin, 'POST', `/api/admin/characters/${firstId}/retire`)).statusCode).toBe(200);
  expect((await req(player, 'GET', '/api/characters/me')).json().character).toBeNull();
  expect((await req(admin, 'POST', `/api/admin/characters/${firstId}/retire`)).statusCode).toBe(404);
});
