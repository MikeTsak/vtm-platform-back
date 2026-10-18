// tests/inventory.test.js — ST-run inventory: players cannot create items,
// unresearched mechanics stay hidden, world QRs claim once (or once per
// character with claim_copies), and "Pass item" is a handshake: the receiver
// scans, the giver confirms "pass it to <name>?", and only then does the item
// (or part of the stack) move — once. The Storyteller can take items back.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app, giver, taker, bystander, admin, giverChar, takerChar;
const json = (res) => JSON.parse(res.body);
const call = (who, method, url, payload) => app.inject({ method, url, headers: { cookie: who.cookie }, payload });
const inv = async (who, charId) => json(await call(who, 'GET', `/api/characters/${charId}/inventory`)).items;
const status = async (who, token) => json(await call(who, 'GET', `/api/inventory/transfers/${token}`));
const pass = async (item, extra = {}) => json(await call(giver, 'POST', '/api/inventory/transfers', { item_id: item.id, ...extra })).token;
const scan = (who, code, extra = {}) => call(who, 'POST', '/api/inventory/claim', { code, ...extra });
const confirm = (token) => call(giver, 'POST', `/api/inventory/transfers/${token}/confirm`);

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  await pool.query('DELETE FROM inventory_transfers').catch(() => {});
  app = buildTestApp(pool);
  await app.ready();
  giver = await registerUser(app, { displayName: 'Giver' });
  taker = await registerUser(app, { displayName: 'Taker' });
  bystander = await registerUser(app, { displayName: 'Bystander' });
  admin = await registerUser(app, { displayName: 'Boss' });
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = login.cookies.map(c => `${c.name}=${c.value}`).join('; ');
  const mk = async (u, name) => (await pool.query('INSERT INTO characters (user_id, name, clan, xp) VALUES (?,?,?,0)', [u.user.id, name, 'Toreador']))[0].insertId;
  giverChar = await mk(giver, 'Anna');
  takerChar = await mk(taker, 'Boris');
  await mk(bystander, 'Cleo');
});

afterAll(async () => { await app.close(); await teardownTestDatabase(); });

test('players cannot create items; admin can, and mechanics hide until researched', async () => {
  expect((await call(giver, 'POST', `/api/characters/${giverChar}/inventory`, { name: 'x' })).statusCode).toBe(404);
  expect((await call(giver, 'POST', '/api/admin/inventory', { name: 'x' })).statusCode).toBe(403);
  expect((await call(admin, 'POST', '/api/admin/inventory', { name: '  ' })).statusCode).toBe(400);
  expect((await call(admin, 'POST', '/api/admin/inventory', { name: 'x', item_type: 'Spaceship' })).statusCode).toBe(400);
  expect((await call(admin, 'POST', '/api/admin/inventory', { name: 'x', character_id: 999999 })).statusCode).toBe(400);

  const res = await call(admin, 'POST', '/api/admin/inventory', { name: 'Bullets', character_id: giverChar, quantity: 10, mechanic_notes: '+1 dmg', item_type: 'Weapon' });
  expect(res.statusCode).toBe(201);
  const { item } = json(res);
  let [mine] = await inv(giver, giverChar);
  expect(mine.mechanic_notes).toBeNull();
  expect(mine).not.toHaveProperty('claim_code');
  expect((await call(taker, 'GET', `/api/characters/${giverChar}/inventory`)).statusCode).toBe(403);
  expect((await call(taker, 'PUT', `/api/characters/${giverChar}/inventory/${item.id}/notes`, { player_notes: 'mine now' })).statusCode).toBe(403);

  await call(admin, 'PUT', `/api/admin/inventory/${item.id}`, { researched: true });
  [mine] = await inv(giver, giverChar);
  expect(mine.mechanic_notes).toBe('+1 dmg');
  expect(mine.name).toBe('Bullets'); // partial PUT left the rest alone
});

test('pass is a handshake: scan parks it, nothing moves until the giver confirms', async () => {
  const [bullets] = await inv(giver, giverChar);
  await call(giver, 'PUT', `/api/characters/${giverChar}/inventory/${bullets.id}/notes`, { player_notes: 'from the docks' });
  expect((await call(taker, 'POST', '/api/inventory/transfers', { item_id: bullets.id })).statusCode).toBe(404); // not theirs
  expect((await call(giver, 'POST', '/api/inventory/transfers', { item_id: bullets.id, quantity: 11 })).statusCode).toBe(400);

  const token = await pass(bullets, { quantity: 3, include_notes: true });
  expect((await scan(giver, token)).statusCode).toBe(400); // to yourself
  expect((await confirm(token)).statusCode).toBe(409); // nobody scanned yet

  // The "are you sure?" preview changes nothing.
  const pv = json(await call(taker, 'POST', '/api/inventory/preview', { code: token }));
  expect(pv).toMatchObject({ kind: 'transfer', from_name: 'Anna', item: { name: 'Bullets', quantity: 3 } });
  expect((await status(giver, token)).status).toBe('open');

  expect(json(await scan(taker, token))).toMatchObject({ kind: 'pending', from_name: 'Anna' });
  expect((await scan(taker, token)).statusCode).toBe(200); // rescanning is harmless
  expect((await scan(bystander, token)).statusCode).toBe(409); // someone else is receiving
  expect((await status(bystander, token)).status).toBeUndefined(); // and cannot peek
  expect(await status(giver, token)).toMatchObject({ status: 'pending', to_name: 'Boris' });
  expect((await inv(giver, giverChar))[0].quantity).toBe(10); // nothing moved yet

  expect(json(await confirm(token))).toMatchObject({ status: 'claimed', to_name: 'Boris' });
  expect((await confirm(token)).statusCode).toBe(409); // double-tap confirms once
  expect((await status(taker, token)).status).toBe('claimed');
  expect((await inv(giver, giverChar))[0].quantity).toBe(7);
  const got = (await inv(taker, takerChar)).find(i => i.name === 'Bullets');
  expect(got).toMatchObject({ quantity: 3, player_notes: 'from the docks', mechanic_notes: '+1 dmg' });
});

test('"Not them", receiver backing out, timeouts and a vanished item', async () => {
  const [bullets] = await inv(giver, giverChar);

  // Giver declines the wrong person; the code is dead, the item stays.
  let token = await pass(bullets, { quantity: 1 });
  await scan(bystander, token);
  await call(giver, 'DELETE', `/api/inventory/transfers/${token}`);
  expect((await status(bystander, token)).status).toBe('cancelled');
  expect((await confirm(token)).statusCode).toBe(409);
  expect((await scan(taker, token)).statusCode).toBe(410);

  // Receiver backs out while waiting.
  token = await pass(bullets);
  await scan(taker, token);
  await call(taker, 'DELETE', `/api/inventory/transfers/${token}`);
  expect((await status(giver, token)).status).toBe('cancelled');

  // A new pass for the same item kills the old one.
  const old = await pass(bullets);
  token = await pass(bullets);
  expect((await scan(taker, old)).statusCode).toBe(410);

  // Expired before or after the scan.
  await pool.query('UPDATE inventory_transfers SET expires_at = NOW() - INTERVAL 1 MINUTE WHERE token = ?', [token]);
  expect((await scan(taker, token)).statusCode).toBe(410);
  token = await pass(bullets);
  await scan(taker, token);
  await pool.query('UPDATE inventory_transfers SET expires_at = NOW() - INTERVAL 1 MINUTE WHERE token = ?', [token]);
  expect((await status(giver, token)).status).toBe('expired');
  expect((await confirm(token)).statusCode).toBe(410);

  // The receiver's character is retired mid-handshake.
  token = await pass(bullets);
  await scan(taker, token);
  await pool.query('UPDATE characters SET user_id = NULL, retired_user_id = ? WHERE id = ?', [taker.user.id, takerChar]);
  expect((await confirm(token)).statusCode).toBe(409);
  await pool.query('UPDATE characters SET user_id = ?, retired_user_id = NULL WHERE id = ?', [taker.user.id, takerChar]);

  // The ST takes the item away mid-handshake.
  token = await pass(bullets);
  await scan(taker, token);
  await call(admin, 'PUT', `/api/admin/inventory/${bullets.id}`, { quantity: 1 });
  await call(admin, 'PUT', `/api/admin/inventory/${bullets.id}`, { character_id: takerChar });
  expect((await confirm(token)).statusCode).toBe(409);
  await call(admin, 'PUT', `/api/admin/inventory/${bullets.id}`, { character_id: giverChar, quantity: 7 });

  // Deleted outright: the pass goes with it.
  const { item: doomed } = json(await call(admin, 'POST', '/api/admin/inventory', { name: 'Doomed', character_id: giverChar }));
  token = await pass(doomed);
  await call(admin, 'DELETE', `/api/admin/inventory/${doomed.id}`);
  expect((await call(giver, 'GET', `/api/inventory/transfers/${token}`)).statusCode).toBe(404);
  expect((await scan(taker, token)).statusCode).toBe(404);
});

test('the Storyteller takes items back: by a pass QR (player confirms) or a prop QR', async () => {
  const [bullets] = await inv(giver, giverChar);
  expect((await scan(taker, 'x', { as_storyteller: true })).statusCode).toBe(403); // players cannot pose as the ST

  const token = await pass(bullets, { quantity: 2 });
  expect(json(await scan(admin, token, { as_storyteller: true }))).toMatchObject({ kind: 'pending', from_name: 'Anna' });
  expect(await status(giver, token)).toMatchObject({ status: 'pending', to_name: 'the Storyteller' });
  await confirm(token);
  const all = json(await call(admin, 'GET', '/api/admin/inventory')).items;
  const back = all.find(i => i.name === 'Bullets' && i.character_id == null);
  expect(back).toMatchObject({ quantity: 2 });
  expect(back.claim_code).toBeTruthy(); // ready to go back out with a QR
  expect((await inv(giver, giverChar)).find(i => i.id === bullets.id).quantity).toBe(5);

  // The prop's own printed QR: the ST scans it and it is back in the world.
  const { item: ring } = json(await call(admin, 'POST', '/api/admin/inventory', { name: 'Ring', character_id: takerChar }));
  expect(json(await call(admin, 'POST', '/api/inventory/preview', { code: ring.claim_code, as_storyteller: true }))).toMatchObject({ kind: 'takeback', from_name: 'Boris' });
  expect(json(await scan(admin, ring.claim_code, { as_storyteller: true })).kind).toBe('takeback');
  expect((await scan(admin, ring.claim_code, { as_storyteller: true })).statusCode).toBe(409); // already back
  expect((await inv(taker, takerChar)).find(i => i.id === ring.id)).toBeUndefined();
});

test('world items: once goes to the first scanner, copies give one each', async () => {
  const { item: key } = json(await call(admin, 'POST', '/api/admin/inventory', { name: 'Iron Key' }));
  expect(key.character_id).toBeNull();
  expect(json(await call(taker, 'POST', '/api/inventory/preview', { code: key.claim_code })).kind).toBe('world');
  expect(json(await scan(taker, key.claim_code)).kind).toBe('world');
  const late = await scan(giver, key.claim_code);
  expect(late.statusCode).toBe(409);
  expect(json(late).error).toContain('Boris already has this item');
  expect((await scan(taker, key.claim_code)).statusCode).toBe(409);

  const { item: flyer } = json(await call(admin, 'POST', '/api/admin/inventory', { name: 'Flyer', claim_copies: true }));
  expect((await scan(giver, flyer.claim_code)).statusCode).toBe(200);
  expect((await scan(taker, flyer.claim_code)).statusCode).toBe(200);
  expect((await scan(taker, flyer.claim_code)).statusCode).toBe(409);
  const all = json(await call(admin, 'GET', '/api/admin/inventory')).items;
  expect(all.find(i => i.id === flyer.id)).toMatchObject({ character_id: null, copies_claimed: 2 });
  expect((await scan(giver, 'nope')).statusCode).toBe(404);
  expect((await scan(giver, '')).statusCode).toBe(400);
  expect((await scan(giver, 'x'.repeat(65))).statusCode).toBe(400);
});
