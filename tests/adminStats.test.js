// tests/adminStats.test.js — GET /api/admin/stats: admin only, the period
// bounds (Athens days, inclusive; "all time" has no bounds), hidden
// characters never named, and an award shared by more than three is dropped.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser, extractSessionCookie } = require('./setup/helpers');

let pool, app, admin, alice, bob, ghost;

const login = async (u) => {
  const res = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: u.email, password: u.password } });
  return extractSessionCookie(res);
};
const stats = async (query = '') => {
  const res = await app.inject({ method: 'GET', url: `/api/admin/stats${query}`, headers: { cookie: admin.cookie } });
  expect(res.statusCode).toBe(200);
  return res.json();
};
const card = (body, id) => body.sections.flatMap((s) => s.cards).find((c) => c.id === id);

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  // truncateAll leaves these, and other files write to them; counts below are exact.
  for (const t of ['chat_messages', 'chat_group_messages', 'npc_messages', 'email_messages']) await pool.query(`DELETE FROM ${t}`);
  await pool.query('DELETE FROM domain_claims');
  app = buildTestApp(pool);
  await app.ready();
  [admin, alice, bob, ghost] = [await registerUser(app), await registerUser(app), await registerUser(app), await registerUser(app)];
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  admin.cookie = await login(admin);
  alice.cookie = await login(alice);
  for (const [u, name, hidden] of [[alice, 'Alice', 0], [bob, 'Bob', 0], [ghost, 'Ghost', 1]]) {
    await pool.query("INSERT INTO characters (user_id, name, clan, sheet, is_hidden) VALUES (?, ?, 'Toreador', '{}', ?)", [u.user.id, name, hidden]);
  }
  // 23:30 UTC on 2 Oct is 02:30 on 3 Oct in Athens: it belongs to the 3rd.
  // Exact instants (UTC), whatever the server's time zone.
  const msg = (from, to, utc) => pool.query(
    "INSERT INTO chat_messages (sender_id, recipient_id, body, type, created_at) VALUES (?, ?, 'x', 'text', FROM_UNIXTIME(?))",
    [from.user.id, to.user.id, Date.parse(`${utc}Z`) / 1000]
  );
  await msg(alice, bob, '2026-10-02T23:30:00');
  await msg(alice, bob, '2026-10-03T10:00:00');
  await msg(bob, alice, '2026-10-03T11:00:00');
  for (let i = 0; i < 5; i++) await msg(ghost, bob, '2026-10-03T12:00:00');
  await msg(alice, bob, '2026-09-01T10:00:00'); // outside the period
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

describe('GET /api/admin/stats', () => {
  it('is admin only', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/admin/stats', headers: { cookie: alice.cookie } });
    expect(res.statusCode).toBe(403);
  });

  it('counts only the chosen Athens days, and everything for all time', async () => {
    expect(card(await stats('?from=2026-10-03&to=2026-10-03'), 'comms.total').value).toBe('8');
    expect(card(await stats('?from=2026-10-02&to=2026-10-02'), 'comms.total').value).toBe('0');
    expect(card(await stats(), 'comms.total').value).toBe('9');
  });

  it('never names a hidden character, even when it wrote the most', async () => {
    const body = await stats('?from=2026-10-03&to=2026-10-03');
    expect(card(body, 'comms.writer')).toMatchObject({ name: 'Alice', clan: 'Toreador', value: '2 messages' });
    expect(JSON.stringify(body)).not.toContain('Ghost');
  });

  it('drops an award shared by more than three', async () => {
    const ids = [];
    for (let i = 0; i < 4; i++) {
      const [r] = await pool.query("INSERT INTO characters (retired_user_id, name, clan, sheet) VALUES (?, ?, 'Brujah', '{}')", [admin.user.id, `Tied ${i}`]);
      ids.push(r.insertId);
    }
    for (const id of ids) await pool.query("INSERT INTO domain_claims (division, owner_character_id, color, safety_rating) VALUES (?, ?, '#888888', 10)", [id + 100, id]);
    expect(card(await stats(), 'domains.landlord')).toBeUndefined();
    await pool.query("INSERT INTO domain_claims (division, owner_character_id, color, safety_rating) VALUES (999, ?, '#888888', 10)", [ids[0]]);
    expect(card(await stats(), 'domains.landlord')).toMatchObject({ name: 'Tied 0', value: '2 divisions' });
  });
});
