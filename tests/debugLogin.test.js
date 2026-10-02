// tests/debugLogin.test.js — admin debug login (routes/debugLogin.js): only an
// admin can mint a code, it is single-use and bound to one player's email, the
// session it opens is the player's (flagged `imp`), and none of it touches the
// player's own password or sessions.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { extractSessionCookie, registerUser } = require('./setup/helpers');

let pool;
let app;
let admin;
let player;
let other;

const genCode = (cookie, userId) =>
  app.inject({ method: 'POST', url: `/api/admin/users/${userId}/debug-login-code`, headers: { cookie } });
const redeem = (email, code) =>
  app.inject({ method: 'POST', url: '/api/auth/debug-login', payload: { email, code } });
const me = (cookie) => app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie } });

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  await pool.query('DELETE FROM debug_login_codes');
  app = buildTestApp(pool);
  await app.ready();

  admin = await registerUser(app, { displayName: 'Admin' });
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = extractSessionCookie(login);

  player = await registerUser(app, { displayName: 'Player' });
  other = await registerUser(app, { displayName: 'Other' });
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

describe('debug login', () => {
  it('refuses non-admins and admin targets', async () => {
    expect((await genCode(player.cookie, other.user.id)).statusCode).toBe(403);
    expect((await genCode(admin.cookie, admin.user.id)).statusCode).toBe(400);
  });

  it('opens a flagged player session once, leaving the player untouched', async () => {
    const gen = await genCode(admin.cookie, player.user.id);
    expect(gen.statusCode).toBe(200);
    const { code, email } = JSON.parse(gen.body);
    expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);

    // Bound to that player's email.
    expect((await redeem(other.email, code)).statusCode).toBe(401);

    const ok = await redeem(email.toUpperCase(), code.toLowerCase());
    expect(ok.statusCode).toBe(200);
    const cookie = extractSessionCookie(ok);
    const { user } = JSON.parse((await me(cookie)).body);
    expect(user.id).toBe(player.user.id);
    expect(user.imp).toBe(admin.user.id);

    // Single use.
    expect((await redeem(email, code)).statusCode).toBe(401);

    // Can't escalate: no codes from inside, refresh doesn't re-mint, logout-all spares the player.
    expect((await genCode(cookie, other.user.id)).statusCode).toBe(403);
    const refresh = await app.inject({ method: 'POST', url: '/api/auth/refresh', headers: { cookie } });
    expect(refresh.headers['set-cookie']).toBeUndefined();
    await app.inject({ method: 'POST', url: '/api/auth/logout-all', headers: { cookie } });
    expect((await me(player.cookie)).statusCode).toBe(200);

    // Player's password still works.
    const pl = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: player.email, password: player.password } });
    expect(pl.statusCode).toBe(200);
  });

  it('rejects expired codes and codes whose admin was demoted', async () => {
    let { code, email } = JSON.parse((await genCode(admin.cookie, player.user.id)).body);
    await pool.query('UPDATE debug_login_codes SET expires_at = NOW() - INTERVAL 1 MINUTE WHERE used_at IS NULL');
    expect((await redeem(email, code)).statusCode).toBe(401);

    ({ code, email } = JSON.parse((await genCode(admin.cookie, player.user.id)).body));
    await pool.query("UPDATE users SET role='user' WHERE id=?", [admin.user.id]);
    expect((await redeem(email, code)).statusCode).toBe(401);
    await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  });
});
