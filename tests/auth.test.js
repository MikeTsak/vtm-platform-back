// tests/auth.test.js — integration tests against the real routes/auth.js
// plugin: registration, login, session cookie, logout, and the
// password-reset -> token revocation flow.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { uniqueEmail, extractSessionCookie, registerUser } = require('./setup/helpers');

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

describe('POST /api/auth/register', () => {
  it('creates a user and sets an httpOnly session cookie, never the raw JWT in the body', async () => {
    const email = uniqueEmail();
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: { email, display_name: 'Alice', password: 'CorrectHorse123' },
    });

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ ok: true });
    expect(JSON.parse(res.body).token).toBeUndefined();

    const setCookie = res.headers['set-cookie'];
    expect(setCookie).toBeTruthy();
    const cookieStr = Array.isArray(setCookie) ? setCookie[0] : setCookie;
    expect(cookieStr).toMatch(/^token=/);
    expect(cookieStr).toMatch(/HttpOnly/i);
  });

  it('uses SameSite=Lax (no Secure required) for requests that look like local dev', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      headers: { host: 'localhost:3001' },
      payload: { email: uniqueEmail(), display_name: 'Local Dev User', password: 'CorrectHorse123' },
    });
    const cookieStr = res.headers['set-cookie'];
    expect(cookieStr).toMatch(/SameSite=Lax/i);
    expect(cookieStr).not.toMatch(/Secure/i);
  });

  it('uses SameSite=None + Secure for a production-looking cross-site request', async () => {
    // Mirrors the real deployment: frontend and API on different registrable
    // domains (portal.attlarp.gr vs vtm.back.miketsak.gr) — SameSite=None is
    // required or the browser never sends the cookie back on the next
    // request, which is exactly the bug this pins down as a regression.
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      headers: { host: 'vtm.back.miketsak.gr' },
      payload: { email: uniqueEmail(), display_name: 'Prod User', password: 'CorrectHorse123' },
    });
    const cookieStr = res.headers['set-cookie'];
    expect(cookieStr).toMatch(/SameSite=None/i);
    expect(cookieStr).toMatch(/Secure/i);
  });

  it('rejects a duplicate email', async () => {
    const email = uniqueEmail();
    await registerUser(app, { email });

    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: { email, display_name: 'Alice Again', password: 'CorrectHorse123' },
    });

    expect(res.statusCode).toBe(409);
  });

  it('rejects a password shorter than 8 characters', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: { email: uniqueEmail(), display_name: 'Short', password: 'short' },
    });
    expect(res.statusCode).toBe(400);
  });
});

describe('POST /api/auth/login', () => {
  it('logs in with correct credentials and sets the session cookie', async () => {
    const email = uniqueEmail();
    const password = 'CorrectHorse123';
    await registerUser(app, { email, password });

    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: { email, password },
    });

    expect(res.statusCode).toBe(200);
    expect(extractSessionCookie(res)).toMatch(/^token=/);
  });

  it('rejects the wrong password', async () => {
    const email = uniqueEmail();
    await registerUser(app, { email, password: 'CorrectHorse123' });

    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: { email, password: 'WrongPassword999' },
    });

    expect(res.statusCode).toBe(401);
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  it('rejects an email that was never registered', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: { email: uniqueEmail(), password: 'whatever123' },
    });
    expect(res.statusCode).toBe(401);
  });
});

describe('GET /api/auth/me', () => {
  it('returns the current user for a valid session cookie', async () => {
    const { cookie, email } = await registerUser(app);

    const res = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie } });

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).user.email).toBe(email);
  });

  it('rejects a request with no cookie', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/auth/me' });
    expect(res.statusCode).toBe(401);
  });

  it('rejects a garbage cookie value', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/auth/me',
      headers: { cookie: 'token=not-a-real-jwt' },
    });
    expect(res.statusCode).toBe(401);
  });
});

describe('POST /api/auth/logout', () => {
  it('clears the session cookie', async () => {
    const { cookie } = await registerUser(app);

    const res = await app.inject({ method: 'POST', url: '/api/auth/logout', headers: { cookie } });

    expect(res.statusCode).toBe(200);
    const setCookie = res.headers['set-cookie'];
    const cookieStr = Array.isArray(setCookie) ? setCookie[0] : setCookie;
    expect(cookieStr).toMatch(/^token=;/);
    expect(cookieStr).toMatch(/Max-Age=0/);
  });

  it('succeeds even with no session at all (idempotent cleanup)', async () => {
    const res = await app.inject({ method: 'POST', url: '/api/auth/logout' });
    expect(res.statusCode).toBe(200);
  });
});

describe('POST /api/auth/reset — token revocation', () => {
  it('invalidates every session that existed before the reset', async () => {
    const email = uniqueEmail();
    const oldPassword = 'CorrectHorse123';
    const { cookie: sessionBeforeReset } = await registerUser(app, { email, password: oldPassword });

    // Sanity check: the pre-reset session works right now.
    const preCheck = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: sessionBeforeReset } });
    expect(preCheck.statusCode).toBe(200);

    // Trigger "forgot password" — the real handler still writes a
    // password_resets row and calls sendResetEmailWithEmailJS even though
    // our test stub doesn't actually send anything (see testApp.js).
    app.testResetEmails.length = 0;
    const forgotRes = await app.inject({ method: 'POST', url: '/api/auth/forgot', payload: { email } });
    expect(forgotRes.statusCode).toBe(200);
    expect(app.testResetEmails.length).toBe(1);

    const resetLink = app.testResetEmails[0].link;
    const resetToken = new URL(resetLink).searchParams.get('token');
    expect(resetToken).toBeTruthy();

    const newPassword = 'BrandNewPassword456';
    const resetRes = await app.inject({
      method: 'POST',
      url: '/api/auth/reset',
      payload: { token: resetToken, password: newPassword },
    });
    expect(resetRes.statusCode).toBe(200);

    // The OLD session cookie must now be dead...
    const postResetCheck = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: sessionBeforeReset } });
    expect(postResetCheck.statusCode).toBe(401);

    // ...but logging in again with the NEW password works and issues a fresh, valid session.
    const loginRes = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email, password: newPassword } });
    expect(loginRes.statusCode).toBe(200);
    const newCookie = extractSessionCookie(loginRes);
    const meRes = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: newCookie } });
    expect(meRes.statusCode).toBe(200);
  });
});
