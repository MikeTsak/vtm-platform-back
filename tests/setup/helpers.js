// tests/setup/helpers.js — small shared utilities for the integration suite.
const crypto = require('crypto');

function uniqueEmail(prefix = 'test') {
  return `${prefix}-${crypto.randomUUID()}@example.test`;
}

/** Pulls the `token=...` cookie pair (name+value only) out of a Set-Cookie response header. */
function extractSessionCookie(response) {
  const setCookie = response.headers['set-cookie'];
  if (!setCookie) return null;
  const raw = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  return raw.split(';')[0]; // "token=<jwt>"
}

/** Registers a brand-new user against the test app and returns their session cookie + user record. */
async function registerUser(app, { email, password = 'CorrectHorse123', displayName = 'Test User' } = {}) {
  const finalEmail = email || uniqueEmail();
  const res = await app.inject({
    method: 'POST',
    url: '/api/auth/register',
    payload: { email: finalEmail, display_name: displayName, password },
  });
  if (res.statusCode !== 200) {
    throw new Error(`registerUser failed: ${res.statusCode} ${res.body}`);
  }
  const cookie = extractSessionCookie(res);

  const meRes = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie } });
  const { user } = JSON.parse(meRes.body);

  return { cookie, user, email: finalEmail, password };
}

module.exports = { uniqueEmail, extractSessionCookie, registerUser };
