const jwt = require('jsonwebtoken');
const { COOKIE_NAME } = require('./utils/authCookie');
const { getTokenVersion } = require('./utils/tokenVersion');

async function authRequired(req, reply) {
  const hdr = req.headers.authorization || '';
  let token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  // Browsers: the httpOnly session cookie. Non-browser API/mobile clients
  // that can't rely on cookies keep working via the Authorization header above.
  if (!token) token = req.cookies?.[COOKIE_NAME] || null;
  // Deliberately no `req.query.token` fallback — a token embedded in a URL
  // leaks into access logs, proxy logs, and browser history. SSE (EventSource)
  // and <img>/socket.io connections authenticate via the cookie instead.
  if (!token) return reply.status(401).send({ error: 'Missing token' });

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return reply.status(401).send({ error: 'Invalid token' });
  }

  // Revocation check: a token minted before a password reset / "log out
  // everywhere" no longer matches the user's current token_version.
  const currentVersion = await getTokenVersion(payload.id);
  if (currentVersion === null || (payload.tv ?? 0) !== currentVersion) {
    return reply.status(401).send({ error: 'Session revoked, please log in again' });
  }

  req.user = payload;
}

// Populates req.user when a valid session is present, and stays silent when it
// isn't. For endpoints that are public but show more to a logged-in caller.
//
// authRequired must NOT be used for that: it *sends* a 401 rather than
// throwing, so wrapping it in try/catch does not make it optional — the catch
// never runs, the reply is already committed, and the handler goes on to send
// a second one. That is what made GET /api/wiki/articles answer 401 to
// anonymous visitors even though it is meant to be a public feed.
async function optionalAuth(req) {
  const hdr = req.headers.authorization || '';
  let token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) token = req.cookies?.[COOKIE_NAME] || null;
  if (!token) return null;

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const currentVersion = await getTokenVersion(payload.id);
    if (currentVersion === null || (payload.tv ?? 0) !== currentVersion) return null;
    req.user = payload;
    return payload;
  } catch {
    return null;
  }
}

function requireAdmin(req, reply, done) {
  if (req.user?.role !== 'admin') return reply.status(403).send({ error: 'Admin only' });
  done();
}

module.exports = { authRequired, optionalAuth, requireAdmin };
