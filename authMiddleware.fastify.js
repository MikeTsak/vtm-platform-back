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

function requireAdmin(req, reply, done) {
  if (req.user?.role !== 'admin') return reply.status(403).send({ error: 'Admin only' });
  done();
}

module.exports = { authRequired, requireAdmin };
