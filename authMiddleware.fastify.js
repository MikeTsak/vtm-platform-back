const jwt = require('jsonwebtoken');

function authRequired(req, reply, done) {
  const hdr = req.headers.authorization || '';
  let token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token && req.query.token) token = req.query.token;
  if (!token) return reply.status(401).send({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    done();
  } catch {
    return reply.status(401).send({ error: 'Invalid token' });
  }
}

function requireAdmin(req, reply, done) {
  if (req.user?.role !== 'admin') return reply.status(403).send({ error: 'Admin only' });
  done();
}

module.exports = { authRequired, requireAdmin };
