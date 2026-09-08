// services/guards.js
//
// Route guards and rate-limit preHandlers.
//
// authRequired / requireAdmin live in authMiddleware.fastify.js; this module
// holds the Court-level guard and the rate limiters.
//
// NOTE: the four limiters below are deliberate no-ops, exactly as they were
// inline in server.fastify.js. @fastify/rate-limit is installed but has never
// been wired up. They are kept as named functions so every call site already
// declares which tier it wants — turning real limiting on is then a change to
// this file alone, not to 200 route definitions.

const { log } = require('../logger');

const requireCourt = (req, reply, next) => {
  if (req.user && (req.user.role === 'admin' || req.user.role === 'courtuser')) {
    return next();
  }
  log.warn('Court access denied', { user_id: req.user?.id, role: req.user?.role });
  return reply.status(403).send({ error: 'Forbidden: Court access required' });
};

const globalLimiter = async (req, reply) => { /* Dummy rate limiter */ };
const authLimiter = async (req, reply) => { /* Dummy rate limiter */ };
const moderateLimiter = async (req, reply) => { /* Dummy rate limiter */ };
const uploadLimiter = async (req, reply) => { /* Dummy rate limiter */ };

module.exports = { requireCourt, globalLimiter, authLimiter, moderateLimiter, uploadLimiter };
