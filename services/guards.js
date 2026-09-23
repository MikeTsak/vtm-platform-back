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

// Single definition of "is this user an admin" — every route should check
// through here instead of inlining `role === 'admin'` (or a stale
// `permission_level === 'admin'` fallback that nothing ever sets) so the
// condition can't drift between files again.
const isAdmin = (user) => !!user && user.role === 'admin';

// Admin, or the resource's own owner. The shape repeated across
// characters/mechanics/feeding/avatars/chat: `ownerId` is whatever id column
// the route already fetched (user_id, owner_user_id, ...).
const isOwnerOrAdmin = (user, ownerId) => isAdmin(user) || (!!user && Number(user.id) === Number(ownerId));

// characters.js's per-request ownership check: does `userId` own the
// character `charId`? Used identically by every character sub-resource route
// (inventory, retainers, disciplines, ...) to gate non-admin access.
async function userOwnsCharacter(pool, userId, charId) {
  const [rows] = await pool.query('SELECT id FROM characters WHERE id = ? AND user_id = ?', [charId, userId]);
  return rows.length > 0;
}

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

module.exports = { isAdmin, isOwnerOrAdmin, userOwnsCharacter, requireCourt, globalLimiter, authLimiter, moderateLimiter, uploadLimiter };
