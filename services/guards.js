// services/guards.js
//
// Route guards and rate-limit preHandlers.
//
// authRequired / requireAdmin live in authMiddleware.fastify.js; this module
// holds the Court-level guard and the rate limiters.
//
// The limiter tiers below are named preHandlers so each call site declares
// which tier it wants; tuning a tier is a change to this file alone.

const { log } = require('../logger');

// Single definition of "is this user an admin" — every route should check
// through here instead of inlining `role === 'admin'` (or a stale
// `permission_level === 'admin'` fallback that nothing ever sets) so the
// condition can't drift between files again.
const isAdmin = (user) => !!user && user.role === 'admin';
// Admin or court user: the "staff" tier. Offices narrow it further (services/courtOffices.js).
const isCourt = (user) => isAdmin(user) || (!!user && user.role === 'courtuser');

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
  if (isCourt(req.user)) {
    return next();
  }
  log.warn('Court access denied', { user_id: req.user?.id, role: req.user?.role });
  return reply.status(403).send({ error: 'Forbidden: Court access required' });
};

// Fixed-window counter per tier + caller. Signed-in callers are keyed by user id
// (a venue's shared wifi must not lock out a whole table of players); anonymous
// ones by client IP, read the same way routes/auth.js reads it.
// ponytail: in-memory and per-process like presence/socket rooms; swap the Map
// for a shared store (Redis) if the server ever runs >1 process.
function makeLimiter(tier, max, windowMs) {
  const hits = new Map(); // key -> { count, resetAt }
  return async (req, reply) => {
    const now = Date.now();
    const ip = req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] || (req.headers['x-forwarded-for'] || '').split(',')[0]?.trim() || req.ip || 'unknown';
    const key = req.user?.id ? `u${req.user.id}` : `ip${ip}`;
    let h = hits.get(key);
    if (!h || h.resetAt <= now) {
      if (hits.size > 5000) for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k);
      h = { count: 0, resetAt: now + windowMs };
      hits.set(key, h);
    }
    if (++h.count > max) {
      const retry = Math.ceil((h.resetAt - now) / 1000);
      log.warn('Rate limited', { tier, key, retry_after_s: retry });
      return reply.status(429).header('Retry-After', retry).send({ error: 'Too many requests. Please slow down and try again shortly.' });
    }
  };
}

const globalLimiter = async () => {}; // unused: no route wires it; per-tier limits cover the sensitive paths
const authLimiter = makeLimiter('auth', 30, 15 * 60_000);      // login / register / reset, per IP
const moderateLimiter = makeLimiter('moderate', 120, 60_000);  // creates and signals, per user
const uploadLimiter = makeLimiter('upload', 30, 60_000);       // file uploads, per user

module.exports = { makeLimiter, isAdmin, isCourt, isOwnerOrAdmin, userOwnsCharacter, requireCourt, globalLimiter, authLimiter, moderateLimiter, uploadLimiter };
