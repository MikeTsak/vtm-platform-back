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

// The caller's IP, for rate limiting and logs. There is no Cloudflare in front
// of the API (Plesk nginx -> Passenger), so CF-Connecting-IP is just whatever
// the client typed and is ignored. X-Forwarded-For is read from the RIGHT: our
// own proxy appends the address it actually saw, so the last entry can't be
// forged, while the first one is the client's to choose (sending a fresh fake
// one per request used to dodge the login limiter entirely).
// ponytail: assumes exactly one appending proxy; if a CDN/LB is ever added in
// front, take the entry one further from the right instead.
function clientIp(req) {
  const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  return xff[xff.length - 1] || req.headers['x-real-ip'] || req.ip || req.socket?.remoteAddress || 'unknown';
}

// Fixed-window counter per tier + caller. Signed-in callers are keyed by user id
// (a venue's shared wifi must not lock out a whole table of players); anonymous
// ones by client IP, read the same way routes/auth.js reads it.
// ponytail: in-memory and per-process like presence/socket rooms; swap the Map
// for a shared store (Redis) if the server ever runs >1 process.
function makeLimiter(tier, max, windowMs) {
  const hits = new Map(); // key -> { count, resetAt }
  return async (req, reply) => {
    const now = Date.now();
    const key = req.user?.id ? `u${req.user.id}` : `ip${clientIp(req)}`;
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

// Request body caps. Fastify parses the body BEFORE preHandlers run, so the
// global cap applies to anonymous callers too: the old 550 MB limit let one
// unauthenticated POST exhaust the 2 GB host. Real JSON tops out around 15 KB
// (largest character sheet); only routes that post a data-URL image get more.
// Multipart uploads are capped separately (plugins/security.js).
const DEFAULT_BODY_LIMIT = 5 * 1024 * 1024;
const IMAGE_BODY_LIMIT = 25 * 1024 * 1024;

module.exports = { DEFAULT_BODY_LIMIT, IMAGE_BODY_LIMIT, clientIp, makeLimiter, isAdmin, isCourt, isOwnerOrAdmin, userOwnsCharacter, requireCourt, globalLimiter, authLimiter, moderateLimiter, uploadLimiter };
