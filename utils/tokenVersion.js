// utils/tokenVersion.js
//
// JWT revocation via a per-user version number (see migrations/list/0005_*).
// Every JWT embeds the token_version it was minted with (`tv` claim);
// authRequired rejects any token whose `tv` no longer matches the DB. Bumping
// a user's version instantly revokes every token issued before the bump.
//
// A short in-memory cache keeps this from being a DB round trip on every
// single authenticated request — several frontend features poll every 4-10s
// per open tab. Revocation still takes effect within CACHE_TTL_MS for
// everyone, and immediately for anyone whose cache entry was just cleared by
// the bump itself (their next request is always a real DB read).

const pool = require('../db');

const CACHE_TTL_MS = 15_000;
const cache = new Map(); // user_id -> { version, expiresAt }

/**
 * @param {number} userId
 * @returns {Promise<number|null>} current token_version, or null if the user no longer exists
 */
async function getTokenVersion(userId) {
  const hit = cache.get(userId);
  if (hit && hit.expiresAt > Date.now()) return hit.version;

  const [rows] = await pool.query('SELECT token_version FROM users WHERE id = ?', [userId]);
  const version = rows.length ? (rows[0].token_version || 0) : null;
  cache.set(userId, { version, expiresAt: Date.now() + CACHE_TTL_MS });
  return version;
}

/**
 * Invalidate every JWT previously issued to this user.
 * @param {number} userId
 */
async function bumpTokenVersion(userId) {
  await pool.query('UPDATE users SET token_version = token_version + 1 WHERE id = ?', [userId]);
  cache.delete(userId);
}

function clearTokenVersionCache(userId) {
  if (userId === undefined) cache.clear();
  else cache.delete(userId);
}

module.exports = { getTokenVersion, bumpTokenVersion, clearTokenVersionCache };
