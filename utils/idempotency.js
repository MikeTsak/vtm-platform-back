// utils/idempotency.js
//
// Real idempotency-key protection, scoped to a short list of sensitive
// mutations where a duplicate would cause actual harm (XP is a limited,
// spendable resource — see routes/characterXp.js and the admin XP-spend
// routes in server.fastify.js). Everywhere else, double-submit protection
// is just disabling the button while its mutation is in flight — the
// standard, sufficient pattern, and not worth an unbounded DB table for
// every mutating endpoint in the app.
//
// Wire both into a route's options directly (NOT as a global hook):
//   fastify.post('/path', {
//     preHandler: [authRequired, idempotencyCheck],
//     onSend: [idempotencySave],
//   }, handler)
//
// idempotencyCheck must run AFTER authRequired — it relies on req.user
// already being verified, so the cache lookup is scoped to the
// server-verified caller, never a client-claimed identity embedded in the
// key string itself. A previous version of this file scoped only by
// idempotency_key as a global PRIMARY KEY, which meant one user's cached
// response could theoretically be served back to a different request that
// happened to send the same key string; scoping by (key, user, path) here
// closes that.

const pool = require('../db');
const { log } = require('../logger');

const RETENTION_HOURS = 48; // long enough to cover any realistic client retry; not "forever"

async function idempotencyCheck(req, reply) {
  const key = req.headers['idempotency-key'];
  if (!key) return; // this route wasn't called with a key — behave normally

  // req.url (NOT req.routeOptions.url) deliberately — the latter is the
  // route *pattern* ("/api/admin/characters/:id/xp/spend"), which would
  // conflate two different admin targets (character 42 vs 43) into the same
  // scope. req.url carries the actual resolved path.
  const path = req.url;
  try {
    const [rows] = await pool.query(
      'SELECT response_code, response_body FROM idempotency_keys WHERE idempotency_key = ? AND user_id = ? AND request_path = ? LIMIT 1',
      [key, req.user.id, path]
    );
    if (rows.length) {
      let body = rows[0].response_body;
      try { body = JSON.parse(body); } catch { /* stored as-is */ }
      reply.header('X-Idempotent-Replay', 'true');
      return reply.status(rows[0].response_code).send(body);
    }
  } catch (e) {
    log.err('Idempotency check failed — proceeding without it', { error: e.message });
  }
}

async function idempotencySave(req, reply, payload) {
  const key = req.headers['idempotency-key'];
  if (!key || !req.user) return payload;
  // Don't cache 5xx — a server error should be safe (and expected) to retry,
  // not permanently pinned as "the" response for this key.
  if (reply.statusCode >= 500) return payload;

  const path = req.url; // see the matching comment in idempotencyCheck above
  pool.query(
    `INSERT INTO idempotency_keys (idempotency_key, user_id, request_path, request_method, response_code, response_body)
     VALUES (?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE response_code = VALUES(response_code), response_body = VALUES(response_body)`,
    [key, req.user.id, path, req.method, reply.statusCode, typeof payload === 'string' ? payload : JSON.stringify(payload)]
  ).catch((e) => log.err('Failed to save idempotency response', { error: e.message }));

  return payload;
}

/** Deletes idempotency rows older than the retention window. Meant to run on a nightly cron. */
async function purgeOldIdempotencyKeys() {
  const [result] = await pool.query(
    'DELETE FROM idempotency_keys WHERE created_at < (NOW() - INTERVAL ? HOUR)',
    [RETENTION_HOURS]
  );
  return result.affectedRows;
}

module.exports = { idempotencyCheck, idempotencySave, purgeOldIdempotencyKeys, RETENTION_HOURS };
