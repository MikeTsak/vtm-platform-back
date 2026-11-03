// utils/idempotency.js
//
// Real idempotency-key protection for every POST route (installIdempotency
// below, minus NOT_IDEMPOTENT). Disabling the button is not enough: under lag
// a request times out in the browser, the player clicks again, and the server
// later runs both. Rows are purged after RETENTION_HOURS (nightly job).
//
// installIdempotency appends both hooks to each POST route's own options,
// after its auth; a route may also wire them by hand:
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
const zlib = require('zlib');
const { log } = require('../logger');

const RETENTION_HOURS = 48; // long enough to cover any realistic client retry; not "forever"
const IN_FLIGHT_WAIT_MS = 10000; // how long a duplicate waits for the first request to finish
const STALE_CLAIM_SECONDS = 60;  // a claim never completed after this long was left by a crash

const SCOPE = 'idempotency_key = ? AND user_id = ? AND request_path = ?';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The key is claimed BEFORE the handler runs, by inserting its row with a
// NULL response_code (the unique (key, user, path) index lets exactly one
// concurrent request win). Checking first and saving afterwards, as this used
// to, left a gap: a duplicate arriving while the first was still running
// found no row and executed a second time. Now the loser waits for the
// winner's response and replays it.
async function idempotencyCheck(req, reply) {
  const key = req.headers['idempotency-key'];
  if (!key) return; // this route wasn't called with a key — behave normally
  if (!req.user) return; // public route (login, register...): nothing to scope the key to

  // req.url (NOT req.routeOptions.url) deliberately — the latter is the
  // route *pattern* ("/api/admin/characters/:id/xp/spend"), which would
  // conflate two different admin targets (character 42 vs 43) into the same
  // scope. req.url carries the actual resolved path.
  const scope = [key, req.user.id, req.url];
  const deadline = Date.now() + IN_FLIGHT_WAIT_MS;
  try {
    for (;;) {
      try {
        await pool.query(
          'INSERT INTO idempotency_keys (idempotency_key, user_id, request_path, request_method) VALUES (?, ?, ?, ?)',
          [...scope, req.method]
        );
        req.idempotencyClaimed = true;
        return;
      } catch (e) {
        if (e.code !== 'ER_DUP_ENTRY') throw e;
      }

      const [[row]] = await pool.query(
        `SELECT response_code, response_body, created_at < NOW() - INTERVAL ? SECOND AS stale
         FROM idempotency_keys WHERE ${SCOPE} LIMIT 1`,
        [STALE_CLAIM_SECONDS, ...scope]
      );
      if (!row) continue; // the other request failed and released its claim: take it
      if (row.response_code !== null) {
        let body = row.response_body;
        try {
          body = JSON.parse(body);
          if (body && body.type === 'Buffer' && Array.isArray(body.data)) {
            let buf = Buffer.from(body.data);
            try {
              buf = zlib.brotliDecompressSync(buf);
            } catch {
              try { buf = zlib.gunzipSync(buf); } catch {}
            }
            body = JSON.parse(buf.toString('utf8'));
          }
        } catch { /* stored as-is */ }
        reply.header('X-Idempotent-Replay', 'true');
        return reply.status(row.response_code).send(body);
      }
      if (row.stale) {
        await pool.query(`DELETE FROM idempotency_keys WHERE ${SCOPE} AND response_code IS NULL`, scope);
        continue;
      }
      if (Date.now() >= deadline) {
        // Tells the client to keep this key for its next try (core/api.js).
        reply.header('X-Idempotent-Pending', 'true');
        return reply.status(409).send({ error: 'This request is still being processed. Try again in a moment.' });
      }
      await sleep(250);
    }
  } catch (e) {
    log.err('Idempotency check failed : proceeding without it', { error: e.message });
  }
}

async function idempotencySave(req, reply, payload) {
  // Only the request that claimed the key records it: a replay or a 409 from
  // idempotencyCheck must not overwrite the stored response.
  if (!req.idempotencyClaimed) return payload;

  const scope = [req.headers['idempotency-key'], req.user.id, req.url];
  // A stream (file download) can't be stored for replay: release the claim.
  if (payload && typeof payload.pipe === 'function') {
    pool.query(`DELETE FROM idempotency_keys WHERE ${SCOPE}`, scope)
      .catch((e) => log.err('Failed to release idempotency claim', { error: e.message }));
    return payload;
  }
  // Not awaited. A retry that lands before this write finds the claim still
  // open and waits for it. Awaiting here would also hold the hook past the
  // handler's return, and Fastify then sends a second, empty reply for
  // handlers that call reply.send() without `return reply`.
  let bodyToStore = payload;
  if (Buffer.isBuffer(payload)) {
    const enc = reply.getHeader('content-encoding');
    try {
      if (enc === 'br') {
        bodyToStore = zlib.brotliDecompressSync(payload).toString('utf8');
      } else if (enc === 'gzip') {
        bodyToStore = zlib.gunzipSync(payload).toString('utf8');
      } else if (enc === 'deflate') {
        bodyToStore = zlib.inflateSync(payload).toString('utf8');
      } else {
        bodyToStore = payload.toString('utf8');
      }
    } catch (e) {
      log.err('Failed to decompress payload for idempotency save', { error: e.message });
      bodyToStore = payload.toString('utf8');
    }
  } else if (typeof payload !== 'string') {
    bodyToStore = JSON.stringify(payload);
  }

  const write = reply.statusCode >= 500
    // Release the claim: a server error should be safe (and expected) to
    // retry, not permanently pinned as "the" response for this key.
    ? pool.query(`DELETE FROM idempotency_keys WHERE ${SCOPE}`, scope)
    : pool.query(
      `UPDATE idempotency_keys SET response_code = ?, response_body = ? WHERE ${SCOPE}`,
      [reply.statusCode, bodyToStore, ...scope]
    );
  write.catch((e) => log.err('Failed to save idempotency response', { error: e.message }));
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

// POSTs that are harmless to repeat and frequent enough that a row per call
// isn't worth it: read marks, heartbeats, reads sent as POST, the session login.
const NOT_IDEMPOTENT = /\/(read|delivered|heartbeat|preview|reactions\/batch)$|^\/api\/auth\//;

// Every POST route honours an Idempotency-Key (the front sends one with every
// POST, core/api.js), checked after the route's own auth. Under lag a player's
// second click, after the first timed out, used to run again once the server
// caught up: a downtime filed 3 times, an item created twice (2026-11-03).
// Call before the routes are registered: onRoute only sees routes added later.
function installIdempotency(fastify) {
  fastify.addHook('onRoute', (route) => {
    const methods = [].concat(route.method);
    if (!methods.includes('POST') || NOT_IDEMPOTENT.test(route.url)) return;
    const pre = [].concat(route.preHandler ?? []);
    if (pre.includes(idempotencyCheck)) return; // wired by hand already
    route.preHandler = [...pre, idempotencyCheck];
    route.onSend = [...[].concat(route.onSend ?? []), idempotencySave];
  });
}

module.exports = { idempotencyCheck, idempotencySave, installIdempotency, purgeOldIdempotencyKeys, RETENTION_HOURS };
