// plugins/observability.js
//
// Request/response logging, freeze forensics, the no-store policy for admin
// endpoints, graceful pool shutdown, and the catch-all error handler.
//
// Wrapped in fastify-plugin so the hooks and the error handler attach to the
// root instance and therefore cover every route in the app.

const fp = require('fastify-plugin');
const { monitorEventLoopDelay } = require('perf_hooks');
const { log, vitals } = require('../logger');
const { reportErrorToDiscord } = require('../services/discord');

// Endpoints that would otherwise log themselves being polled, forever.
const SILENT_PREFIXES = ['/api/admin/logs'];
const isSilent = (url) => SILENT_PREFIXES.some((p) => url.startsWith(p));
const SLOW_MS = 1000;
const pathOf = (url) => String(url).split('?')[0]; // query strings can carry tokens

// Requests not yet answered: request.id -> { method, url, at }.
const inFlight = new Map();
const oldest = (now, n) => [...inFlight.values()]
  .sort((a, b) => a.at - b.at)
  .slice(0, n)
  .map((r) => `${r.method} ${r.url} ${Math.round((now - r.at) / 1000)}s`);

module.exports = fp(async function observability(fastify) {
  fastify.addHook('onRequest', (request, reply, done) => {
    inFlight.set(request.id, { method: request.method, url: pathOf(request.url), at: Date.now() });
    done();
  });
  fastify.addHook('onRequestAbort', (request, done) => {
    inFlight.delete(request.id);
    done();
  });

  // Errors, refusals and slow answers only: one line per request filled the
  // file in hours, and what was answered quickly says nothing about a freeze.
  fastify.addHook('onResponse', (request, reply, done) => {
    inFlight.delete(request.id);
    if (isSilent(request.url)) return done();

    const ms = Math.round(reply.elapsedTime);
    const code = reply.statusCode;
    const line = `${code} ${request.method} ${pathOf(request.url)} (${ms}ms)`;
    const base = { status: code, ms };

    if (code >= 500) log.err(line, base);
    else if (code >= 400) log.warn(line, base, 'warn');
    else if (ms >= SLOW_MS) log.warn(`slow ${line}`, base, 'warn');

    done();
  });

  // Admin responses must never be cached — a 304 from an intermediary is
  // indistinguishable from stale data in the admin panel.
  fastify.addHook('preHandler', async (request, reply) => {
    if (request.url.startsWith('/api/admin')) {
      reply.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    }
  });

  fastify.addHook('onClose', async (instance, done) => {
    try {
      await instance.db.end();
      log.info('Database pool closed gracefully.');
    } catch (err) {
      log.err('Error closing database pool', { error: err.message });
    }
    done();
  });

  fastify.setErrorHandler(async (error, request, reply) => {
    // If it's a validation error from our schemas, it has a validation array
    if (error.validation) {
      return reply.status(400).send({ error: 'Validation Error', details: error.validation });
    }

    // Fastify's own client errors (413 body too large, 415 content type, 400
    // malformed JSON...) are the caller's fault: answer with their status, and
    // don't page Discord for them — they used to surface as 500s.
    if (error.statusCode >= 400 && error.statusCode < 500) {
      return reply.status(error.statusCode).send({ error: error.message });
    }

    log.err('Unhandled Fastify Error', { error: error.message, stack: error.stack, url: pathOf(request.url) });
    await reportErrorToDiscord(`Fastify Route ${pathOf(request.url)}`, error).catch(() => { });

    reply.status(500).send({ error: 'Internal Server Error' });
  });
});

/**
 * Freeze forensics, started once by the server process. Every minute a
 * `health` line: memory, both DB pools (see db.js poolStats), the longest
 * event-loop stall, open requests and running jobs. Between them, a warning
 * straight away when the event loop was blocked 2 s+ or callers have queued
 * 5 s+ for a DB connection, naming the oldest open requests. A process that
 * dies without an "exit" line was killed from outside (the host's limits).
 */
function startHealthWatch({ runningJobs = () => [] } = {}) {
  const pool = require('../db');
  const loop = monitorEventLoopDelay({ resolution: 20 });
  loop.enable();
  let last = Date.now();
  let queuedSince = 0;
  let lastAlarm = 0;
  let lastHealth = Date.now();

  setInterval(() => {
    const now = Date.now();
    const lag = now - last - 1000;
    last = now;
    const db = pool.poolStats();
    queuedSince = db.queued ? (queuedSince || now) : 0;

    if (lag >= 2000) {
      log.warn(`Event loop was blocked for ${lag} ms`, { pool: db, open: inFlight.size, oldest: oldest(now, 5), jobs: runningJobs() }, 'warn');
    } else if (queuedSince && now - queuedSince >= 5000 && now - lastAlarm >= 30000) {
      lastAlarm = now;
      log.warn(`Requests have waited ${Math.round((now - queuedSince) / 1000)} s for a database connection`,
        { pool: db, open: inFlight.size, oldest: oldest(now, 5), jobs: runningJobs() }, 'warn');
    }

    if (now - lastHealth >= 60 * 1000) { // by the clock: a blocked loop skips ticks
      lastHealth = now;
      log.info(`health ${vitals()}`, {
        pool: db, lockPool: pool.poolStats(pool.lockPool), open: inFlight.size, oldest: oldest(now, 3),
        loopMaxMs: Math.round(loop.max / 1e6), jobs: runningJobs(),
      });
      loop.reset();
      // A hijacked or streamed reply can skip onResponse: forget it after 10 min.
      for (const [id, r] of inFlight) if (now - r.at > 10 * 60 * 1000) inFlight.delete(id);
    }
  }, 1000).unref();
}

module.exports.startHealthWatch = startHealthWatch;
