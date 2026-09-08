// plugins/observability.js
//
// Request/response logging, the no-store policy for admin endpoints, graceful
// pool shutdown, and the catch-all error handler.
//
// Wrapped in fastify-plugin so the hooks and the error handler attach to the
// root instance and therefore cover every route in the app.

const fp = require('fastify-plugin');
const { log } = require('../logger');
const { reportErrorToDiscord } = require('../services/discord');

// Endpoints that would otherwise log themselves being polled, forever.
const SILENT_PREFIXES = ['/api/admin/logs'];
const isSilent = (url) => SILENT_PREFIXES.some((p) => url.startsWith(p));

module.exports = fp(async function observability(fastify) {
  fastify.addHook('onRequest', (request, reply, done) => {
    if (isSilent(request.url)) return done();

    log.req(`${request.method} ${request.url}`, { ip: request.ip, ua: request.headers['user-agent'] });
    done();
  });

  fastify.addHook('onResponse', (request, reply, done) => {
    if (isSilent(request.url)) return done();

    const ms = Math.round(reply.getResponseTime());
    const code = reply.statusCode;
    const base = { status: code, ms };

    if (code >= 500) log.err(`${code} ${request.method} ${request.url} (${ms}ms)`, base);
    else if (code >= 400) log.warn(`${code} ${request.method} ${request.url} (${ms}ms)`, base, 'warn');
    else log.ok(`${code} ${request.method} ${request.url} (${ms}ms)`, base);

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

    log.err('Unhandled Fastify Error', { error: error.message, stack: error.stack, url: request.url });
    await reportErrorToDiscord(`Fastify Route ${request.url}`, error).catch(() => { });

    reply.status(500).send({ error: 'Internal Server Error' });
  });
});
