// app.js
//
// Builds the Fastify instance: decorators, infrastructure plugins, and every
// route module. Deliberately does NOT listen, attach socket.io, or start cron
// jobs — that is server.fastify.js's job — so the app can be constructed in
// isolation (tests, route dumps, swagger generation) without opening a port.

const pool = require('./db');
const { log } = require('./logger');
const { authRequired, optionalAuth, requireAdmin } = require('./authMiddleware.fastify');
const { requireCourt, authLimiter, moderateLimiter, uploadLimiter } = require('./services/guards');
const { broadcastNtfyAlert } = require('./utils/ntfy');
const { sendPushNotification } = require('./services/push');
const { getMimeType, imageClient } = require('./services/media');
const { sendResetEmailWithEmailJS, maskEmail } = require('./services/email');
const { validateRetainerSheet } = require('./utils/retainerValidation');
const { startBootProgress } = require('./utils/bootBanner');
const { ROUTE_MODULES, registerRoutes } = require('./routes');

const sharp = require('sharp');
// Optimize sharp for low memory environments (like 2GB Plesk)
sharp.cache(false);
sharp.concurrency(1);

// Named so the boot progress bar can count them up front.
const INFRA_PLUGINS = ['multipart', 'helmet', 'cors', 'cookie', 'static', 'compression', 'swagger', 'swagger-ui'];

function buildApp(overrides = {}) {
  const fastify = require('fastify')({
    logger: false,
    bodyLimit: 73400320,
  });

  startBootProgress([...INFRA_PLUGINS, ...ROUTE_MODULES.map((m) => m.name)]);

  fastify.decorate('db', pool);

  // Route handlers across the app call `reply.status(x).json(y)` — an
  // Express-ism inherited from the pre-Fastify server. This shim keeps those
  // call sites working; without it every one of them throws.
  fastify.decorateReply('json', function (payload) {
    return this.send(payload);
  });

  fastify.register(require('./plugins/observability'));
  fastify.register(require('./plugins/security'));
  fastify.register(require('./plugins/docs'));

  // The shared dependency bundle handed to every route module. Keep it small:
  // anything stateless belongs in a require() inside the module that uses it.
  const deps = {
    pool,
    log,
    authRequired,
    optionalAuth,
    requireAdmin,
    requireCourt,
    authLimiter,
    moderateLimiter,
    uploadLimiter,
    broadcastNtfyAlert,
    sendPushNotification,
    getMimeType,
    imageClient,
    sharp,
    validateRetainerSheet,
    maskEmail,
    sendResetEmailWithEmailJS,
    ...overrides,
  };

  registerRoutes(fastify, deps);

  return fastify;
}

module.exports = { buildApp, INFRA_PLUGINS };
