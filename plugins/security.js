// plugins/security.js
//
// Transport-level plugins: body parsing limits, security headers, CORS,
// cookies, static assets, compression.
//
// Wrapped in fastify-plugin so everything it registers (notably the cookie
// and multipart decorators) lands on the root instance and is therefore
// visible to every route module registered alongside it.

const fp = require('fastify-plugin');
const path = require('path');
const helmet = require('@fastify/helmet');
const cors = require('@fastify/cors');
const multipart = require('@fastify/multipart');
const compression = require('@fastify/compress');
const { corsOrigin } = require('../config/cors');
const { pluginLoaded } = require('../utils/bootBanner');

module.exports = fp(async function security(fastify) {
  fastify.register(multipart, { limits: { fileSize: 50 * 1024 * 1024 } });
  fastify.after(() => pluginLoaded('multipart'));

  // This API only serves two HTML surfaces itself: the "/" status page and Swagger UI
  // (/api-docs, which sets its own CSP for its static assets via `staticCSP`).
  // The React SPA is a separately-hosted static build (see front/public/.htaccess for
  // its CSP) — this header has no effect on it.
  fastify.register(helmet, {
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    crossOriginEmbedderPolicy: false, // would break Swagger UI's cross-origin assets for no benefit here
    enableCSPNonces: true, // exposes reply.cspNonce.{script,style} for server-rendered HTML
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"], // nonce auto-appended per request; no inline/eval anywhere
        styleSrc: ["'self'"],  // nonce auto-appended per request (see views/status.html)
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
  });
  fastify.after(() => pluginLoaded('helmet'));

  fastify.register(cors, {
    origin: corsOrigin,
    credentials: true,
    methods: ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cache-Control', 'Pragma', 'Expires', 'Idempotency-Key', 'X-Requested-With', 'Accept'],
  });
  fastify.after(() => pluginLoaded('cors'));

  // Session JWT lives in an httpOnly cookie (see utils/authCookie.js) — this
  // decorates req.cookies / reply.setCookie / reply.clearCookie.
  fastify.register(require('@fastify/cookie'));
  fastify.after(() => pluginLoaded('cookie'));

  fastify.register(require('@fastify/static'), {
    root: path.join(__dirname, '..', 'public'),
    prefix: '/public/',
  });
  fastify.after(() => pluginLoaded('static'));

  // Registered NON-global on purpose: it decorates reply.compress() but adds no
  // onSend hook, so no route is compressed unless it asks.
  //
  // Why: Fastify requires an async handler that calls reply.send() to also
  // `return reply` (or `return reply.send(...)`). Handlers across this codebase
  // instead end with a bare `reply.send(...)` — ~490 call sites. With a global
  // compression onSend hook in play, reply.send() no longer completes
  // synchronously, so the handler's promise resolves with `undefined` while the
  // reply is still in flight and Fastify sends a SECOND, empty response. The
  // client then gets `Content-Encoding: gzip` with `Content-Length: 0` and an
  // empty body — but only for payloads over the 1KB compression threshold,
  // which is why small responses looked fine and every large list (admin users,
  // rosters, claims, coteries) came back blank.
  //
  // This was latent before the routes moved into plugins: inline routes were
  // added to the root instance synchronously, before this plugin's hook was
  // installed during ready(), so global compression never actually applied to
  // them. Turning it on for the first time is what surfaced the handler bug.
  //
  // To switch global compression back on, the handlers must be fixed first —
  // every `reply.send(x)` that ends an async handler needs to become
  // `return reply.send(x)`.
  fastify.register(compression, { global: false });
  fastify.after(() => pluginLoaded('compression'));
});
