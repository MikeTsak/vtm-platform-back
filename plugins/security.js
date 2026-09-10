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
const { corsOrigin } = require('../config/cors');
const { pluginLoaded } = require('../utils/bootBanner');
const { compressionHook } = require('../utils/compression');

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

  // Response compression (gzip / brotli for text payloads).
  //
  // This is a synchronous onSend hook (see utils/compression.js), NOT
  // `@fastify/compress` in global mode. That plugin's global hook makes
  // reply.send() resolve asynchronously, and ~490 handlers here end with a
  // bare `reply.send(x)` / `reply.status(n).json(x)` instead of
  // `return reply.send(x)` — their promises then settle as `undefined` mid-
  // flight and Fastify ships a second, empty response (Content-Encoding set,
  // Content-Length 0, no body). That footgun is why compression sat disabled.
  // A sync hook sidesteps it entirely: the onSend chain runs in the same tick,
  // before the handler's promise resolution, so reply.send() stays synchronous
  // from Fastify's point of view. zlib sync deflate is ~1–3ms even for this
  // API's largest JSON responses.
  fastify.addHook('onSend', compressionHook);
  fastify.after(() => pluginLoaded('compression'));
});
