// tests/setup/testApp.js
//
// Builds a real Fastify instance for integration tests: the actual
// authMiddleware/route-plugin code the production server runs, wired to the
// isolated test database from testDb.js. External side effects (ntfy push,
// EmailJS, image uploads) are stubbed — everything auth/DB/authorization
// related is the real production code, unmocked.

// Must run before authMiddleware.fastify.js (below) is required — it
// transitively requires ../db, whose pool is built from process.env.DB_*
// the moment it's first required. See env.js for the full rationale.
require('./env');
const fastify = require('fastify');
const fastifyCookie = require('@fastify/cookie');
const { authRequired, requireAdmin } = require('../../authMiddleware.fastify');
const { validateRetainerSheet } = require('../../utils/retainerValidation');

// Quiet by default; set VERBOSE_TEST_LOGS=1 to see route-level log output
// while debugging a failing test.
const VERBOSE = process.env.VERBOSE_TEST_LOGS === '1';
const noop = () => {};
const testLog = {
  adm: VERBOSE ? console.log : noop,
  auth: VERBOSE ? console.log : noop,
  char: VERBOSE ? console.log : noop,
  err: VERBOSE ? console.error : noop,
  mail: VERBOSE ? console.log : noop,
  ok: VERBOSE ? console.log : noop,
  warn: VERBOSE ? console.warn : noop,
  xp: VERBOSE ? console.log : noop,
};

const maskEmail = (email) => {
  if (!email || typeof email !== 'string') return email;
  const [u, d] = email.trim().toLowerCase().split('@');
  if (!d) return email;
  const maskedUser = u.length <= 2 ? (u[0] || '') + '*' : u[0] + '*'.repeat(u.length - 2) + u.slice(-1);
  return `${maskedUser}@${d}`;
};

// No-op stand-ins for the "dummy rate limiter" preHandlers production also
// currently uses (see back/server.fastify.js) — real rate limiting being
// disabled is a separate, already-flagged issue, not something these tests
// assert on.
const noopLimiter = async () => {};

/**
 * @param {import('mysql2/promise').Pool} pool the isolated test-database pool
 * @returns {import('fastify').FastifyInstance}
 */
function buildTestApp(pool) {
  const app = fastify({ logger: false });

  // Route handlers across the app call `reply.status(x).json(y)` (an
  // Express-ism) — production only works because server.fastify.js adds
  // this shim itself. Mirror it here or every error path 500s in tests.
  app.decorateReply('json', function (payload) {
    return this.send(payload);
  });

  // Captures every "sent" password-reset email instead of actually sending
  // one, so tests can pull the real reset link/token out of
  // app.testResetEmails and exercise the full forgot -> reset flow.
  app.testResetEmails = [];

  app.register(fastifyCookie);
  // routes/auth.js calls fastify.db.query(...) rather than the pool passed in
  // opts (matches how it's decorated in the real server.fastify.js).
  app.decorate('db', pool);

  app.register(require('../../routes/auth'), {
    prefix: '/api/auth',
    pool,
    log: testLog,
    maskEmail,
    authRequired,
    authLimiter: noopLimiter,
    broadcastNtfyAlert: noop, // never hit a real ntfy.sh topic from tests
    sendResetEmailWithEmailJS: async (payload) => {
      app.testResetEmails.push(payload);
    },
  });

  app.register(require('../../routes/characters'), {
    pool,
    log: testLog,
    authRequired,
    requireAdmin,
    moderateLimiter: noopLimiter,
    validateRetainerSheet,
    getMimeType: () => 'image/webp',
    sharp: null, // not exercised by the routes these tests cover
    imageClient: { uploadImage: async () => ({ success: false }) },
    broadcastNtfyAlert: noop,
  });

  app.register(require('../../routes/characterXp'), {
    pool,
    log: testLog,
    authRequired,
  });

  return app;
}

module.exports = { buildTestApp };
