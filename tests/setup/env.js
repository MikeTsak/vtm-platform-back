// tests/setup/env.js
//
// MUST be required before anything that touches back/db.js (directly or
// transitively, e.g. authMiddleware.fastify.js -> utils/tokenVersion.js).
// db.js builds its connection pool once, at require time, from
// process.env.DB_*. Overriding DB_NAME here — before that first require —
// makes every module that imports the app's normal db.js singleton (not
// just the ones tests explicitly wire up) transparently point at the
// isolated test database instead of real dev/production data.
//
// Loaded as a Vitest `setupFiles` entry (runs first, per test-file worker)
// AND required directly by tests/setup/globalSetup.js, which Vitest runs in
// a separate process where `setupFiles` doesn't apply.
require('dotenv').config();

const REAL_DB_NAME = process.env.DB_NAME || 'vtm';
process.env.TEST_DB_NAME = process.env.TEST_DB_NAME || `${REAL_DB_NAME}_test`;
process.env.DB_NAME = process.env.TEST_DB_NAME;
