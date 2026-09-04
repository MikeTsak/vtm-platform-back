// tests/setup/testDb.js
//
// Provides a fully isolated MySQL database for the integration test suite.
// Reuses the SAME connection credentials the app already uses (DB_HOST,
// DB_PORT, DB_USER, DB_PASS from .env) but points at a dedicated database —
// TEST_DB_NAME, defaulting to `<DB_NAME>_test` — so tests never read or
// write real dev/production data even when run against the same MySQL
// server. The schema is built by running the project's real, tracked
// migrations (migrations/list/*.js via migrations/runner.js), so the test
// schema can never drift from what production runs.
//
// IMPORTANT: this only works because tests/setup/env.js overrides
// process.env.DB_NAME to TEST_DB_NAME *before* anything requires ../../db —
// so db.js's own pool singleton (which authMiddleware.fastify.js and
// utils/tokenVersion.js import directly, not via dependency injection)
// transparently points at the test database too, not just the pool this
// file hands to route plugins explicitly.
require('./env');
const mysql = require('mysql2/promise');
const { runMigrations } = require('../../migrations/runner');

const TEST_DB_NAME = process.env.TEST_DB_NAME;

/** Creates the test database (if it doesn't already exist) and migrates it. Returns the app's real db.js pool. */
async function setupTestDatabase() {
  const admin = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
  });
  try {
    await admin.query(`CREATE DATABASE IF NOT EXISTS \`${TEST_DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci`);
  } finally {
    await admin.end();
  }

  // Requiring this AFTER DB_NAME is overridden (see env.js) is what makes it
  // build its pool against the test database instead of the real one.
  const pool = require('../../db');
  await runMigrations(pool);
  return pool;
}

function getTestPool() {
  return require('../../db');
}

async function teardownTestDatabase() {
  const pool = require('../../db');
  await pool.end();
}

/** Deletes all rows created by tests, in FK-safe order. Call between test files, not mid-file. */
async function truncateAll() {
  const p = getTestPool();
  await p.query('SET FOREIGN_KEY_CHECKS=0');
  const tables = [
    'xp_log', 'xp_logs', 'inventory_items', 'character_inventory', 'retainers',
    'password_resets', 'characters', 'users',
  ];
  for (const table of tables) {
    try {
      await p.query(`DELETE FROM \`${table}\``);
    } catch (e) {
      // Table may not exist in every schema version — non-fatal for test cleanup.
    }
  }
  await p.query('SET FOREIGN_KEY_CHECKS=1');
}

module.exports = { setupTestDatabase, getTestPool, teardownTestDatabase, truncateAll, TEST_DB_NAME };
