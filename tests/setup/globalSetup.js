// tests/setup/globalSetup.js — Vitest globalSetup: runs once, in its own
// process, before any test file. Provisions the isolated test database up
// front so failures surface fast and clearly (bad DB creds, MySQL not
// running) instead of as a confusing failure inside the first test file.
//
// Runs in a separate process from the test files themselves, so it can't
// share in-memory pool state with them — each test file provisions its own
// connection via testDb.js (cheap/idempotent: the database + schema already
// exist by the time they run).
const { setupTestDatabase, teardownTestDatabase, TEST_DB_NAME } = require('./testDb');

module.exports = async function globalSetup() {
  console.log(`\n[tests] Provisioning isolated test database "${TEST_DB_NAME}"...`);
  await setupTestDatabase();
  await teardownTestDatabase();
  console.log('[tests] Test database ready.\n');
};
