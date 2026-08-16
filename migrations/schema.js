const { log } = require('../logger');
const { runMigrations } = require('./runner');

// Runs any migration in migrations/list/ that hasn't been applied yet
// (tracked in the schema_migrations table). On an already-initialized
// database this is a single SELECT after the first boot, instead of
// re-issuing 70 CREATE TABLE statements and two ALTER-and-catch calls
// on every startup.
async function initDatabase() {
  try {
    await runMigrations();
  } catch (e) {
    log.err('Failed to init database', { message: e.message });
  }
}

module.exports = { initDatabase };
