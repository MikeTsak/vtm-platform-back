// scripts/migrate.js
//
// Applies pending migrations from migrations/list/ via the versioned runner —
// the same code path initDatabase() uses on every boot, so running this by hand
// and starting the server can never disagree about what the schema is.
//
// (`npm run migrate` used to point at migrations/run-migrations.js, an older
// ad-hoc script that re-issued CREATE TABLE / ALTER statements outside the
// schema_migrations bookkeeping. It is still there as `migrate:legacy`, but
// nothing calls it in normal operation.)

// Load .env from the application root, not the current working directory, so
// this works from a cron entry, a Plesk scheduled task, or any other cwd.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const pool = require('../db');
const { runMigrations } = require('../migrations/runner');

(async () => {
  await runMigrations(pool);
  await pool.end();
})().catch((e) => {
  console.error('Migration failed:', e.message);
  process.exit(1);
});
