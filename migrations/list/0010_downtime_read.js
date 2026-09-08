// Adds the downtime read-receipt column and the matching per-user ntfy opt-in.
//
// NOTE ON SHAPE: this file used to `module.exports = run` — a bare function,
// with its own `require('../../db')` at the top. migrations/runner.js requires
// `{ name, up }`, so it failed the `typeof mod.up === 'function' && mod.name`
// guard and was silently skipped ("Skipping malformed migration file") on every
// single boot — it was never recorded in schema_migrations. The columns exist
// today only because the legacy migrations/run-migrations.js adds them too.
//
// Converted to the standard shape. The body is unchanged and still checks each
// column before adding it, so applying it now is a no-op on any database that
// already went through the legacy path.
module.exports = {
  name: '0010_downtime_read',
  async up(pool) {
    const [dt] = await pool.query("SHOW COLUMNS FROM `downtimes` LIKE 'is_read'");
    if (dt.length === 0) {
      await pool.query('ALTER TABLE `downtimes` ADD COLUMN `is_read` BOOLEAN NOT NULL DEFAULT 0');
    }

    const [u] = await pool.query("SHOW COLUMNS FROM `users` LIKE 'ntfy_subscribe_downtimes'");
    if (u.length === 0) {
      await pool.query('ALTER TABLE `users` ADD COLUMN `ntfy_subscribe_downtimes` BOOLEAN NOT NULL DEFAULT 0');
    }
  },
};
