const fs = require('fs');
const path = require('path');
const defaultPool = require('../db');
const { log } = require('../logger');

const LIST_DIR = path.join(__dirname, 'list');

async function ensureMigrationsTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS \`schema_migrations\` (
      \`id\` int(11) NOT NULL AUTO_INCREMENT,
      \`name\` varchar(255) NOT NULL,
      \`applied_at\` timestamp NOT NULL DEFAULT current_timestamp(),
      PRIMARY KEY (\`id\`),
      UNIQUE KEY \`name\` (\`name\`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);
}

function loadMigrations() {
  if (!fs.existsSync(LIST_DIR)) return [];
  return fs
    .readdirSync(LIST_DIR)
    .filter((f) => f.endsWith('.js'))
    .sort()
    .map((f) => ({ file: f, mod: require(path.join(LIST_DIR, f)) }));
}

// Applies every migration in migrations/list that isn't already recorded in
// schema_migrations, in filename order. Each migration only ever runs once —
// if it throws, it is NOT recorded as applied, so the next boot retries it.
//
// Accepts an optional pool so the test suite can build a schema-identical,
// fully isolated test database by running the exact same migrations against
// a different pool/database — see back/tests/setup/testDb.js.
//
// `onProgress` receives { phase: 'start' | 'applying' | 'applied', ... } so a
// caller (the remote `npm run migrations` stream) can drive a progress bar.
// `dryRun` reports what is pending without applying anything. Returns the
// names of the migrations that were (or, on a dry run, would be) applied.
async function runMigrations(pool = defaultPool, { onProgress, dryRun = false } = {}) {
  await ensureMigrationsTable(pool);

  const [appliedRows] = await pool.query('SELECT name FROM schema_migrations');
  const applied = new Set(appliedRows.map((r) => r.name));

  const pending = [];
  for (const { file, mod } of loadMigrations()) {
    if (!mod || typeof mod.up !== 'function' || !mod.name) {
      log.warn('Skipping malformed migration file', { file });
      continue;
    }
    if (!applied.has(mod.name)) pending.push(mod);
  }

  const total = pending.length;
  onProgress?.({ phase: 'start', total, pending: pending.map((m) => m.name), appliedCount: applied.size });
  if (dryRun) return pending.map((m) => m.name);

  for (let i = 0; i < total; i++) {
    const mod = pending[i];
    log.info(`Applying migration: ${mod.name}`);
    onProgress?.({ phase: 'applying', index: i, total, name: mod.name });
    await mod.up(pool);
    await pool.query('INSERT INTO schema_migrations (name) VALUES (?)', [mod.name]);
    log.ok(`Migration applied: ${mod.name}`);
    onProgress?.({ phase: 'applied', index: i + 1, total, name: mod.name });
  }

  if (total === 0) {
    log.ok('Schema is up to date. No migrations to run.');
  } else {
    log.ok(`Applied ${total} migration(s).`);
  }
  return pending.map((m) => m.name);
}

module.exports = { runMigrations };
