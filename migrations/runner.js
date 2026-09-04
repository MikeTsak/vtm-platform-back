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
async function runMigrations(pool = defaultPool) {
  await ensureMigrationsTable(pool);

  const [appliedRows] = await pool.query('SELECT name FROM schema_migrations');
  const applied = new Set(appliedRows.map((r) => r.name));

  const migrations = loadMigrations();
  let ranCount = 0;

  for (const { file, mod } of migrations) {
    if (!mod || typeof mod.up !== 'function' || !mod.name) {
      log.warn('Skipping malformed migration file', { file });
      continue;
    }
    if (applied.has(mod.name)) continue;

    log.info(`Applying migration: ${mod.name}`);
    await mod.up(pool);
    await pool.query('INSERT INTO schema_migrations (name) VALUES (?)', [mod.name]);
    ranCount++;
    log.ok(`Migration applied: ${mod.name}`);
  }

  if (ranCount === 0) {
    log.ok('Schema is up to date. No migrations to run.');
  } else {
    log.ok(`Applied ${ranCount} migration(s).`);
  }
}

module.exports = { runMigrations };
