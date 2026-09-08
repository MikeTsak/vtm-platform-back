// scripts/migrate-status.js
//
// Shows the schema version state: which migrations in migrations/list/ have
// been applied (and when), and which are still pending.
//
// `npm run migrate` applies the pending ones. initDatabase() also runs them on
// every boot, so in normal operation there is never anything pending — this is
// for checking after a deploy, or before touching the database by hand.

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const pool = require('../db');

const LIST_DIR = path.join(__dirname, '..', 'migrations', 'list');

(async () => {
  const files = fs.existsSync(LIST_DIR)
    ? fs.readdirSync(LIST_DIR).filter((f) => f.endsWith('.js')).sort()
    : [];

  let applied = new Map();
  try {
    const [rows] = await pool.query('SELECT name, applied_at FROM schema_migrations ORDER BY name');
    applied = new Map(rows.map((r) => [r.name, r.applied_at]));
  } catch (e) {
    if (e.code === 'ER_NO_SUCH_TABLE') {
      console.log('schema_migrations does not exist yet — nothing has been applied.');
    } else {
      throw e;
    }
  }

  console.log(`database: ${process.env.DB_NAME}\n`);
  let pending = 0;
  for (const file of files) {
    const mod = require(path.join(LIST_DIR, file));
    const name = (mod && mod.name) || file.replace(/\.js$/, '');
    const at = applied.get(name);
    if (at) {
      console.log(`  applied   ${name.padEnd(34)} ${new Date(at).toISOString()}`);
    } else {
      pending++;
      console.log(`  PENDING   ${name}`);
    }
  }

  // Recorded in the DB but no longer present on disk — usually a deleted or
  // renamed migration file, worth noticing.
  const known = new Set(files.map((f) => {
    const mod = require(path.join(LIST_DIR, f));
    return (mod && mod.name) || f.replace(/\.js$/, '');
  }));
  for (const name of applied.keys()) {
    if (!known.has(name)) console.log(`  orphaned  ${name.padEnd(34)} (recorded, but no file on disk)`);
  }

  console.log(`\n${files.length} migration(s), ${pending} pending.`);
  await pool.end();
})().catch((e) => {
  console.error('migrate:status failed:', e.message);
  process.exit(1);
});
