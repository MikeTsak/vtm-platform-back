const pool = require('../../db');
const { log } = require('../../logger');

async function run() {
  log.info('Running migration: 0010_downtime_read.js');
  try {
    // Check if is_read already exists on downtimes
    let [rows] = await pool.query("SHOW COLUMNS FROM \`downtimes\` LIKE 'is_read'");
    if (rows.length === 0) {
      await pool.query("ALTER TABLE \`downtimes\` ADD COLUMN \`is_read\` BOOLEAN NOT NULL DEFAULT 0");
      log.info('Added is_read to downtimes');
    }

    // Check if ntfy_subscribe_downtimes already exists on users
    [rows] = await pool.query("SHOW COLUMNS FROM \`users\` LIKE 'ntfy_subscribe_downtimes'");
    if (rows.length === 0) {
      await pool.query("ALTER TABLE \`users\` ADD COLUMN \`ntfy_subscribe_downtimes\` BOOLEAN NOT NULL DEFAULT 0");
      log.info('Added ntfy_subscribe_downtimes to users');
    }

    log.info('Migration 0010_downtime_read.js completed successfully.');
  } catch (err) {
    log.err('Migration 0010_downtime_read.js failed', { error: err.message });
    throw err;
  }
}

module.exports = run;
