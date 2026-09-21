// migrations/list/0022_premonition_warnings.js
//
// Adds `warnings` TEXT column to the `premonitions` table to store optional
// content warning tags (e.g. Gore, Suicide, Extreme Violence, Infanticide) as JSON.

async function columnExists(pool, table, column) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0022_premonition_warnings',
  async up(pool) {
    if (await columnExists(pool, 'premonitions', 'warnings')) return;
    await pool.query(
      'ALTER TABLE premonitions ADD COLUMN `warnings` TEXT NULL DEFAULT NULL AFTER `content_url`'
    );
  },
};
