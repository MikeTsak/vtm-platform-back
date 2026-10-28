// back/migrations/list/0066_news_entries_views.js
// Migration 0066: Add views column to news_entries table for public page view tracking

async function columnExists(conn, table, column) {
  const [rows] = await conn.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0066_news_entries_views',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      try {
        await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      } catch (_) {}

      if (!(await columnExists(conn, 'news_entries', 'views'))) {
        await conn.query('ALTER TABLE `news_entries` ADD COLUMN `views` INT UNSIGNED NOT NULL DEFAULT 0');
      }
    } finally {
      conn.release();
    }
  },
};
