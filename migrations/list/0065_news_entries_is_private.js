// back/migrations/list/0065_news_entries_is_private.js
// Migration 0065: Add is_private column to news_entries table if missing

async function columnExists(conn, table, column) {
  const [rows] = await conn.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0065_news_entries_is_private',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      if (!(await columnExists(conn, 'news_entries', 'is_private'))) {
        await conn.query('ALTER TABLE `news_entries` ADD COLUMN `is_private` TINYINT(1) NOT NULL DEFAULT 0');
      }
    } finally {
      conn.release();
    }
  },
};
