// back/migrations/list/0071_news_edited_at.js
// Migration 0071: when a published article or decree was last edited (the
// one-hour edit window, PUT /api/news/:id), shown as "edited".

async function columnExists(conn, table, column) {
  const [rows] = await conn.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0071_news_edited_at',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      try {
        await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      } catch (_) {}
      if (!(await columnExists(conn, 'news_entries', 'edited_at'))) {
        await conn.query('ALTER TABLE `news_entries` ADD COLUMN `edited_at` DATETIME NULL DEFAULT NULL');
      }
    } finally {
      conn.release();
    }
  },
};
