// back/migrations/list/0070_feeding_safety_before.js
// Migration 0070: remember the domain's Safety rating just before a hunt was
// applied, so the admin Feeding tab can show before -> after -> now. Older
// rows stay NULL (only their change is known).

async function columnExists(conn, table, column) {
  const [rows] = await conn.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0070_feeding_safety_before',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      try {
        await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      } catch (_) {}
      if (!(await columnExists(conn, 'feedings', 'safety_before'))) {
        await conn.query('ALTER TABLE `feedings` ADD COLUMN `safety_before` TINYINT NULL DEFAULT NULL AFTER `safety_delta`');
      }
    } finally {
      conn.release();
    }
  },
};
