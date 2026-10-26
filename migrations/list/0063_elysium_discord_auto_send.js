// back/migrations/list/0063_elysium_discord_auto_send.js
// Migration 0063: Track Elysium invitation Discord broadcasts and store pre-rendered card images
// Supports automatic Discord broadcast on the Monday before Elysium gatherings
// and immediate auto-send when published on or after the Monday of the event.

async function columnExists(conn, table, column) {
  const [rows] = await conn.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0063_elysium_discord_auto_send',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      if (!(await columnExists(conn, 'elysium_invitations', 'discord_posted_at'))) {
        await conn.query('ALTER TABLE `elysium_invitations` ADD COLUMN `discord_posted_at` DATETIME NULL DEFAULT NULL');
      }
      if (!(await columnExists(conn, 'elysium_invitations', 'rendered_card_data'))) {
        await conn.query('ALTER TABLE `elysium_invitations` ADD COLUMN `rendered_card_data` LONGTEXT NULL DEFAULT NULL');
      }
    } finally {
      conn.release();
    }
  },
};
