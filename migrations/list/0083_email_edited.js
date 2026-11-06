// back/migrations/list/0083_email_edited.js
// Migration 0083: a Storyteller can edit any Surface Web email
// (routes/emails.js). An edited one says so, as SchreckNet messages do
// (chat_messages.edited), so a player can tell their words were changed.
// Separate from 0082 so a database given 0082's SQL by hand still gets it.
module.exports = {
  name: '0083_email_edited',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      const [cols] = await conn.query(
        `SELECT 1 FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'email_messages' AND COLUMN_NAME = 'edited' LIMIT 1`
      );
      if (cols.length) return;
      await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      await conn.query('ALTER TABLE `email_messages` ADD COLUMN `edited` TINYINT(1) NOT NULL DEFAULT 0');
    } finally {
      conn.release();
    }
  },
};
