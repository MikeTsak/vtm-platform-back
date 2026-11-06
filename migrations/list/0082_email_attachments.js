// back/migrations/list/0082_email_attachments.js
// Migration 0082: Surface Web emails can carry an image, like SchreckNet. It is
// stored as a chat_media row (uploaded through /api/chat/upload) and the email
// keeps its id, as chat messages do; services/chatMedia.js lets the thread's
// player see it. The SET SESSION covers a system-versioned email_messages
// (0051) and is harmless on a plain one.
module.exports = {
  name: '0082_email_attachments',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      const [cols] = await conn.query(
        `SELECT 1 FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'email_messages' AND COLUMN_NAME = 'attachment_id' LIMIT 1`
      );
      if (cols.length) return;
      await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      await conn.query('ALTER TABLE `email_messages` ADD COLUMN `attachment_id` INT(10) UNSIGNED NULL DEFAULT NULL');
    } finally {
      conn.release();
    }
  },
};
