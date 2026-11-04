// back/migrations/list/0080_chat_forwarded_from.js
// Migration 0080: forwarding a chat message (services/chatForward.js). A
// forwarded copy keeps its original author's in-universe name in forwarded_from
// ("Forwarded from Livia"), set by the server, never by the client; NULL for an
// ordinary message. All three chat kinds, like reply_to_id (0027). These tables
// are system-versioned (0051), so the ALTER needs system_versioning_alter_history.
const TABLES = ['chat_messages', 'chat_group_messages', 'npc_messages'];

module.exports = {
  name: '0080_chat_forwarded_from',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      for (const table of TABLES) {
        const [cols] = await conn.query(
          `SELECT 1 FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = 'forwarded_from' LIMIT 1`, [table]
        );
        if (!cols.length) await conn.query(`ALTER TABLE \`${table}\` ADD COLUMN \`forwarded_from\` VARCHAR(255) NULL DEFAULT NULL`);
      }
    } finally {
      conn.release();
    }
  },
};
