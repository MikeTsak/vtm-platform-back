// back/migrations/list/0084_chat_pinned_messages.js
//
// Migration 0084: Pinned messages support across 1-on-1 direct messages (chat_messages),
// group messages (chat_group_messages), and NPC messages (npc_messages).
// These tables are system-versioned (0051), so the ALTER needs system_versioning_alter_history.

const TABLES = ['chat_messages', 'chat_group_messages', 'npc_messages'];

module.exports = {
  name: '0084_chat_pinned_messages',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      for (const table of TABLES) {
        const [cols] = await conn.query(
          `SELECT COLUMN_NAME FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME IN ('is_pinned', 'pinned_at', 'pinned_by')`,
          [table]
        );
        const colNames = cols.map(c => c.COLUMN_NAME);

        if (!colNames.includes('is_pinned')) {
          await conn.query(`ALTER TABLE \`${table}\` ADD COLUMN \`is_pinned\` TINYINT(1) NOT NULL DEFAULT 0`);
        }
        if (!colNames.includes('pinned_at')) {
          await conn.query(`ALTER TABLE \`${table}\` ADD COLUMN \`pinned_at\` TIMESTAMP NULL DEFAULT NULL`);
        }
        if (!colNames.includes('pinned_by')) {
          await conn.query(`ALTER TABLE \`${table}\` ADD COLUMN \`pinned_by\` INT NULL DEFAULT NULL`);
        }
      }
    } finally {
      conn.release();
    }
  },
};

