// migrations/list/0036_chat_system_message_type.js
//
// Extends chat_messages and npc_messages with a `type` column ('text' | 'system'),
// matching chat_group_messages. System messages represent auto-generated conversation
// events (such as changing the theme or conversation emoji) that display centered
// in the message timeline.

const TABLES = ['chat_messages', 'npc_messages'];

module.exports = {
  name: '0036_chat_system_message_type',
  async up(pool) {
    for (const table of TABLES) {
      const [cols] = await pool.query(
        `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = 'type'`,
        [table]
      );
      if (cols.length) continue;
      await pool.query(
        `ALTER TABLE ${table} ADD COLUMN \`type\` ENUM('text','system') NOT NULL DEFAULT 'text' AFTER \`body\``
      );
    }
  },
};
