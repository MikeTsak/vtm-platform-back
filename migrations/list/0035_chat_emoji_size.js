// migrations/list/0035_chat_emoji_size.js
//
// SchreckNet's hold-to-grow conversation emoji (the Messenger "big like"):
// holding the send button inflates the emoji and the chosen size (1-3) is
// stored with the message so both sides render it at that size. NULL for
// every ordinary message.
//
// Idempotent: each table is skipped once it has the column.
const TABLES = ['chat_messages', 'chat_group_messages', 'npc_messages'];

module.exports = {
  name: '0035_chat_emoji_size',
  async up(pool) {
    for (const table of TABLES) {
      const [cols] = await pool.query(`
        SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = 'emoji_size'
      `, [table]);
      if (cols.length) continue;
      await pool.query(`ALTER TABLE ${table} ADD COLUMN \`emoji_size\` TINYINT UNSIGNED DEFAULT NULL`);
    }
  },
};
