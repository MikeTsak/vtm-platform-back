// migrations/list/0027_chat_message_replies.js
//
// Reply-to-a-specific-message ("quote reply") for all three chat kinds:
// player DMs, group chats and player<->NPC threads. reply_to_id points at a
// row in the SAME table. No foreign key on purpose: when the quoted message
// is deleted the reply keeps its reply_to_id, the history join comes back
// empty, and the UI shows "original message deleted" instead of silently
// losing the fact that it was a reply.

async function columnExists(pool, table, column) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

const TABLES = ['chat_messages', 'chat_group_messages', 'npc_messages'];

module.exports = {
  name: '0027_chat_message_replies',
  async up(pool) {
    for (const table of TABLES) {
      if (await columnExists(pool, table, 'reply_to_id')) continue;
      await pool.query(`ALTER TABLE \`${table}\` ADD COLUMN \`reply_to_id\` INT UNSIGNED NULL DEFAULT NULL`);
    }
  },
};
