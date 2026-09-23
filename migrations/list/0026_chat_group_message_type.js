// migrations/list/0026_chat_group_message_type.js
//
// Distinguishes ordinary group chat messages from auto-generated system
// lines (member added/removed, group renamed, icon changed). A system row
// still has a real sender_id (the user who performed the action, for
// attribution) but body is the final, already-formatted text rather than
// something typed by a player.

async function columnExists(pool, table, column) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0026_chat_group_message_type',
  async up(pool) {
    if (await columnExists(pool, 'chat_group_messages', 'type')) return;
    await pool.query(
      "ALTER TABLE chat_group_messages ADD COLUMN `type` ENUM('text','system') NOT NULL DEFAULT 'text' AFTER `body`"
    );
  },
};
