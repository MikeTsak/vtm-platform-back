// migrations/list/0024_chat_group_icon.js
//
// Lets a group chat's creator pick an emoji (a literal unicode character, or
// a ':Clan_Name:' crest token — the same convention chat_message_reactions
// already uses) as the group's picture, shown wherever its avatar renders.

async function columnExists(pool, table, column) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0024_chat_group_icon',
  async up(pool) {
    if (await columnExists(pool, 'chat_groups', 'icon')) return;
    await pool.query(
      "ALTER TABLE chat_groups ADD COLUMN `icon` VARCHAR(64) DEFAULT NULL AFTER `name`"
    );
  },
};
