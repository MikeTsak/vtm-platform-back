// migrations/list/0034_chat_conversation_settings.js
//
// Shared per-conversation settings for SchreckNet (theme, conversation emoji),
// visible to everyone in the chat. conv_key identifies the conversation:
// 'u:<lowUserId>:<highUserId>' for a DM, 'g:<groupId>' for a group,
// 'n:<npcId>:<userId>' for an NPC thread (see utils/chatConversation.js).
module.exports = {
  name: '0034_chat_conversation_settings',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_conversation_settings (
        conv_key VARCHAR(64) NOT NULL,
        theme VARCHAR(32) DEFAULT NULL,
        emoji VARCHAR(32) DEFAULT NULL,
        updated_by INT UNSIGNED DEFAULT NULL,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (conv_key)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
