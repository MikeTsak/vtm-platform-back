// back/migrations/list/0086_chat_social.js
//
// Migration 0086: per-person SchreckNet controls (routes/chat.js).
//   chat_blocks          who blocked whom (DMs only; the blocked person is told)
//   chat_contact_prefs   one row per person per chat in their list: pinned to
//                        the top, muted until. contact_key is what the OWNER
//                        sees: 'u:<otherUserId>', 'g:<groupId>', 'n:<npcId>'
//                        (an admin's 'n:' covers every player's thread with it).
//                        muted_until 9999-12-31 = muted until turned back on.
//   chat_saved_messages  messages a person saved for themselves (private,
//                        unlike pins, which everyone in the chat sees).
// All three follow a retired character to its archive account
// (services/characterRetirement.js), so the next character starts clean.
module.exports = {
  name: '0086_chat_social',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS \`chat_blocks\` (
        \`blocker_id\` INT(10) UNSIGNED NOT NULL,
        \`blocked_id\` INT(10) UNSIGNED NOT NULL,
        \`created_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (\`blocker_id\`, \`blocked_id\`),
        KEY \`idx_blocked\` (\`blocked_id\`),
        CONSTRAINT \`fk_chat_blocks_blocker\` FOREIGN KEY (\`blocker_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE,
        CONSTRAINT \`fk_chat_blocks_blocked\` FOREIGN KEY (\`blocked_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS \`chat_contact_prefs\` (
        \`user_id\` INT(10) UNSIGNED NOT NULL,
        \`contact_key\` VARCHAR(40) NOT NULL,
        \`pinned_at\` DATETIME NULL DEFAULT NULL,
        \`muted_until\` DATETIME NULL DEFAULT NULL,
        \`updated_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (\`user_id\`, \`contact_key\`),
        CONSTRAINT \`fk_chat_prefs_user\` FOREIGN KEY (\`user_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS \`chat_saved_messages\` (
        \`user_id\` INT(10) UNSIGNED NOT NULL,
        \`message_table\` VARCHAR(32) NOT NULL,
        \`message_id\` INT(10) UNSIGNED NOT NULL,
        \`created_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (\`user_id\`, \`message_table\`, \`message_id\`),
        CONSTRAINT \`fk_chat_saved_user\` FOREIGN KEY (\`user_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`);
  },
};
