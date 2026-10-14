// back/migrations/list/0056_comms_drafts.js
// Migration 0056: drafts a player writes while comms are closed, so they can
// keep their thoughts next to the conversation instead of in another notes
// app. Never sent automatically: the player sends, copies or deletes each
// one by hand once comms reopen. Private to their author.
//   conv_key: the chat key from utils/chatConversation.js ('u:low:high',
//   'g:id', 'n:npc:user'), 'e:<threadId>' for an email reply, or 'e:new' for
//   a new email (to_address + subject are only used there).
module.exports = {
  name: '0056_comms_drafts',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS \`comms_drafts\` (
        \`id\` INT(11) NOT NULL AUTO_INCREMENT,
        \`user_id\` INT(10) UNSIGNED NOT NULL,
        \`conv_key\` VARCHAR(64) NOT NULL,
        \`body\` MEDIUMTEXT NOT NULL,
        \`subject\` VARCHAR(255) NULL DEFAULT NULL,
        \`to_address\` VARCHAR(255) NULL DEFAULT NULL,
        \`created_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        \`updated_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (\`id\`),
        KEY \`idx_comms_drafts_owner\` (\`user_id\`, \`conv_key\`, \`created_at\`),
        CONSTRAINT \`fk_comms_drafts_user\` FOREIGN KEY (\`user_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
