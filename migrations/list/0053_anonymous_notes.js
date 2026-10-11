// back/migrations/list/0053_anonymous_notes.js
// Migration 0053: one-off anonymous notes a Storyteller drops into a player's
// Surface Web. No sender is ever shown and there is no reply; one row per
// recipient so read state is per player. images = JSON array of CDN urls.
module.exports = {
  name: '0053_anonymous_notes',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS \`anonymous_notes\` (
        \`id\` INT(11) NOT NULL AUTO_INCREMENT,
        \`user_id\` INT(10) UNSIGNED NOT NULL,
        \`sender_id\` INT(10) UNSIGNED NULL DEFAULT NULL,
        \`body\` MEDIUMTEXT NULL,
        \`images\` TEXT NULL,
        \`read_at\` DATETIME NULL DEFAULT NULL,
        \`created_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (\`id\`),
        KEY \`idx_anonymous_notes_user\` (\`user_id\`, \`created_at\`),
        CONSTRAINT \`fk_anonymous_notes_user\` FOREIGN KEY (\`user_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE,
        CONSTRAINT \`fk_anonymous_notes_sender\` FOREIGN KEY (\`sender_id\`) REFERENCES \`users\` (\`id\`) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
  },
};
