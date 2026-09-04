// Message reactions (double-tap-to-like + emoji react), additive on top of
// the existing chat tables. `message_table` is a whitelisted discriminator
// (never client-controlled SQL — see the REACTION_TABLES check in
// server.fastify.js) rather than three separate nullable FK columns, since
// message ids are per-table auto-increment and not unique across tables.
module.exports = {
  name: '0009_chat_message_reactions',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_message_reactions (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        message_table VARCHAR(32) NOT NULL,
        message_id INT UNSIGNED NOT NULL,
        user_id INT UNSIGNED NOT NULL,
        emoji VARCHAR(32) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uniq_reaction (message_table, message_id, user_id, emoji),
        KEY idx_message (message_table, message_id),
        CONSTRAINT fk_reaction_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
