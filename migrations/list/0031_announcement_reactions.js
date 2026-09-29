// migrations/list/0031_announcement_reactions.js
//
// Dedicated reactions table for court announcements and news entries.
// Supports emoji reactions, clan crest tokens (:Clan_Name:), and user attribution.
// Foreign key constraints cascade deletes when an announcement or user is removed.
module.exports = {
  name: '0031_announcement_reactions',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS announcement_reactions (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        announcement_id INT UNSIGNED NOT NULL,
        user_id INT UNSIGNED NOT NULL,
        emoji VARCHAR(32) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uniq_announcement_reaction (announcement_id, user_id, emoji),
        KEY idx_announcement (announcement_id),
        CONSTRAINT fk_announcement_reaction_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        CONSTRAINT fk_announcement_reaction_entry FOREIGN KEY (announcement_id) REFERENCES news_entries (id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    // Migrate any reactions that were stored in chat_message_reactions
    try {
      await pool.query(`
        INSERT IGNORE INTO announcement_reactions (announcement_id, user_id, emoji, created_at)
        SELECT message_id, user_id, emoji, created_at
        FROM chat_message_reactions
        WHERE message_table = 'news_entries'
      `);
      await pool.query("DELETE FROM chat_message_reactions WHERE message_table = 'news_entries'");
    } catch (e) {
      // If chat_message_reactions doesn't have any or doesn't exist, proceed safely
    }
  },
};
