// migrations/list/0032_rumor_reactions.js
//
// Dedicated reactions table for rumors.
// Supports emoji reactions, clan crest tokens (:Clan_Name:), and user attribution.
// Foreign key constraints cascade deletes when a rumor or user is removed.
module.exports = {
  name: '0032_rumor_reactions',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS rumor_reactions (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        rumor_id INT UNSIGNED NOT NULL,
        user_id INT UNSIGNED NOT NULL,
        emoji VARCHAR(32) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uniq_rumor_reaction (rumor_id, user_id, emoji),
        KEY idx_rumor (rumor_id),
        CONSTRAINT fk_rumor_reaction_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        CONSTRAINT fk_rumor_reaction_entry FOREIGN KEY (rumor_id) REFERENCES rumors (id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
