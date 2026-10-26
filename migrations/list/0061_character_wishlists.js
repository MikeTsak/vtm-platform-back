// back/migrations/list/0061_character_wishlists.js
// Migration 0061: Store player wishlists for powers and rituals
// Allows players to save desired powers and rituals for quick reference
// and provides Storytellers an admin view of all player desires.

module.exports = {
  name: '0061_character_wishlists',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS \`character_wishlists\` (
        \`id\` INT UNSIGNED NOT NULL AUTO_INCREMENT,
        \`character_id\` INT UNSIGNED NOT NULL,
        \`item_type\` ENUM('power', 'ritual') NOT NULL,
        \`item_id\` VARCHAR(100) NOT NULL,
        \`name\` VARCHAR(150) NOT NULL,
        \`discipline\` VARCHAR(60) NOT NULL,
        \`level\` TINYINT UNSIGNED NOT NULL DEFAULT 1,
        \`note\` VARCHAR(500) DEFAULT NULL,
        \`created_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (\`id\`),
        UNIQUE KEY \`uq_char_wishlist_item\` (\`character_id\`, \`item_type\`, \`item_id\`),
        KEY \`idx_char_wishlist_char\` (\`character_id\`),
        CONSTRAINT \`fk_char_wishlist_char\` FOREIGN KEY (\`character_id\`) REFERENCES \`characters\` (\`id\`) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
