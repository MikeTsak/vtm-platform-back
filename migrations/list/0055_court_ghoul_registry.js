// back/migrations/list/0055_court_ghoul_registry.js
// Migration 0055: Court Actions — Ghouls Registry.
// Official court census notes on Kindred ghouls, managed exclusively by
// the Prince, Seneschal, and Harpy (plus Assistant Harpy and Storyteller/Admin).

module.exports = {
  name: '0055_court_ghoul_registry',
  async up(pool) {
    await pool.query(`
CREATE TABLE IF NOT EXISTS \`court_ghoul_registry\` (
  \`id\` INT(11) NOT NULL AUTO_INCREMENT,
  \`target_type\` ENUM('player', 'npc') NOT NULL,
  \`target_id\` INT(11) NOT NULL,
  \`ghoul_count\` INT(11) NOT NULL DEFAULT 0,
  \`notes\` TEXT NULL DEFAULT NULL,
  \`updated_by\` INT(10) UNSIGNED NULL DEFAULT NULL,
  \`updated_office\` VARCHAR(40) NULL DEFAULT NULL,
  \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  \`updated_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`uq_court_ghoul_target\` (\`target_type\`, \`target_id\`),
  CONSTRAINT \`fk_court_ghoul_user\` FOREIGN KEY (\`updated_by\`) REFERENCES \`users\` (\`id\`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`);
  },
};
