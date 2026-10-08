// back/migrations/list/0048_court_actions.js
// Migration 0048: Court Actions.
//  - events.is_elysium: which chronicle events are Elysium gatherings (the
//    Keeper's invitation cycle follows these). Backfilled to the Modern Day events.
//  - elysium_invitations: one Keeper-authored invitation per Elysium event.
//  - elysium_invitation_reads: who has opened it (drives the Home pop-up).
//  - blood_hunts: proposed / ratified / lifted Blood Hunts.
//  - court_wanted: the Sheriff's board of persons of interest.

async function columnExists(pool, table, column) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0048_court_actions',
  async up(pool) {
    if (!(await columnExists(pool, 'events', 'is_elysium'))) {
      await pool.query('ALTER TABLE `events` ADD COLUMN `is_elysium` TINYINT(1) NOT NULL DEFAULT 0');
      await pool.query("UPDATE `events` SET `is_elysium` = 1 WHERE `title` LIKE '%Modern%'");
    }

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`elysium_invitations\` (
  \`event_id\` INT(11) NOT NULL,
  \`name\` VARCHAR(160) NULL DEFAULT NULL,
  \`location\` VARCHAR(255) NULL DEFAULT NULL,
  \`salutation\` VARCHAR(255) NULL DEFAULT NULL,
  \`body\` TEXT NULL DEFAULT NULL,
  \`dress_code\` VARCHAR(160) NULL DEFAULT NULL,
  \`signature\` VARCHAR(160) NULL DEFAULT NULL,
  \`design\` LONGTEXT NULL DEFAULT NULL,
  \`barred\` LONGTEXT NULL DEFAULT NULL,
  \`published_at\` DATETIME NULL DEFAULT NULL,
  \`updated_by\` INT(10) UNSIGNED NULL DEFAULT NULL,
  \`updated_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (\`event_id\`),
  CONSTRAINT \`fk_elysium_inv_event\` FOREIGN KEY (\`event_id\`) REFERENCES \`events\` (\`id\`) ON DELETE CASCADE,
  CONSTRAINT \`fk_elysium_inv_user\` FOREIGN KEY (\`updated_by\`) REFERENCES \`users\` (\`id\`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`elysium_invitation_reads\` (
  \`event_id\` INT(11) NOT NULL,
  \`user_id\` INT(10) UNSIGNED NOT NULL,
  \`read_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (\`event_id\`, \`user_id\`),
  CONSTRAINT \`fk_elysium_read_event\` FOREIGN KEY (\`event_id\`) REFERENCES \`events\` (\`id\`) ON DELETE CASCADE,
  CONSTRAINT \`fk_elysium_read_user\` FOREIGN KEY (\`user_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`blood_hunts\` (
  \`id\` INT(11) NOT NULL AUTO_INCREMENT,
  \`target_type\` ENUM('player','npc') NOT NULL,
  \`target_id\` INT(11) NOT NULL,
  \`target_name\` VARCHAR(255) NOT NULL,
  \`reason\` TEXT NOT NULL,
  \`status\` ENUM('proposed','active','lifted','rejected','expired') NOT NULL DEFAULT 'proposed',
  \`proposed_by\` INT(10) UNSIGNED NULL DEFAULT NULL,
  \`proposed_office\` VARCHAR(40) NULL DEFAULT NULL,
  \`ratified_by\` INT(10) UNSIGNED NULL DEFAULT NULL,
  \`ratified_at\` DATETIME NULL DEFAULT NULL,
  \`closed_by\` INT(10) UNSIGNED NULL DEFAULT NULL,
  \`closed_at\` DATETIME NULL DEFAULT NULL,
  \`expires_at\` DATETIME NULL DEFAULT NULL,
  \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (\`id\`),
  KEY \`idx_blood_hunts_status\` (\`status\`),
  CONSTRAINT \`fk_blood_hunts_proposed\` FOREIGN KEY (\`proposed_by\`) REFERENCES \`users\` (\`id\`) ON DELETE SET NULL,
  CONSTRAINT \`fk_blood_hunts_ratified\` FOREIGN KEY (\`ratified_by\`) REFERENCES \`users\` (\`id\`) ON DELETE SET NULL,
  CONSTRAINT \`fk_blood_hunts_closed\` FOREIGN KEY (\`closed_by\`) REFERENCES \`users\` (\`id\`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`court_wanted\` (
  \`id\` INT(11) NOT NULL AUTO_INCREMENT,
  \`target_name\` VARCHAR(255) NOT NULL,
  \`reason\` TEXT NOT NULL,
  \`posted_by\` INT(10) UNSIGNED NULL DEFAULT NULL,
  \`posted_office\` VARCHAR(40) NULL DEFAULT NULL,
  \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  \`closed_at\` DATETIME NULL DEFAULT NULL,
  \`closed_by\` INT(10) UNSIGNED NULL DEFAULT NULL,
  PRIMARY KEY (\`id\`),
  CONSTRAINT \`fk_court_wanted_posted\` FOREIGN KEY (\`posted_by\`) REFERENCES \`users\` (\`id\`) ON DELETE SET NULL,
  CONSTRAINT \`fk_court_wanted_closed\` FOREIGN KEY (\`closed_by\`) REFERENCES \`users\` (\`id\`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`);
  },
};
