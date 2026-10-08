// back/migrations/list/0049_elysium_invitation_history.js
// Migration 0049: Elysium invitation history and audit.
//  - elysium_invitation_versions: a full snapshot of the invitation (words,
//    design, guest list) at every save / publish / withdraw / re-send /
//    Calendar rename, with who did it and in which office.
//  - elysium_invitation_reads gains open_count, last_read_at, seen_as
//    ('invited' / 'barred': which card the reader was shown the first time)
//    and first/last_version_id (which snapshot was on their screen).
// Existing invitations are snapshotted once as 'import' so history isn't empty.

async function columnExists(pool, table, column) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0049_elysium_invitation_history',
  async up(pool) {
    await pool.query(`
CREATE TABLE IF NOT EXISTS \`elysium_invitation_versions\` (
  \`id\` INT(11) NOT NULL AUTO_INCREMENT,
  \`event_id\` INT(11) NOT NULL,
  \`action\` VARCHAR(24) NOT NULL,
  \`name\` VARCHAR(160) NULL DEFAULT NULL,
  \`location\` VARCHAR(255) NULL DEFAULT NULL,
  \`salutation\` VARCHAR(255) NULL DEFAULT NULL,
  \`body\` TEXT NULL DEFAULT NULL,
  \`dress_code\` VARCHAR(160) NULL DEFAULT NULL,
  \`signature\` VARCHAR(160) NULL DEFAULT NULL,
  \`design\` LONGTEXT NULL DEFAULT NULL,
  \`barred\` LONGTEXT NULL DEFAULT NULL,
  \`published\` TINYINT(1) NOT NULL DEFAULT 0,
  \`actor_id\` INT(10) UNSIGNED NULL DEFAULT NULL,
  \`actor_office\` VARCHAR(40) NULL DEFAULT NULL,
  \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (\`id\`),
  KEY \`idx_elysium_versions_event\` (\`event_id\`, \`created_at\`),
  CONSTRAINT \`fk_elysium_ver_event\` FOREIGN KEY (\`event_id\`) REFERENCES \`events\` (\`id\`) ON DELETE CASCADE,
  CONSTRAINT \`fk_elysium_ver_actor\` FOREIGN KEY (\`actor_id\`) REFERENCES \`users\` (\`id\`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`);

    if (!(await columnExists(pool, 'elysium_invitation_reads', 'open_count'))) {
      await pool.query('ALTER TABLE `elysium_invitation_reads` ADD COLUMN `open_count` INT(11) NOT NULL DEFAULT 1');
    }
    if (!(await columnExists(pool, 'elysium_invitation_reads', 'last_read_at'))) {
      await pool.query('ALTER TABLE `elysium_invitation_reads` ADD COLUMN `last_read_at` DATETIME NULL DEFAULT NULL');
      await pool.query('UPDATE `elysium_invitation_reads` SET `last_read_at` = `read_at`');
    }
    if (!(await columnExists(pool, 'elysium_invitation_reads', 'seen_as'))) {
      await pool.query('ALTER TABLE `elysium_invitation_reads` ADD COLUMN `seen_as` VARCHAR(10) NULL DEFAULT NULL');
    }
    for (const col of ['first_version_id', 'last_version_id']) {
      if (!(await columnExists(pool, 'elysium_invitation_reads', col))) {
        await pool.query(`ALTER TABLE \`elysium_invitation_reads\` ADD COLUMN \`${col}\` INT(11) NULL DEFAULT NULL`);
      }
    }

    await pool.query(`
INSERT INTO elysium_invitation_versions
  (event_id, action, name, location, salutation, body, dress_code, signature, design, barred, published, actor_id, actor_office, created_at)
SELECT i.event_id, 'import', i.name, i.location, i.salutation, i.body, i.dress_code, i.signature, i.design, i.barred,
       i.published_at IS NOT NULL, (SELECT u.id FROM users u WHERE u.id = i.updated_by), NULL, i.updated_at
  FROM elysium_invitations i
 WHERE NOT EXISTS (SELECT 1 FROM elysium_invitation_versions v WHERE v.event_id = i.event_id)`);
  },
};
