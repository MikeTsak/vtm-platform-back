// back/migrations/list/0045_audit_and_attribution_fields.js
// Migration 0045: Audit, attribution, and version control fields across tables
// Adds recorded_by/resolved_by/resolved_at, created_by, assigned_by, actor_id,
// reviewed_by/reviewed_at/review_note, published_by/published_at, granted_by/updated_at,
// ended_by, and creates the character_sheet_versions table.

async function columnExists(pool, table, column) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

async function addColumnIfMissing(pool, table, column, definition) {
  if (!(await columnExists(pool, table, column))) {
    await pool.query(`ALTER TABLE \`${table}\` ADD COLUMN \`${column}\` ${definition}`);
  }
}

async function addForeignKeySafe(pool, table, fkName, fkSql) {
  try {
    await pool.query(`ALTER TABLE \`${table}\` ADD CONSTRAINT \`${fkName}\` ${fkSql}`);
  } catch (e) {
    // Constraint may already exist or fail on partial environment, continue gracefully
  }
}

module.exports = {
  name: '0045_audit_and_attribution_fields',
  async up(pool) {
    // 1. boons: recorded_by, resolved_by, resolved_at
    await addColumnIfMissing(pool, 'boons', 'recorded_by', 'INT(10) UNSIGNED NULL DEFAULT NULL');
    await addForeignKeySafe(pool, 'boons', 'fk_boons_recorded_by', 'FOREIGN KEY (`recorded_by`) REFERENCES `users` (`id`) ON DELETE SET NULL');

    await addColumnIfMissing(pool, 'boons', 'resolved_by', 'INT(10) UNSIGNED NULL DEFAULT NULL');
    await addForeignKeySafe(pool, 'boons', 'fk_boons_resolved_by', 'FOREIGN KEY (`resolved_by`) REFERENCES `users` (`id`) ON DELETE SET NULL');

    await addColumnIfMissing(pool, 'boons', 'resolved_at', 'DATETIME NULL DEFAULT NULL');

    // 2. domain_problems: created_by, resolved_by, resolved_at
    await addColumnIfMissing(pool, 'domain_problems', 'created_by', 'INT(10) UNSIGNED NULL DEFAULT NULL');
    await addForeignKeySafe(pool, 'domain_problems', 'fk_dp_created_by', 'FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL');

    await addColumnIfMissing(pool, 'domain_problems', 'resolved_by', 'INT(10) UNSIGNED NULL DEFAULT NULL');
    await addForeignKeySafe(pool, 'domain_problems', 'fk_dp_resolved_by', 'FOREIGN KEY (`resolved_by`) REFERENCES `users` (`id`) ON DELETE SET NULL');

    await addColumnIfMissing(pool, 'domain_problems', 'resolved_at', 'DATETIME NULL DEFAULT NULL');

    // 3. domain_claims: assigned_by
    await addColumnIfMissing(pool, 'domain_claims', 'assigned_by', 'INT(10) UNSIGNED NULL DEFAULT NULL');
    await addForeignKeySafe(pool, 'domain_claims', 'fk_dc_assigned_by', 'FOREIGN KEY (`assigned_by`) REFERENCES `users` (`id`) ON DELETE SET NULL');

    // 4. xp_log: actor_id
    await addColumnIfMissing(pool, 'xp_log', 'actor_id', 'INT(10) UNSIGNED NULL DEFAULT NULL');
    await addForeignKeySafe(pool, 'xp_log', 'fk_xplog_actor_id', 'FOREIGN KEY (`actor_id`) REFERENCES `users` (`id`) ON DELETE SET NULL');

    // 5. hunt_submissions: reviewed_by, reviewed_at, review_note
    await addColumnIfMissing(pool, 'hunt_submissions', 'reviewed_by', 'INT(10) UNSIGNED NULL DEFAULT NULL');
    await addForeignKeySafe(pool, 'hunt_submissions', 'fk_hs_reviewed_by', 'FOREIGN KEY (`reviewed_by`) REFERENCES `users` (`id`) ON DELETE SET NULL');

    await addColumnIfMissing(pool, 'hunt_submissions', 'reviewed_at', 'DATETIME NULL DEFAULT NULL');
    await addColumnIfMissing(pool, 'hunt_submissions', 'review_note', 'TEXT NULL DEFAULT NULL');

    // 6. news_entries: published_by, published_at
    await addColumnIfMissing(pool, 'news_entries', 'published_by', 'INT(10) UNSIGNED NULL DEFAULT NULL');
    await addForeignKeySafe(pool, 'news_entries', 'fk_ne_published_by', 'FOREIGN KEY (`published_by`) REFERENCES `users` (`id`) ON DELETE SET NULL');

    await addColumnIfMissing(pool, 'news_entries', 'published_at', 'DATETIME NULL DEFAULT NULL');

    // 7. inventory_items: granted_by, updated_at
    await addColumnIfMissing(pool, 'inventory_items', 'granted_by', 'INT(10) UNSIGNED NULL DEFAULT NULL');
    await addForeignKeySafe(pool, 'inventory_items', 'fk_ii_granted_by', 'FOREIGN KEY (`granted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL');

    await addColumnIfMissing(pool, 'inventory_items', 'updated_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');

    // 8. live_sessions: ended_by
    await addColumnIfMissing(pool, 'live_sessions', 'ended_by', 'INT(10) UNSIGNED NULL DEFAULT NULL');
    await addForeignKeySafe(pool, 'live_sessions', 'fk_ls_ended_by', 'FOREIGN KEY (`ended_by`) REFERENCES `users` (`id`) ON DELETE SET NULL');

    // 9. character_sheet_versions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS \`character_sheet_versions\` (
        \`id\` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
        \`character_id\` INT(10) UNSIGNED NOT NULL,
        \`editor_id\` INT(10) UNSIGNED NULL DEFAULT NULL,
        \`sheet\` LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`sheet\`)),
        \`change_summary\` VARCHAR(255) NULL DEFAULT NULL,
        \`created_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (\`id\`),
        KEY \`idx_csv_char_created\` (\`character_id\`, \`created_at\`),
        KEY \`idx_csv_editor\` (\`editor_id\`),
        CONSTRAINT \`fk_csv_character\` FOREIGN KEY (\`character_id\`) REFERENCES \`characters\` (\`id\`) ON DELETE CASCADE,
        CONSTRAINT \`fk_csv_editor\` FOREIGN KEY (\`editor_id\`) REFERENCES \`users\` (\`id\`) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
