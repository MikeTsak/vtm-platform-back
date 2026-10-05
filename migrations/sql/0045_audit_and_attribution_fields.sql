-- Migration 0045: Audit, attribution, and version control fields across tables

-- 1. Boons audit
ALTER TABLE `boons` ADD COLUMN `recorded_by` INT(10) UNSIGNED NULL DEFAULT NULL;
ALTER TABLE `boons` ADD CONSTRAINT `fk_boons_recorded_by` FOREIGN KEY (`recorded_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;
ALTER TABLE `boons` ADD COLUMN `resolved_by` INT(10) UNSIGNED NULL DEFAULT NULL;
ALTER TABLE `boons` ADD CONSTRAINT `fk_boons_resolved_by` FOREIGN KEY (`resolved_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;
ALTER TABLE `boons` ADD COLUMN `resolved_at` DATETIME NULL DEFAULT NULL;

-- 2. Domain problems attribution
ALTER TABLE `domain_problems` ADD COLUMN `created_by` INT(10) UNSIGNED NULL DEFAULT NULL;
ALTER TABLE `domain_problems` ADD CONSTRAINT `fk_dp_created_by` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;
ALTER TABLE `domain_problems` ADD COLUMN `resolved_by` INT(10) UNSIGNED NULL DEFAULT NULL;
ALTER TABLE `domain_problems` ADD CONSTRAINT `fk_dp_resolved_by` FOREIGN KEY (`resolved_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;
ALTER TABLE `domain_problems` ADD COLUMN `resolved_at` DATETIME NULL DEFAULT NULL;

-- 3. Domain claims assignment
ALTER TABLE `domain_claims` ADD COLUMN `assigned_by` INT(10) UNSIGNED NULL DEFAULT NULL;
ALTER TABLE `domain_claims` ADD CONSTRAINT `fk_dc_assigned_by` FOREIGN KEY (`assigned_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;

-- 4. XP log actor
ALTER TABLE `xp_log` ADD COLUMN `actor_id` INT(10) UNSIGNED NULL DEFAULT NULL;
ALTER TABLE `xp_log` ADD CONSTRAINT `fk_xplog_actor_id` FOREIGN KEY (`actor_id`) REFERENCES `users` (`id`) ON DELETE SET NULL;

-- 5. Hunt submissions review
ALTER TABLE `hunt_submissions` ADD COLUMN `reviewed_by` INT(10) UNSIGNED NULL DEFAULT NULL;
ALTER TABLE `hunt_submissions` ADD CONSTRAINT `fk_hs_reviewed_by` FOREIGN KEY (`reviewed_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;
ALTER TABLE `hunt_submissions` ADD COLUMN `reviewed_at` DATETIME NULL DEFAULT NULL;
ALTER TABLE `hunt_submissions` ADD COLUMN `review_note` TEXT NULL DEFAULT NULL;

-- 6. News entries publication
ALTER TABLE `news_entries` ADD COLUMN `published_by` INT(10) UNSIGNED NULL DEFAULT NULL;
ALTER TABLE `news_entries` ADD CONSTRAINT `fk_ne_published_by` FOREIGN KEY (`published_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;
ALTER TABLE `news_entries` ADD COLUMN `published_at` DATETIME NULL DEFAULT NULL;

-- 7. Inventory items attribution & timestamps
ALTER TABLE `inventory_items` ADD COLUMN `granted_by` INT(10) UNSIGNED NULL DEFAULT NULL;
ALTER TABLE `inventory_items` ADD CONSTRAINT `fk_ii_granted_by` FOREIGN KEY (`granted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;
ALTER TABLE `inventory_items` ADD COLUMN `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;

-- 8. Live sessions conclusion
ALTER TABLE `live_sessions` ADD COLUMN `ended_by` INT(10) UNSIGNED NULL DEFAULT NULL;
ALTER TABLE `live_sessions` ADD CONSTRAINT `fk_ls_ended_by` FOREIGN KEY (`ended_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;

-- 9. Character sheet versioning table
CREATE TABLE IF NOT EXISTS `character_sheet_versions` (
  `id` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `character_id` INT(10) UNSIGNED NOT NULL,
  `editor_id` INT(10) UNSIGNED NULL DEFAULT NULL,
  `sheet` LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`sheet`)),
  `change_summary` VARCHAR(255) NULL DEFAULT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_csv_char_created` (`character_id`, `created_at`),
  KEY `idx_csv_editor` (`editor_id`),
  CONSTRAINT `fk_csv_character` FOREIGN KEY (`character_id`) REFERENCES `characters` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_csv_editor` FOREIGN KEY (`editor_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
