-- Migration 0044: Track which Storyteller resolved the downtime action
ALTER TABLE `downtimes` ADD COLUMN `resolved_by` INT(10) UNSIGNED NULL DEFAULT NULL AFTER `resolved_at`;
ALTER TABLE `downtimes` ADD CONSTRAINT `fk_dt_resolved_by` FOREIGN KEY (`resolved_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;
