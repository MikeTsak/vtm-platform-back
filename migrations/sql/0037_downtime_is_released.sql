-- Migration 0037: Add is_released flag to downtimes table
ALTER TABLE `downtimes` ADD COLUMN `is_released` TINYINT(1) NOT NULL DEFAULT 1;

-- Track migration so automated runner knows it has been executed
INSERT INTO `schema_migrations` (`name`, `applied_at`) 
VALUES ('0037_downtime_is_released', NOW())
ON DUPLICATE KEY UPDATE `applied_at` = `applied_at`;
