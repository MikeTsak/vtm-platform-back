-- Migration 0038: Add scene grouping fields to downtimes table
ALTER TABLE `downtimes` ADD COLUMN `scene_id` VARCHAR(60) NULL DEFAULT NULL;
ALTER TABLE `downtimes` ADD COLUMN `scene_title` VARCHAR(150) NULL DEFAULT NULL;
ALTER TABLE `downtimes` ADD INDEX `idx_dt_scene` (`scene_id`);
