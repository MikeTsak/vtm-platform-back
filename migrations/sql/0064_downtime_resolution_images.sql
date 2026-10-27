-- Migration 0064: Add resolution image attachment columns to downtimes table
ALTER TABLE `downtimes` ADD COLUMN `resolution_image_url` VARCHAR(500) NULL DEFAULT NULL AFTER `gm_resolution`;
ALTER TABLE `downtimes` ADD COLUMN `resolution_image_name` VARCHAR(255) NULL DEFAULT NULL AFTER `resolution_image_url`;
ALTER TABLE `downtimes` ADD COLUMN `resolution_images` LONGTEXT NULL DEFAULT NULL AFTER `resolution_image_name`;
