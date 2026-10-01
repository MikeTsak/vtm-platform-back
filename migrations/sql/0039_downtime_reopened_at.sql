-- Migration 0039: mark actions the ST sent back to the player (editable past the deadline)
ALTER TABLE `downtimes` ADD COLUMN `reopened_at` DATETIME NULL DEFAULT NULL;
