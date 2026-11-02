-- 0078_inventory_st_notes: Storyteller-only notes on an inventory item, never sent to players.
-- migrations/list/0078_inventory_st_notes.js does this on boot; this is the same change by hand.

SET SESSION system_versioning_alter_history = KEEP;
ALTER TABLE `inventory_items` ADD COLUMN IF NOT EXISTS `st_notes` TEXT NULL DEFAULT NULL;
