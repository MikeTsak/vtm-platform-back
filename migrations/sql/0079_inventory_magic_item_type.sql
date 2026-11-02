-- 0079_inventory_magic_item_type: adds 'Magic Item' to the inventory item types.
-- migrations/list/0079_inventory_magic_item_type.js does this on boot; this is the same change by hand.

SET SESSION system_versioning_alter_history = KEEP;
ALTER TABLE `inventory_items` MODIFY COLUMN `item_type` ENUM('Relic','Artifact','Blood Magic','Magic Item','Weapon','Armor','Mundane') DEFAULT 'Mundane';
