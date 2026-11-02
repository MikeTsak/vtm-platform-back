// back/migrations/list/0079_inventory_magic_item_type.js
// Migration 0079: 'Magic Item' joins the inventory_items.item_type enum
// (mirrored by ITEM_TYPES in routes/inventory.js and front itemMeta.js).
//
// inventory_items is system-versioned (0051): ALTER needs KEEP, as in 0076.

module.exports = {
  name: '0079_inventory_magic_item_type',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      const [[col]] = await conn.query(
        `SELECT COLUMN_TYPE AS t FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'inventory_items' AND COLUMN_NAME = 'item_type'`
      );
      if (col && !String(col.t).includes('Magic Item')) {
        await conn.query('SET SESSION system_versioning_alter_history = KEEP');
        await conn.query(
          "ALTER TABLE `inventory_items` MODIFY COLUMN `item_type` ENUM('Relic','Artifact','Blood Magic','Magic Item','Weapon','Armor','Mundane') DEFAULT 'Mundane'"
        );
      }
    } finally {
      conn.release();
    }
  },
};
