// back/migrations/list/0078_inventory_st_notes.js
// Migration 0078: inventory_items.st_notes, Storyteller-only notes on an item.
// routes/inventory.js strips the column from every player-facing response
// (forPlayer), so it is never shown to the holder, researched or not.
//
// inventory_items is system-versioned (0051): ALTER needs KEEP, as in 0076.

module.exports = {
  name: '0078_inventory_st_notes',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      const [cols] = await conn.query(
        `SELECT 1 FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'inventory_items' AND COLUMN_NAME = 'st_notes' LIMIT 1`
      );
      if (!cols.length) {
        await conn.query('SET SESSION system_versioning_alter_history = KEEP');
        await conn.query('ALTER TABLE `inventory_items` ADD COLUMN `st_notes` TEXT NULL DEFAULT NULL');
      }
    } finally {
      conn.release();
    }
  },
};
