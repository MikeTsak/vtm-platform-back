// back/migrations/list/0059_inventory_world_items_transfers.js
// Migration 0059: Storyteller-run inventory (routes/inventory.js).
// - inventory_items.character_id becomes nullable: NULL = an item out in the
//   world that nobody holds yet, claimed by scanning its QR (claim_code).
// - claim_copies: the world QR hands every scanner their own copy instead of
//   the one item; copies point back through source_item_id (one per character).
// - player_notes: the holder's own notes; mechanic_notes stays the ST's
//   "what it does" and is hidden from players until `researched`.
// - inventory_transfers: one row per "Pass item" QR, player to player.
module.exports = {
  name: '0059_inventory_world_items_transfers',
  async up(pool) {
    const [cols] = await pool.query(
      `SELECT 1 FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'inventory_items' AND COLUMN_NAME = 'claim_code' LIMIT 1`
    );
    if (!cols.length) {
      const conn = await pool.getConnection();
      try {
        await conn.query('SET SESSION system_versioning_alter_history = KEEP');
        await conn.query(`ALTER TABLE \`inventory_items\`
          MODIFY \`character_id\` INT(11) NULL DEFAULT NULL,
          ADD COLUMN \`player_notes\` TEXT NULL DEFAULT NULL,
          ADD COLUMN \`claim_code\` VARCHAR(64) NULL DEFAULT NULL,
          ADD COLUMN \`claim_copies\` TINYINT(1) NOT NULL DEFAULT 0,
          ADD COLUMN \`source_item_id\` INT(11) NULL DEFAULT NULL,
          ADD UNIQUE KEY \`uq_inv_claim_code\` (\`claim_code\`),
          ADD KEY \`idx_inv_source\` (\`source_item_id\`)`);
      } finally {
        conn.release();
      }
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS \`inventory_transfers\` (
        \`id\` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
        \`token\` VARCHAR(64) NOT NULL,
        \`item_id\` INT(11) NOT NULL,
        \`from_character_id\` INT(11) NOT NULL,
        \`to_character_id\` INT(11) NULL DEFAULT NULL,
        \`quantity\` INT(11) NOT NULL DEFAULT 1,
        \`include_notes\` TINYINT(1) NOT NULL DEFAULT 0,
        \`status\` ENUM('open','claimed','cancelled') NOT NULL DEFAULT 'open',
        \`created_by\` INT(10) UNSIGNED NULL DEFAULT NULL,
        \`created_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        \`expires_at\` DATETIME NOT NULL,
        \`claimed_at\` DATETIME NULL DEFAULT NULL,
        PRIMARY KEY (\`id\`),
        UNIQUE KEY \`uq_inv_transfer_token\` (\`token\`),
        KEY \`idx_inv_transfer_item\` (\`item_id\`, \`status\`),
        CONSTRAINT \`fk_inv_transfer_item\` FOREIGN KEY (\`item_id\`) REFERENCES \`inventory_items\` (\`id\`) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
