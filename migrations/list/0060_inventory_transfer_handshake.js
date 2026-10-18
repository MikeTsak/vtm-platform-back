// back/migrations/list/0060_inventory_transfer_handshake.js
// Migration 0060: Pass item becomes a handshake. The receiver's scan parks the
// transfer as 'pending' with who they are (to_user_id; to_character_id NULL =
// the Storyteller taking it back), and nothing moves until the giver confirms
// "Pass X to <name>?".
module.exports = {
  name: '0060_inventory_transfer_handshake',
  async up(pool) {
    const [cols] = await pool.query(
      `SELECT 1 FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'inventory_transfers' AND COLUMN_NAME = 'to_user_id' LIMIT 1`
    );
    if (cols.length) return;
    await pool.query(`ALTER TABLE \`inventory_transfers\`
      MODIFY \`status\` ENUM('open','pending','claimed','cancelled') NOT NULL DEFAULT 'open',
      ADD COLUMN \`to_user_id\` INT(10) UNSIGNED NULL DEFAULT NULL AFTER \`to_character_id\``);
  },
};
