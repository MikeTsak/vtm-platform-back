// Coterie retainers: a retainer row is now owned by EITHER a character
// (personal, bought with that character's XP) OR a coterie (a sheet for the
// coterie's shared Retainers Background). The coterie's Retainers dots in
// coteries.backgrounds_json are the budget; the sum of its retainers' tiers
// may not exceed them (enforced in routes/coteries.js). Coteries that bought
// Retainers before this existed simply show unassigned dots — no backfill.
//
// domitor_character_id: for a ghouled coterie retainer, which member's blood
// it drinks (the discipline list comes from that character's clan).
module.exports = {
  name: '0042_coterie_retainers',
  async up(pool) {
    const [cols] = await pool.query("SHOW COLUMNS FROM retainers LIKE 'coterie_id'");
    if (cols.length) return;

    await pool.query('ALTER TABLE retainers MODIFY character_id INT(10) UNSIGNED NULL');
    await pool.query(`
      ALTER TABLE retainers
        ADD COLUMN coterie_id INT(11) NULL DEFAULT NULL AFTER character_id,
        ADD COLUMN domitor_character_id INT(10) UNSIGNED NULL DEFAULT NULL AFTER coterie_id,
        ADD KEY idx_retainers_coterie (coterie_id),
        ADD CONSTRAINT fk_retainers_coterie FOREIGN KEY (coterie_id) REFERENCES coteries (id) ON DELETE CASCADE,
        ADD CONSTRAINT fk_retainers_domitor FOREIGN KEY (domitor_character_id) REFERENCES characters (id) ON DELETE SET NULL,
        ADD CONSTRAINT chk_retainers_one_owner CHECK ((character_id IS NULL) <> (coterie_id IS NULL))
    `);
  },
};
