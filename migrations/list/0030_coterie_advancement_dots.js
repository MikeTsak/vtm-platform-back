// migrations/list/0030_coterie_advancement_dots.js
//
// Dots a coterie gains after creation (XP purchases through /purchase and
// personal Backgrounds handed over through /contribute) were counted as
// spending from the creation pool without ever being added to it. Every
// advancement drove the pool's "Remaining" negative, and the builder then
// refused to save the coterie with an overspend error.
//
// `advancement_dots` credits those dots back to the pool (see computePool in
// utils/coterieRules.js). Backfilled from coterie_xp_log, where every
// purchase and contribution is recorded with its from/to rating.
//
// Idempotent: skipped once the column exists.
module.exports = {
  name: '0030_coterie_advancement_dots',
  async up(pool) {
    const [cols] = await pool.query(`
      SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'coteries' AND COLUMN_NAME = 'advancement_dots'
    `);
    if (cols.length) return;

    await pool.query('ALTER TABLE coteries ADD COLUMN `advancement_dots` int(11) NOT NULL DEFAULT 0 AFTER `bonus_points`');
    await pool.query(`
      UPDATE coteries c
      JOIN (
        SELECT coterie_id, SUM(GREATEST(to_dots - from_dots, 0)) AS dots
        FROM coterie_xp_log
        WHERE kind IN ('spend', 'contribute')
        GROUP BY coterie_id
      ) l ON l.coterie_id = c.id
      SET c.advancement_dots = l.dots
    `);
  },
};
