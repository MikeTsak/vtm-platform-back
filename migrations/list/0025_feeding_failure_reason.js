// migrations/list/0025_feeding_failure_reason.js
//
// Stores the in-universe "how the hunt went wrong" line (data/predatorFlavor.js)
// on every feeding that drew attention (Failure / Bestial Failure / Messy
// Critical), not only on the domain_incidents row an owned domain gets, so
// the admin Recent Feedings log can show why a hunt failed.
//
// Backfill: rows that already produced an incident reuse its flavor_text so
// the two read the same; other past failures get a freshly picked line.

const { pickFlavor } = require('../../data/predatorFlavor');

async function columnExists(pool, table, column) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0025_feeding_failure_reason',
  async up(pool) {
    if (!(await columnExists(pool, 'feedings', 'failure_reason'))) {
      await pool.query('ALTER TABLE feedings ADD COLUMN `failure_reason` TEXT DEFAULT NULL AFTER `outcome`');
    }

    await pool.query(`
      UPDATE feedings f
      JOIN domain_incidents di ON di.feeding_id = f.id
      SET f.failure_reason = di.flavor_text
      WHERE f.failure_reason IS NULL AND di.flavor_text IS NOT NULL
    `);

    const [rows] = await pool.query(`
      SELECT id, predator_type FROM feedings
      WHERE failure_reason IS NULL AND status = 'resolved'
        AND outcome IN ('bestial_failure','failure','messy_critical')
    `);
    for (const row of rows) {
      await pool.query('UPDATE feedings SET failure_reason=? WHERE id=?', [pickFlavor(row.predator_type), row.id]);
    }
  },
};
