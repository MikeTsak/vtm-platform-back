// `domain_problems` is queried with `ORDER BY created_at DESC` in two places
// (routes/adminMisc.js /api/admin/domains-advanced, routes/domainClaims.js), but
// on databases where the table was created by the pre-runner legacy migration
// path the `created_at` column was never actually added — every such query
// 500s with "Unknown column 'created_at' in 'ORDER BY'".
//
// The column is in 0001_baseline's CREATE, but that's `CREATE TABLE IF NOT
// EXISTS`, so it no-ops (and never patches) a table that already exists. This
// backfills the column where it's missing. Existing rows get NULL, which is
// fine for the ORDER BY.
async function columnExists(pool, table, column) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column],
  );
  return rows.length > 0;
}

async function tableExists(pool, table) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.TABLES
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? LIMIT 1`,
    [table],
  );
  return rows.length > 0;
}

module.exports = {
  name: '0014_domain_problems_created_at',
  async up(pool) {
    if (!(await tableExists(pool, 'domain_problems'))) return;
    if (await columnExists(pool, 'domain_problems', 'created_at')) return;
    await pool.query(
      'ALTER TABLE domain_problems ADD COLUMN `created_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP',
    );
  },
};
