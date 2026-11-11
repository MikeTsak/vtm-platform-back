// back/migrations/list/0085_coterie_dormancy.js
//
// Migration 0085: a coterie below the 3-member floor goes dormant for a grace
// period, then dissolves (services/coterieLifecycle.js).
//   status         'active' | 'dormant' | 'dissolved'
//   dormant_since  when it fell below the floor (NULL while active)
//   dissolve_at    the deadline while dormant (editable on the admin Calendar);
//                  once dissolved, when that happened
// Existing coteries start 'active'; the coterie job puts any already under
// the floor to sleep on its first run.
// coteries is system-versioned (0051), so the ALTER needs KEEP.
module.exports = {
  name: '0085_coterie_dormancy',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      const [cols] = await conn.query(
        `SELECT COLUMN_NAME FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'coteries'
            AND COLUMN_NAME IN ('status', 'dormant_since', 'dissolve_at')`
      );
      const have = new Set(cols.map((c) => c.COLUMN_NAME));
      const add = [];
      if (!have.has('status')) add.push("ADD COLUMN `status` ENUM('active','dormant','dissolved') NOT NULL DEFAULT 'active'");
      if (!have.has('dormant_since')) add.push('ADD COLUMN `dormant_since` DATETIME NULL DEFAULT NULL');
      if (!have.has('dissolve_at')) add.push('ADD COLUMN `dissolve_at` DATETIME NULL DEFAULT NULL');
      if (!add.length) return;
      await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      await conn.query(`ALTER TABLE \`coteries\` ${add.join(', ')}`);
    } finally {
      conn.release();
    }
  },
};
