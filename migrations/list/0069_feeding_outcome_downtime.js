// back/migrations/list/0069_feeding_outcome_downtime.js
// Migration 0069: a player can spend a downtime action on a guaranteed safe
// feeding (Hunger -2, no roll, no domain). Stored as outcome 'downtime'; the
// matching resolved downtime is filed in the same transaction.

module.exports = {
  name: '0069_feeding_outcome_downtime',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      try {
        await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      } catch (_) {}
      await conn.query(`
        ALTER TABLE feedings
        MODIFY COLUMN outcome ENUM('bestial_failure','failure','success','critical','messy_critical','herd','manual','downtime') DEFAULT NULL
      `);
    } finally {
      conn.release();
    }
  },
};
