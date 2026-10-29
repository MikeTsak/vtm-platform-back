// back/migrations/list/0068_feeding_outcome_manual.js
// Migration 0068: a Storyteller can record a player as fed without a roll
// (GM-adjudicated Predator Types, table rulings). Stored as outcome 'manual':
// it unlocks downtime actions like any feeding, but is not a hunt and never
// touches a domain.

module.exports = {
  name: '0068_feeding_outcome_manual',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      try {
        await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      } catch (_) {}
      await conn.query(`
        ALTER TABLE feedings
        MODIFY COLUMN outcome ENUM('bestial_failure','failure','success','critical','messy_critical','herd','manual') DEFAULT NULL
      `);
    } finally {
      conn.release();
    }
  },
};
