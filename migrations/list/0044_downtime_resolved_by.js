// back/migrations/list/0044_downtime_resolved_by.js
// Migration 0044: Add resolved_by column to downtimes table
// Tracks which Storyteller/admin resolved the downtime action.

module.exports = {
  name: '0044_downtime_resolved_by',
  async up(pool) {
    const [col] = await pool.query("SHOW COLUMNS FROM `downtimes` LIKE 'resolved_by'");
    if (col.length === 0) {
      await pool.query('ALTER TABLE `downtimes` ADD COLUMN `resolved_by` INT(10) UNSIGNED NULL DEFAULT NULL AFTER `resolved_at`');
      try {
        await pool.query('ALTER TABLE `downtimes` ADD CONSTRAINT `fk_dt_resolved_by` FOREIGN KEY (`resolved_by`) REFERENCES `users` (`id`) ON DELETE SET NULL');
      } catch (e) {
        // Index / FK add might vary if already partially defined
      }
    }
  },
};
