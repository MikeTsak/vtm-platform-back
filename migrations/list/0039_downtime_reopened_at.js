// When the ST sends an action back to "submitted", the player may edit it even after the
// deadline. reopened_at marks that; any other status change clears it (routes/downtimes.js).
module.exports = {
  name: '0039_downtime_reopened_at',
  async up(pool) {
    const [col] = await pool.query("SHOW COLUMNS FROM `downtimes` LIKE 'reopened_at'");
    if (col.length === 0) {
      await pool.query('ALTER TABLE `downtimes` ADD COLUMN `reopened_at` DATETIME NULL DEFAULT NULL');
    }
  },
};
