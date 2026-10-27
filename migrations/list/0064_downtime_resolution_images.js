// back/migrations/list/0064_downtime_resolution_images.js
// Migration 0064: Add resolution image attachment columns to downtimes table
// Allows Storytellers to attach images (via Mike's PHP image service) to downtime resolutions.

async function columnExists(conn, table, column) {
  const [rows] = await conn.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0064_downtime_resolution_images',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      await conn.query('SET SESSION system_versioning_alter_history = KEEP');

      if (!(await columnExists(conn, 'downtimes', 'resolution_image_url'))) {
        await conn.query('ALTER TABLE `downtimes` ADD COLUMN `resolution_image_url` VARCHAR(500) NULL DEFAULT NULL AFTER `gm_resolution`');
      }

      if (!(await columnExists(conn, 'downtimes', 'resolution_image_name'))) {
        await conn.query('ALTER TABLE `downtimes` ADD COLUMN `resolution_image_name` VARCHAR(255) NULL DEFAULT NULL AFTER `resolution_image_url`');
      }

      if (!(await columnExists(conn, 'downtimes', 'resolution_images'))) {
        await conn.query('ALTER TABLE `downtimes` ADD COLUMN `resolution_images` LONGTEXT NULL DEFAULT NULL AFTER `resolution_image_name`');
      }
    } finally {
      conn.release();
    }
  },
};
