module.exports = {
  name: '0038_downtime_scenes',
  async up(pool) {
    const [sceneIdCol] = await pool.query("SHOW COLUMNS FROM `downtimes` LIKE 'scene_id'");
    if (sceneIdCol.length === 0) {
      await pool.query('ALTER TABLE `downtimes` ADD COLUMN `scene_id` VARCHAR(60) NULL DEFAULT NULL');
      await pool.query('ALTER TABLE `downtimes` ADD INDEX `idx_dt_scene` (`scene_id`)');
    }

    const [sceneTitleCol] = await pool.query("SHOW COLUMNS FROM `downtimes` LIKE 'scene_title'");
    if (sceneTitleCol.length === 0) {
      await pool.query('ALTER TABLE `downtimes` ADD COLUMN `scene_title` VARCHAR(150) NULL DEFAULT NULL');
    }
  },
};
