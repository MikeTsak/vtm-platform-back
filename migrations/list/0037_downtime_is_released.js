module.exports = {
  name: '0037_downtime_is_released',
  async up(pool) {
    const [dt] = await pool.query("SHOW COLUMNS FROM `downtimes` LIKE 'is_released'");
    if (dt.length === 0) {
      await pool.query('ALTER TABLE `downtimes` ADD COLUMN `is_released` BOOLEAN NOT NULL DEFAULT 1');

      try {
        const [[modeRow]] = await pool.query("SELECT setting_value FROM app_settings WHERE setting_key = 'downtime_mass_release_mode'");
        const [[dateRow]] = await pool.query("SELECT setting_value FROM app_settings WHERE setting_key = 'downtime_mass_release_date'");
        const [[openingRow]] = await pool.query("SELECT setting_value FROM app_settings WHERE setting_key = 'downtime_opening'");

        if (modeRow?.setting_value === 'true' && dateRow?.setting_value) {
          const relTime = new Date(dateRow.setting_value).getTime();
          if (!isNaN(relTime) && Date.now() < relTime && openingRow?.setting_value) {
            await pool.query(
              'UPDATE downtimes SET is_released = 0 WHERE created_at >= ? AND is_read = 0 AND title NOT LIKE "[PROJECT]%"',
              [new Date(openingRow.setting_value)]
            );
          }
        }
      } catch (_) {}
    }
  },
};
