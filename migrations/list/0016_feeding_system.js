// The Feeding system: a required, automated hunting roll gating downtime
// submission each 3-week cycle. `feedings` is one row per character per
// cycle (pending until confirmed, then locked); `domain_incidents` is the
// persisted, dismissible notice shown to a domain owner when someone else's
// hunt there goes wrong (Failure / Bestial Failure / Messy Critical).
//
// Also seeds the three app_settings rows the feature reads via
// getSetting/setSetting: feeding_enabled, feeding_cycle_anchor (the fixed
// epoch cycles are computed from), and feeding_last_decay_cycle_index (the
// cron job's catch-up marker).
module.exports = {
  name: '0016_feeding_system',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS feedings (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        character_id INT UNSIGNED NOT NULL,
        division INT NOT NULL,
        predator_type VARCHAR(60) NOT NULL,
        pool_label VARCHAR(80) NOT NULL,
        dice_pool INT NOT NULL,
        difficulty INT NOT NULL,
        bonus_dice INT NOT NULL DEFAULT 0,
        chasse_merits_applied JSON DEFAULT NULL,
        hunger_before TINYINT NOT NULL,
        normal_dice JSON DEFAULT NULL,
        hunger_dice JSON DEFAULT NULL,
        outcome ENUM('bestial_failure','failure','success','critical','messy_critical') DEFAULT NULL,
        hunger_delta TINYINT DEFAULT NULL,
        safety_delta TINYINT DEFAULT NULL,
        wp_rerolled TINYINT(1) NOT NULL DEFAULT 0,
        status ENUM('pending','resolved') NOT NULL DEFAULT 'pending',
        cycle_index INT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        resolved_at DATETIME DEFAULT NULL,
        KEY idx_feeding_char (character_id),
        KEY idx_feeding_cycle (cycle_index),
        KEY idx_feeding_division (division),
        CONSTRAINT fk_feeding_char FOREIGN KEY (character_id) REFERENCES characters (id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS domain_incidents (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        feeding_id INT UNSIGNED NOT NULL,
        division INT NOT NULL,
        owner_user_id INT UNSIGNED DEFAULT NULL,
        owner_character_id INT UNSIGNED DEFAULT NULL,
        intruder_character_id INT UNSIGNED NOT NULL,
        intruder_character_name VARCHAR(100) NOT NULL,
        outcome ENUM('bestial_failure','failure','messy_critical') NOT NULL,
        flavor_text TEXT NOT NULL,
        dismissed_at DATETIME DEFAULT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY idx_incident_owner (owner_user_id),
        KEY idx_incident_feeding (feeding_id),
        CONSTRAINT fk_incident_feeding FOREIGN KEY (feeding_id) REFERENCES feedings (id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
      INSERT INTO app_settings (setting_key, setting_value) VALUES
        ('feeding_enabled', 'true'),
        ('feeding_cycle_anchor', ?),
        ('feeding_last_decay_cycle_index', '-1')
      ON DUPLICATE KEY UPDATE setting_key = setting_key
    `, [new Date().toISOString()]);
  },
};
