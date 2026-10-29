// back/migrations/list/0067_ghoul_feedings.js
// Migration 0067: ghoul upkeep. One `ghoul_feedings` row per ghoul per
// downtime cycle: 'fed' (early by a player, or by the cycle-end upkeep) or
// 'starved' (let go, or no feeder below Hunger 5). A ghoul whose latest row is
// 'starved' has lost its powers until it is fed again. `retainers.let_starve`
// is the owner's standing "do not feed" choice.

async function columnExists(conn, table, column) {
  const [rows] = await conn.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0067_ghoul_feedings',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      try {
        await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      } catch (_) {}

      await conn.query(`
        CREATE TABLE IF NOT EXISTS ghoul_feedings (
          id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          retainer_id INT(11) NOT NULL,
          cycle_index INT NOT NULL,
          status ENUM('fed','starved') NOT NULL,
          method VARCHAR(20) NOT NULL,
          fed_by_character_id INT(10) UNSIGNED DEFAULT NULL,
          rouse_dice VARCHAR(20) DEFAULT NULL,
          hunger_before TINYINT DEFAULT NULL,
          hunger_after TINYINT DEFAULT NULL,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE KEY uniq_ghoul_cycle (retainer_id, cycle_index),
          KEY idx_ghoul_feedings_cycle (cycle_index),
          CONSTRAINT fk_ghoul_feedings_retainer FOREIGN KEY (retainer_id) REFERENCES retainers (id) ON DELETE CASCADE,
          CONSTRAINT fk_ghoul_feedings_feeder FOREIGN KEY (fed_by_character_id) REFERENCES characters (id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
      `);

      if (!(await columnExists(conn, 'retainers', 'let_starve'))) {
        await conn.query('ALTER TABLE `retainers` ADD COLUMN `let_starve` TINYINT(1) NOT NULL DEFAULT 0');
      }
    } finally {
      conn.release();
    }
  },
};
