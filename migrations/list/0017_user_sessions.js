module.exports = {
  name: '0017_user_sessions',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT UNSIGNED NOT NULL,
        session_start DATETIME NOT NULL,
        last_active DATETIME NOT NULL,
        duration_seconds INT NOT NULL DEFAULT 0,
        KEY idx_user_id (user_id),
        KEY idx_last_active (last_active)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
