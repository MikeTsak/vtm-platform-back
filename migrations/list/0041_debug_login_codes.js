// Admin "debug login": an admin generates a single-use, short-lived code for a
// player and uses it (with the player's email) to open a session as that
// player, to see exactly what they see. The player's password is never read
// or changed. Only a SHA-256 of the code is stored; the plaintext is shown to
// the generating admin once. Used rows double as the audit trail (who, when,
// from where). See routes/debugLogin.js.
module.exports = {
  name: '0041_debug_login_codes',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS debug_login_codes (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT UNSIGNED NOT NULL,
        created_by INT UNSIGNED NOT NULL,
        code_hash CHAR(64) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        used_at TIMESTAMP NULL DEFAULT NULL,
        used_ip VARCHAR(64) DEFAULT NULL,
        UNIQUE KEY uq_code_hash (code_hash),
        KEY idx_user (user_id),
        CONSTRAINT fk_dlc_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        CONSTRAINT fk_dlc_admin FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
