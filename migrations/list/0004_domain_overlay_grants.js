// Per-user access to the restricted Domains-map overlays (catacombs, old
// necropolis, new necropolis). Admins see everything and Nosferatu characters
// get the necropoleis automatically — this table is only for explicit grants
// an admin hands to a specific player.
module.exports = {
  name: '0004_domain_overlay_grants',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS domain_overlay_grants (
        user_id INT UNSIGNED NOT NULL,
        overlay_key VARCHAR(32) NOT NULL,
        granted_by INT UNSIGNED DEFAULT NULL,
        granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, overlay_key),
        KEY idx_overlay_key (overlay_key),
        CONSTRAINT fk_overlay_grant_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        CONSTRAINT fk_overlay_grant_by FOREIGN KEY (granted_by) REFERENCES users (id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
