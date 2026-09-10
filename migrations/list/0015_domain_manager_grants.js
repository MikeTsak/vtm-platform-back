// The allow-list of "Domain Stewards" — non-admin users an admin has
// authorised to run the Athens claims map: approve/deny claim requests,
// directly assign or vacate divisions, moderate the codex, and read the
// Storyteller-facing incident log.
//
// Empty by design. The `courtuser` role used to grant every one of those
// powers implicitly; it no longer does. Admins can always manage domains and
// are NOT stored here.
module.exports = {
  name: '0015_domain_manager_grants',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS domain_manager_grants (
        user_id INT UNSIGNED NOT NULL,
        granted_by INT UNSIGNED DEFAULT NULL,
        granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id),
        CONSTRAINT fk_domain_mgr_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        CONSTRAINT fk_domain_mgr_by FOREIGN KEY (granted_by) REFERENCES users (id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
