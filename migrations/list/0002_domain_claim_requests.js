// Adds the domain claim-request workflow: players can request an unclaimed
// division, Court/admin approve or reject it, and a single "previous owner"
// snapshot is kept on domain_claims when a domain is vacated.
module.exports = {
  name: '0002_domain_claim_requests',
  async up(pool) {
    // domain_claims: allow a vacated domain to have no current owner, and
    // remember who held it last.
    try {
      await pool.query(`
        ALTER TABLE domain_claims
          MODIFY COLUMN owner_name VARCHAR(100) DEFAULT NULL,
          ADD COLUMN previous_owner_name VARCHAR(100) DEFAULT NULL,
          ADD COLUMN previous_owner_character_id INT UNSIGNED DEFAULT NULL,
          ADD COLUMN previous_claimed_at TIMESTAMP NULL DEFAULT NULL
      `);
    } catch (err) {
      if (err.code !== 'ER_DUP_FIELDNAME') throw err;
    }

    try {
      await pool.query(`
        ALTER TABLE domain_claims
          ADD CONSTRAINT fk_claim_prev_char FOREIGN KEY (previous_owner_character_id)
          REFERENCES characters (id) ON DELETE SET NULL ON UPDATE CASCADE
      `);
    } catch (err) {
      if (err.code !== 'ER_FK_DUP_NAME' && err.code !== 'ER_DUP_KEYNAME') throw err;
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS domain_claim_requests (
        id INT NOT NULL AUTO_INCREMENT,
        division INT NOT NULL,
        user_id INT UNSIGNED NOT NULL,
        character_id INT UNSIGNED NOT NULL,
        message VARCHAR(500) DEFAULT NULL,
        color CHAR(7) DEFAULT NULL,
        status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP NULL DEFAULT NULL,
        resolved_by INT UNSIGNED DEFAULT NULL,
        PRIMARY KEY (id),
        KEY idx_division_status (division, status),
        KEY idx_user (user_id),
        CONSTRAINT fk_req_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        CONSTRAINT fk_req_char FOREIGN KEY (character_id) REFERENCES characters (id) ON DELETE CASCADE,
        CONSTRAINT fk_req_resolver FOREIGN KEY (resolved_by) REFERENCES users (id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
