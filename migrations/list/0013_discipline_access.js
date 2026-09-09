// Out-of-clan discipline access: a Storyteller can unlock a discipline a
// character wouldn't normally be able to learn (up to a level cap), either
// directly or by approving a player-submitted request. Mirrors the
// domain_claim_requests workflow from 0002 — a small request queue plus a
// table of the actual grants it (or a direct admin action) produces.
module.exports = {
  name: '0013_discipline_access',
  async up(pool) {
    // One row per character+discipline the character has been granted access
    // to beyond their clan. No row = no access. Re-granting (or approving a
    // second request for the same discipline) upserts in place.
    await pool.query(`
      CREATE TABLE IF NOT EXISTS discipline_access (
        id INT NOT NULL AUTO_INCREMENT,
        character_id INT UNSIGNED NOT NULL,
        discipline VARCHAR(60) NOT NULL,
        max_level TINYINT UNSIGNED NOT NULL,
        note VARCHAR(500) DEFAULT NULL,
        granted_by INT UNSIGNED DEFAULT NULL,
        granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uq_discacc_char_discipline (character_id, discipline),
        CONSTRAINT fk_discacc_char FOREIGN KEY (character_id) REFERENCES characters (id) ON DELETE CASCADE,
        CONSTRAINT fk_discacc_granter FOREIGN KEY (granted_by) REFERENCES users (id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    // The request queue a player uses to ask for access; approving one writes
    // (or raises) a row in discipline_access above.
    await pool.query(`
      CREATE TABLE IF NOT EXISTS discipline_requests (
        id INT NOT NULL AUTO_INCREMENT,
        character_id INT UNSIGNED NOT NULL,
        user_id INT UNSIGNED NOT NULL,
        discipline VARCHAR(60) NOT NULL,
        requested_level TINYINT UNSIGNED NOT NULL,
        message VARCHAR(500) DEFAULT NULL,
        status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
        granted_level TINYINT UNSIGNED DEFAULT NULL,
        admin_note VARCHAR(500) DEFAULT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP NULL DEFAULT NULL,
        resolved_by INT UNSIGNED DEFAULT NULL,
        PRIMARY KEY (id),
        KEY idx_discreq_char_status (character_id, status),
        KEY idx_discreq_user (user_id),
        CONSTRAINT fk_discreq_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        CONSTRAINT fk_discreq_char FOREIGN KEY (character_id) REFERENCES characters (id) ON DELETE CASCADE,
        CONSTRAINT fk_discreq_resolver FOREIGN KEY (resolved_by) REFERENCES users (id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
