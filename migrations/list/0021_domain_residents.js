// Domain residents: a character or NPC temporarily operating from an
// UNCLAIMED division — not a domain owner, not a guest in someone else's
// territory, just physically present in uncontrolled ground.
//
// No FK to domain_claims.division because unclaimed divisions have no row
// there (a claim row only exists once a division has been touched by the
// Court). The constraint "this division must not be owned" is enforced in
// application logic at insert time.
//
// When the division later gets claimed by someone ELSE, the transition helper
// in domainResidents.js converts remaining resident rows into domain_guests
// entries for the new owner before deleting them.
module.exports = {
  name: '0021_domain_residents',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS domain_residents (
        id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
        division     INT(11) NOT NULL,
        character_id INT(10) UNSIGNED DEFAULT NULL,
        npc_id       INT(11) DEFAULT NULL,
        note         VARCHAR(255) DEFAULT NULL,
        added_by     INT UNSIGNED DEFAULT NULL,
        created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_resident_division  (division),
        KEY idx_resident_character (character_id),
        KEY idx_resident_npc       (npc_id),
        CONSTRAINT fk_resident_character FOREIGN KEY (character_id) REFERENCES characters (id) ON DELETE CASCADE,
        CONSTRAINT fk_resident_npc       FOREIGN KEY (npc_id)       REFERENCES npcs       (id) ON DELETE CASCADE,
        CONSTRAINT fk_resident_added_by  FOREIGN KEY (added_by)     REFERENCES users      (id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
