// Domain guests: who is being given hospitality in a division, beyond its
// owner. A row links a division to the character or NPC being hosted there —
// a Kindred staying in someone else's territory with permission, not a claim.
module.exports = {
  name: '0020_domain_guests',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS domain_guests (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        division INT(11) NOT NULL,
        character_id INT(10) UNSIGNED DEFAULT NULL,
        npc_id INT(11) DEFAULT NULL,
        note VARCHAR(255) DEFAULT NULL,
        added_by INT UNSIGNED DEFAULT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_guest_division (division),
        KEY idx_guest_character (character_id),
        KEY idx_guest_npc (npc_id),
        CONSTRAINT fk_guest_division FOREIGN KEY (division) REFERENCES domain_claims (division) ON DELETE CASCADE,
        CONSTRAINT fk_guest_character FOREIGN KEY (character_id) REFERENCES characters (id) ON DELETE CASCADE,
        CONSTRAINT fk_guest_npc FOREIGN KEY (npc_id) REFERENCES npcs (id) ON DELETE CASCADE,
        CONSTRAINT fk_guest_added_by FOREIGN KEY (added_by) REFERENCES users (id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
