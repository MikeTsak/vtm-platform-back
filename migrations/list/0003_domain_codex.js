// Adds a community "codex" (lore notes) any logged-in player can contribute
// to a domain — separate from the Court-only incident log in domain_problems.
module.exports = {
  name: '0003_domain_codex',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS domain_codex_entries (
        id INT NOT NULL AUTO_INCREMENT,
        division INT NOT NULL,
        user_id INT UNSIGNED NOT NULL,
        character_id INT UNSIGNED DEFAULT NULL,
        text VARCHAR(1000) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_division (division),
        CONSTRAINT fk_codex_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        CONSTRAINT fk_codex_char FOREIGN KEY (character_id) REFERENCES characters (id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
