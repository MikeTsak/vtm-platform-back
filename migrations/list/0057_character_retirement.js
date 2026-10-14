// back/migrations/list/0057_character_retirement.js
// Migration 0057: one account, many characters over time (a character dies,
// the player makes a new one). Only one is current.
//   user_id          the account PLAYING this character now; NULL once retired.
//                    Every existing `characters.user_id = ?` query keeps meaning
//                    "this account's current character", and UNIQUE(user_id)
//                    still allows only one (NULL never collides).
//   retired_user_id  the account that owns a retired character (NULL while current).
//   retired_at       when it was retired.
// The CHECK keeps exactly one of the two owner columns set.
//
// characters is system-versioned (0051): ALTER needs KEEP, as in 0052.
module.exports = {
  name: '0057_character_retirement',
  async up(pool) {
    const [cols] = await pool.query(
      `SELECT 1 FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'characters' AND COLUMN_NAME = 'retired_user_id' LIMIT 1`
    );
    if (cols.length) return;

    const conn = await pool.getConnection();
    try {
      await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      await conn.query(`ALTER TABLE \`characters\`
        MODIFY \`user_id\` INT(10) UNSIGNED NULL DEFAULT NULL,
        ADD COLUMN \`retired_user_id\` INT(10) UNSIGNED NULL DEFAULT NULL,
        ADD COLUMN \`retired_at\` TIMESTAMP NULL DEFAULT NULL,
        ADD KEY \`idx_char_retired_user\` (\`retired_user_id\`),
        ADD CONSTRAINT \`fk_char_retired_user\` FOREIGN KEY (\`retired_user_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE,
        ADD CONSTRAINT \`chk_char_one_owner\` CHECK ((\`user_id\` IS NULL) <> (\`retired_user_id\` IS NULL))`);
    } finally {
      conn.release();
    }
  },
};
