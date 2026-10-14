// back/migrations/list/0058_character_avatar_snapshot.js
// Migration 0058: a retired character keeps its portrait. Avatars live on the
// account (users.avatar_url), so retiring moves them here and the player's next
// character starts with none; restoring moves them back
// (services/characterRetirement.js). NULL on every current character. The image
// host names each upload uniquely, so a stored URL is never overwritten.
module.exports = {
  name: '0058_character_avatar_snapshot',
  async up(pool) {
    const [cols] = await pool.query(
      `SELECT 1 FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'characters' AND COLUMN_NAME = 'avatar_url' LIMIT 1`
    );
    if (cols.length) return;

    const conn = await pool.getConnection();
    try {
      await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      await conn.query(`ALTER TABLE \`characters\`
        ADD COLUMN \`avatar_url\` VARCHAR(2048) NULL DEFAULT NULL,
        ADD COLUMN \`avatar_url_thumb\` VARCHAR(2048) NULL DEFAULT NULL`);
    } finally {
      conn.release();
    }
  },
};
