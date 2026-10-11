// back/migrations/list/0052_news_entries_npc_author.js
// Migration 0052: an admin can issue a court decree (announcement) in the name
// of an NPC. npc_id set = the decree shows that NPC's name, titles and portrait
// instead of the posting user's character; author_id still records who posted.
//
// news_entries is system-versioned (0051), and MariaDB refuses ALTER on a
// versioned table unless the session allows it; KEEP leaves history rows as is.
module.exports = {
  name: '0052_news_entries_npc_author',
  async up(pool) {
    const [cols] = await pool.query(
      `SELECT 1 FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'news_entries' AND COLUMN_NAME = 'npc_id' LIMIT 1`
    );
    if (cols.length) return;

    const conn = await pool.getConnection();
    try {
      await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      await conn.query(`ALTER TABLE \`news_entries\`
        ADD COLUMN \`npc_id\` INT(11) NULL DEFAULT NULL,
        ADD CONSTRAINT \`fk_news_entries_npc\` FOREIGN KEY (\`npc_id\`) REFERENCES \`npcs\` (\`id\`) ON DELETE SET NULL`);
    } finally {
      conn.release();
    }
  },
};
