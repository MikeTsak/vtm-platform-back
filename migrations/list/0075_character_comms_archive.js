// back/migrations/list/0075_character_comms_archive.js
// Migration 0075: a retired character's comms move to a hidden archive account
// (services/characterRetirement.js), so the player's next character starts with
// empty chats, mail, NPC threads, notes and premonitions, while other players'
// threads with the dead character keep its name.
//   users.archived_character_id  set only on an archive account: the retired
//                                character whose comms it holds. NULL for every
//                                real account. Archive accounts cannot log in and
//                                are left out of user lists.
//
// users is system-versioned (0051): ALTER needs KEEP, as in 0057.
module.exports = {
  name: '0075_character_comms_archive',
  async up(pool) {
    const [cols] = await pool.query(
      `SELECT 1 FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'archived_character_id' LIMIT 1`
    );
    if (cols.length) return;

    const conn = await pool.getConnection();
    try {
      await conn.query('SET SESSION system_versioning_alter_history = KEEP');
      await conn.query(`ALTER TABLE \`users\`
        ADD COLUMN \`archived_character_id\` INT(10) UNSIGNED NULL DEFAULT NULL,
        ADD UNIQUE KEY \`uq_users_archived_character\` (\`archived_character_id\`),
        ADD CONSTRAINT \`fk_users_archived_character\` FOREIGN KEY (\`archived_character_id\`) REFERENCES \`characters\` (\`id\`) ON DELETE CASCADE`);
    } finally {
      conn.release();
    }
  },
};
