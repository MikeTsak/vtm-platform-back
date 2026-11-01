// back/migrations/list/0073_index_cleanup.js
// Migration 0073: index housekeeping.
//
// - Drop single-column indexes that a composite index already starts with
//   (every write maintained both; reads only ever need the composite):
//     downtimes.idx_dt_char        -> idx_char_created (character_id, created_at)
//     dice_rolls.character_id      -> idx_dice_char_created (character_id, created_at)
//     chat_messages.idx_sender_id  -> conversation_idx (sender_id, ...)
//     chat_messages.idx_recipient_id -> idx_recipient_read_at (recipient_id, read_at)
//     chat_group_messages.fk_cgms_group -> idx_group_created (group_id, created_at)
//   Each still has an index on its leading column, so its foreign key keeps one.
// - chat_messages.conversation_idx gains created_at: DM history pages on
//   (created_at, id) (utils/chatConversation.js) and InnoDB appends the primary
//   key, so a page is read from the index alone (covering) and only that one
//   conversation's rows are sorted, not every message either user ever sent.
// - characters.user_id becomes UNIQUE: one current character per account is a
//   house rule (retired characters have user_id NULL, which UNIQUE allows any
//   number of). POST /api/characters already enforces it in a transaction; this
//   makes the database refuse a duplicate too. Skipped, with a warning, if
//   duplicates already exist, since those need a human to pick which one stays.
// Idempotent: every step checks the current state first.

async function indexCols(conn, table, index) {
  const [rows] = await conn.query(
    `SELECT COLUMN_NAME AS c, NON_UNIQUE AS nu FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ? ORDER BY SEQ_IN_INDEX`,
    [table, index]
  );
  return rows.length ? { cols: rows.map((r) => r.c).join(','), unique: rows[0].nu === 0 } : null;
}

module.exports = {
  name: '0073_index_cleanup',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      // downtimes and characters are system-versioned (0051): ALTER needs this on the same connection.
      try { await conn.query('SET SESSION system_versioning_alter_history = KEEP'); } catch (_) {}

      const redundant = [
        ['downtimes', 'idx_dt_char'],
        ['dice_rolls', 'character_id'],
        ['chat_messages', 'idx_sender_id'],
        ['chat_messages', 'idx_recipient_id'],
        ['chat_group_messages', 'fk_cgms_group'],
      ];
      for (const [table, index] of redundant) {
        if (await indexCols(conn, table, index)) await conn.query(`ALTER TABLE \`${table}\` DROP INDEX \`${index}\``);
      }

      const conv = await indexCols(conn, 'chat_messages', 'conversation_idx');
      if (!conv || conv.cols !== 'sender_id,recipient_id,created_at') {
        await conn.query(
          `ALTER TABLE chat_messages ${conv ? 'DROP INDEX conversation_idx,' : ''} ADD INDEX conversation_idx (sender_id, recipient_id, created_at)`
        );
      }

      const uniq = await indexCols(conn, 'characters', 'uniq_char_user');
      if (!uniq) {
        const [dupes] = await conn.query(
          'SELECT user_id, COUNT(*) AS n FROM characters WHERE user_id IS NOT NULL GROUP BY user_id HAVING n > 1'
        );
        if (dupes.length) {
          console.warn('[0073] characters.user_id NOT made unique: accounts with more than one current character:',
            dupes.map((d) => `user ${d.user_id} (${d.n})`).join(', '));
        } else {
          await conn.query('ALTER TABLE characters ADD UNIQUE INDEX uniq_char_user (user_id)');
          // The old plain index is now a prefix duplicate; the FK moves to the unique one.
          if (await indexCols(conn, 'characters', 'user_id')) await conn.query('ALTER TABLE characters DROP INDEX `user_id`');
        }
      }
    } finally {
      conn.release();
    }
  },
};
