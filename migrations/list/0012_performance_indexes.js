// Composite indexes for the "filter on N columns, then sort by date" queries,
// plus removal of exactly-duplicated indexes.
//
// Measured on staging before writing this (EXPLAIN + timing, index created and
// dropped again):
//
//   npc thread        (npc_id, user_id)     ORDER BY created_at  filesort -> none
//   group messages    (group_id)            ORDER BY created_at  filesort -> none
//   downtimes recent  (character_id)        ORDER BY created_at  filesort -> none
//
// Deliberately NOT included: (sender_id, recipient_id, created_at) on
// chat_messages. The DM history query is bidirectional —
//   WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)
// — and two disjoint index ranges cannot be read in one created_at order, so
// MySQL still sorts. Verified: creating that index leaves "Using filesort" in
// place, and rewriting the query as UNION ALL doesn't help either. Removing
// that sort needs a canonical conversation_id column, which is a schema *and*
// code change, not an index.
//
// The duplicate drops matter more than the additions on current data volumes:
// every duplicate is maintained on each INSERT/UPDATE, and chat_messages is the
// most write-heavy table in the schema.
//
// Every step is existence-checked, so re-running this is a no-op. Additions run
// before removals: each column being de-duplicated also carries a FOREIGN KEY,
// and InnoDB refuses to drop the last index that can serve one.

async function indexExists(pool, table, name) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ? LIMIT 1`,
    [table, name],
  );
  return rows.length > 0;
}

async function tableExists(pool, table) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.TABLES
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? LIMIT 1`,
    [table],
  );
  return rows.length > 0;
}

async function addIndex(pool, table, name, columns) {
  if (!(await tableExists(pool, table))) return;
  if (await indexExists(pool, table, name)) return;
  await pool.query(`CREATE INDEX \`${name}\` ON \`${table}\` (${columns})`);
}

// Drops `name` only if `keep` still exists on the same table — so an index
// backing a foreign key is never the one left missing.
async function dropDuplicate(pool, table, name, keep) {
  if (!(await tableExists(pool, table))) return;
  if (!(await indexExists(pool, table, name))) return;
  if (!(await indexExists(pool, table, keep))) return;
  await pool.query(`DROP INDEX \`${name}\` ON \`${table}\``);
}

module.exports = {
  name: '0012_performance_indexes',
  async up(pool) {
    // --- 1. composite indexes that remove a filesort ---------------------
    await addIndex(pool, 'npc_messages', 'idx_npc_user_created', 'npc_id, user_id, created_at');
    await addIndex(pool, 'chat_group_messages', 'idx_group_created', 'group_id, created_at');
    await addIndex(pool, 'downtimes', 'idx_char_created', 'character_id, created_at');

    // --- 2. exact duplicate indexes ---------------------------------------
    // Each pair below indexes an identical column list under two names.
    // The kept name is the second argument.
    await dropDuplicate(pool, 'chat_messages', 'sender_id_idx', 'idx_sender_id');
    await dropDuplicate(pool, 'chat_messages', 'recipient_id_idx', 'idx_recipient_id');
    await dropDuplicate(pool, 'downtimes', 'idx_character', 'idx_dt_char');
    await dropDuplicate(pool, 'characters', 'idx_user_id', 'user_id');
    await dropDuplicate(pool, 'push_subscriptions', 'idx_user_id', 'user_id');
  },
};
