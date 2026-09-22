// migrations/list/0023_npc_message_queue_status.js
//
// Lets an admin queue an NPC reply (SchreckNet chat or SurfaceWeb email)
// instead of sending it immediately, so it can be typed during a comms
// downtime window and delivered automatically once comms reopen. `status`
// defaults to 'sent' so every existing row and every non-admin send path
// is unaffected.

async function columnExists(pool, table, column) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0023_npc_message_queue_status',
  async up(pool) {
    if (!(await columnExists(pool, 'npc_messages', 'status'))) {
      await pool.query(
        "ALTER TABLE npc_messages ADD COLUMN `status` ENUM('sent','queued') NOT NULL DEFAULT 'sent' AFTER `edited`"
      );
    }
    if (!(await columnExists(pool, 'email_messages', 'status'))) {
      await pool.query(
        "ALTER TABLE email_messages ADD COLUMN `status` ENUM('sent','queued') NOT NULL DEFAULT 'sent' AFTER `is_read`"
      );
    }
  },
};
