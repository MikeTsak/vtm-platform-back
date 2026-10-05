// back/migrations/list/0046_live_sessions_metadata.js
// Migration 0046: live_sessions.metadata (Storyteller effects, roll requests, etc.).
// The baseline only creates it on fresh installs; older databases lack it, which
// made every live-session roll (POST /api/dice/roll) fail with a 500.

module.exports = {
  name: '0046_live_sessions_metadata',
  async up(pool) {
    const [col] = await pool.query("SHOW COLUMNS FROM `live_sessions` LIKE 'metadata'");
    if (col.length === 0) {
      await pool.query('ALTER TABLE `live_sessions` ADD COLUMN `metadata` LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL CHECK (json_valid(`metadata`))');
    }
  },
};
