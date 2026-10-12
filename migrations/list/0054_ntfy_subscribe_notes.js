// back/migrations/list/0054_ntfy_subscribe_notes.js
// Migration 0054: per-admin opt-in for ntfy "player read your anonymous note"
// receipts (same shape as ntfy_subscribe_downtimes).
module.exports = {
  name: '0054_ntfy_subscribe_notes',
  async up(pool) {
    const [u] = await pool.query("SHOW COLUMNS FROM `users` LIKE 'ntfy_subscribe_notes'");
    if (u.length === 0) {
      await pool.query('ALTER TABLE `users` ADD COLUMN `ntfy_subscribe_notes` BOOLEAN NOT NULL DEFAULT 0');
    }
  },
};
