// back/migrations/list/0077_nosferatu_old_necropolis_grants.js
// Migration 0077: Backfill necropolis_old grants for active Nosferatu characters
// so their access is persisted in domain_overlay_grants and can be revoked.
module.exports = {
  name: '0077_nosferatu_old_necropolis_grants',
  async up(pool) {
    await pool.query(`
      INSERT IGNORE INTO domain_overlay_grants (user_id, overlay_key, granted_by)
      SELECT DISTINCT user_id, 'necropolis_old', NULL
      FROM characters
      WHERE clan = 'Nosferatu'
        AND user_id IS NOT NULL
        AND COALESCE(is_deceased, 0) = 0
        AND COALESCE(is_left, 0) = 0
    `);
  },
};

