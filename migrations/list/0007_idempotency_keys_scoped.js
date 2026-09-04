// The idempotency_keys table used idempotency_key as its sole PRIMARY KEY —
// a single global namespace shared by every user and every endpoint. Two
// different requests that ever produced the same key string (plausible with
// deterministic, content-based keys — see utils/idempotency.js) would
// collide, and worse, the lookup path (before this migration) only filtered
// on idempotency_key, so a crafted key could serve back a cached response
// meant for a completely different user/endpoint.
//
// This replaces that with a surrogate `id` primary key and scopes real
// uniqueness to (idempotency_key, user_id, request_path), and adds an index
// on created_at for the nightly purge query (see utils/idempotency.js /
// purgeOldIdempotencyKeys).
module.exports = {
  name: '0007_idempotency_keys_scoped',
  async up(pool) {
    await pool.query(`
      ALTER TABLE idempotency_keys
        DROP PRIMARY KEY,
        ADD COLUMN id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST,
        ADD UNIQUE KEY uniq_idem_key_user_path (idempotency_key, user_id, request_path),
        ADD INDEX idx_idem_created_at (created_at)
    `);
  },
};
