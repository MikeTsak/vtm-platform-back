// Avatars (users/npcs/retainers/email_identities) are all resized once to a
// fixed 500x500 on upload and served at that one size everywhere — a 32px
// admin-table avatar downloads the same file as a 128px profile picture.
// This adds a second, small CDN URL per entity so small render contexts can
// request a much smaller file via srcset instead (see Avatar.jsx and the
// `?size=thumb` handling on each GET .../avatar route). Left nullable and
// populated lazily on next avatar upload — no backfill needed, GET routes
// fall back to the existing full-size avatar_url when this is null.
module.exports = {
  name: '0011_avatar_thumb_urls',
  async up(pool) {
    await pool.query('ALTER TABLE users ADD COLUMN avatar_url_thumb VARCHAR(2048) DEFAULT NULL');
    await pool.query('ALTER TABLE npcs ADD COLUMN avatar_url_thumb VARCHAR(2048) DEFAULT NULL');
    await pool.query('ALTER TABLE retainers ADD COLUMN avatar_url_thumb VARCHAR(2048) DEFAULT NULL');
    await pool.query('ALTER TABLE email_identities ADD COLUMN avatar_url_thumb VARCHAR(2048) DEFAULT NULL');
  },
};
