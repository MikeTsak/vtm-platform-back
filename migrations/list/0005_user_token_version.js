// Enables JWT revocation without a server-side session store. Every JWT we
// issue embeds the user's token_version at mint time (`tv` claim); on every
// authenticated request we compare it against the current DB value (see
// utils/tokenVersion.js). Bumping this column instantly invalidates every
// token issued before the bump — used by password reset ("log out everyone
// but me after a compromise") and the new /api/auth/logout-all endpoint.
module.exports = {
  name: '0005_user_token_version',
  async up(pool) {
    await pool.query(`
      ALTER TABLE users
      ADD COLUMN token_version INT UNSIGNED NOT NULL DEFAULT 0
    `);
  },
};
