// migrations/list/0033_drop_rumor_reactions.js
//
// Drops the rumor_reactions table cleanly.
module.exports = {
  name: '0033_drop_rumor_reactions',
  async up(pool) {
    await pool.query('DROP TABLE IF EXISTS rumor_reactions');
  },
};
