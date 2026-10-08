// back/migrations/list/0047_coterie_members_character_backfill.js
// Migration 0047: re-run the coterie_members.character_id backfill from 0008.
// Members added while their player had no character yet (or before 0008 ran)
// kept character_id NULL. Every coterie-retainer path keys on it, so such a
// coterie could not pick a ghoul's domitor or see its clan Disciplines.
// Data only, idempotent: fills NULLs with the player's first character.

module.exports = {
  name: '0047_coterie_members_character_backfill',
  async up(pool) {
    await pool.query(`
      UPDATE coterie_members m
      JOIN (SELECT user_id, MIN(id) AS character_id FROM characters GROUP BY user_id) c
        ON c.user_id = m.user_id
      SET m.character_id = c.character_id
      WHERE m.character_id IS NULL
    `);
  },
};
