// services/characterRetirement.js
//
// An account plays one character at a time; past ones are retired, not
// deleted (migration 0057). Retiring frees characters.user_id, so every query
// that finds "the user's character" by user_id now finds the next one (or
// none, which sends the player to character creation). Everything keyed by
// character_id (domains, downtimes, XP log, inventory, retainers) stays with
// the retired character.
//
// Both helpers take a connection inside the caller's transaction.

// Coterie membership is checked by user_id, so a dead member left in place
// would hand their seat to the player's next character. Not restored on
// reactivation: a Storyteller re-adds them if the coterie takes them back.
async function retireCharacter(conn, charId) {
  const [[ch]] = await conn.query(
    'SELECT id, user_id FROM characters WHERE id = ? AND user_id IS NOT NULL FOR UPDATE', [charId]
  );
  if (!ch) return false;
  // The portrait goes with the character (migration 0058); the account is left
  // without one for the next character. Two statements: a multi-table UPDATE
  // does not guarantee assignment order.
  await conn.query(
    `UPDATE characters c JOIN users u ON u.id = ?
        SET c.avatar_url = u.avatar_url, c.avatar_url_thumb = u.avatar_url_thumb
      WHERE c.id = ?`, [ch.user_id, charId]
  );
  await conn.query('UPDATE users SET avatar_url = NULL, avatar_url_thumb = NULL WHERE id = ?', [ch.user_id]);
  // Left to right: retired_user_id takes user_id before it is cleared.
  await conn.query(
    'UPDATE characters SET retired_user_id = user_id, user_id = NULL, retired_at = NOW() WHERE id = ?', [charId]
  );
  await conn.query(
    'DELETE FROM coterie_members WHERE character_id = ? OR (user_id = ? AND character_id IS NULL)', [charId, ch.user_id]
  );
  return true;
}

// Makes a retired character its owner's current one again, retiring whoever
// is current now. Clears is_deceased: bringing a character back means the
// death is undone. Returns the owner's user id, or null if not retired.
async function restoreCharacter(conn, charId) {
  const [[ch]] = await conn.query(
    'SELECT id, retired_user_id FROM characters WHERE id = ? AND retired_user_id IS NOT NULL FOR UPDATE', [charId]
  );
  if (!ch) return null;
  const [[current]] = await conn.query(
    'SELECT id FROM characters WHERE user_id = ? FOR UPDATE', [ch.retired_user_id]
  );
  if (current) await retireCharacter(conn, current.id);
  // Its portrait becomes the account's again.
  await conn.query(
    `UPDATE users u JOIN characters c ON c.id = ?
        SET u.avatar_url = c.avatar_url, u.avatar_url_thumb = c.avatar_url_thumb
      WHERE u.id = ?`, [charId, ch.retired_user_id]
  );
  await conn.query(
    `UPDATE characters SET user_id = retired_user_id, retired_user_id = NULL, retired_at = NULL, is_deceased = 0,
            avatar_url = NULL, avatar_url_thumb = NULL
      WHERE id = ?`,
    [charId]
  );
  return ch.retired_user_id;
}

module.exports = { retireCharacter, restoreCharacter };
