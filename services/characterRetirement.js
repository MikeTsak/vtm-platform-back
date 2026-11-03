// services/characterRetirement.js
//
// An account plays one character at a time; past ones are retired, not
// deleted (migration 0057). Retiring frees characters.user_id, so every query
// that finds "the user's character" by user_id now finds the next one (or
// none, which sends the player to character creation). Everything keyed by
// character_id (domains, downtimes, XP log, inventory, retainers) stays with
// the retired character.
//
// Comms (chat, mail, NPC threads, notes, premonitions, drafts) are keyed by
// account, so retiring moves them to the character's archive account
// (users.archived_character_id, migration 0075): the next character starts
// with none, other players' threads with the dead one keep its name, and
// restoring moves them back. Archive accounts cannot log in and are left out
// of user lists (filter `archived_character_id IS NULL`).
//
// Both helpers take a connection inside the caller's transaction.

const { parseSheet } = require('../utils/sheet');

// Character status flags that end a character's story: its player may make a
// new one themselves (POST /api/characters). Missing may come back; hunted lives.
const isOutOfPlay = (c) => !!(c && (c.is_deceased || c.is_left || c.is_exiled));
// ...or a Storyteller allowed it for any other reason (a missing character,
// a player change): sheet.allow_new_character, set in Admin > Characters and
// consumed when the character is retired. Players can't set it (see
// stripStorytellerGrants in routes/characters.js, utils/playerSheetEdit.js).
const canStartNew = (c) => isOutOfPlay(c) || parseSheet(c?.sheet).allow_new_character === true;

// Every account-keyed comms column. `UPDATE IGNORE`: a row that would collide
// with one the target already has (a reaction, a conversation setting) stays put.
const COMMS_COLUMNS = [
  ['chat_messages', 'sender_id'], ['chat_messages', 'recipient_id'],
  ['chat_group_messages', 'sender_id'], ['chat_message_reactions', 'user_id'],
  ['chat_media', 'uploader_id'],
  // Group seats and groups they made: the dead stay in the group under their
  // own name; the player's next character is a separate member if added.
  ['chat_group_members', 'user_id'], ['chat_groups', 'created_by'],
  ['npc_messages', 'user_id'], ['npc_email_threads', 'user_id'], ['email_threads', 'user_id'],
  ['anonymous_notes', 'user_id'],
  ['premonition_recipients', 'user_id'], ['premonition_targets', 'user_id'],
  ['comms_drafts', 'user_id'],
];

// Conversation keys (utils/chatConversation.js convKey) name accounts:
// u:<low>:<high> for a DM, n:<npc>:<user> for an NPC thread.
function swapConvKey(key, from, to) {
  const [kind, a, b] = key.split(':');
  if (kind === 'u') {
    const [x, y] = [+a, +b].map(id => (id === from ? to : id));
    return `u:${Math.min(x, y)}:${Math.max(x, y)}`;
  }
  if (kind === 'n' && +b === from) return `n:${a}:${to}`;
  return key;
}

async function moveComms(conn, from, to) {
  for (const [table, col] of COMMS_COLUMNS) {
    await conn.query(`UPDATE IGNORE \`${table}\` SET \`${col}\` = ? WHERE \`${col}\` = ?`, [to, from]);
  }
  // A seat left behind duplicates one the target already holds in that group
  // (restoring a character whose next one had been added there too).
  await conn.query('DELETE FROM chat_group_members WHERE user_id = ?', [from]);
  // Theme/emoji of a conversation, and anyone's drafts addressed to it, follow it.
  const keyRe = `^(u:${from}:[0-9]+|u:[0-9]+:${from}|n:[0-9]+:${from})$`;
  for (const table of ['chat_conversation_settings', 'comms_drafts']) {
    const [rows] = await conn.query(`SELECT DISTINCT conv_key FROM \`${table}\` WHERE conv_key REGEXP ?`, [keyRe]);
    for (const { conv_key } of rows) {
      await conn.query(`UPDATE IGNORE \`${table}\` SET conv_key = ? WHERE conv_key = ?`, [swapConvKey(conv_key, from, to), conv_key]);
    }
  }
}

// The character's archive account, created on its first retirement. It wears
// the character's name and saved portrait, so its old messages read as theirs.
async function archiveAccount(conn, charId) {
  const [[c]] = await conn.query('SELECT name, avatar_url, avatar_url_thumb FROM characters WHERE id = ?', [charId]);
  const [[a]] = await conn.query('SELECT id FROM users WHERE archived_character_id = ?', [charId]);
  if (a) {
    await conn.query('UPDATE users SET display_name = ?, avatar_url = ?, avatar_url_thumb = ? WHERE id = ?',
      [c.name, c.avatar_url, c.avatar_url_thumb, a.id]);
    return a.id;
  }
  // '!' is no bcrypt hash, and login skips archive accounts anyway.
  const [r] = await conn.query(
    `INSERT INTO users (email, display_name, password_hash, role, archived_character_id, avatar_url, avatar_url_thumb)
     VALUES (?, ?, '!', 'user', ?, ?, ?)`,
    [`archived-character-${charId}@archive.invalid`, c.name, charId, c.avatar_url, c.avatar_url_thumb]
  );
  return r.insertId;
}

// Coterie membership is checked by user_id, so a dead member left in place
// would hand their seat to the player's next character. (Chat group seats go
// with the comms instead: the dead stay in the group.) Divisions it rules are
// vacated (kept as the previous owner, as the Steward's Vacate does), and it
// stops being a guest or resident anywhere. None of this comes back on
// restore: the court reassigns it.
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
  // Left to right: retired_user_id takes user_id before it is cleared. The
  // "may start a new character" grant is used up: a restore must not bring it back.
  await conn.query(
    `UPDATE characters SET retired_user_id = user_id, user_id = NULL, retired_at = NOW(),
            sheet = IF(JSON_VALID(sheet), JSON_REMOVE(sheet, '$.allow_new_character'), sheet)
      WHERE id = ?`, [charId]
  );
  await conn.query(
    'DELETE FROM coterie_members WHERE character_id = ? OR (user_id = ? AND character_id IS NULL)', [charId, ch.user_id]
  );
  await moveComms(conn, ch.user_id, await archiveAccount(conn, charId));

  // Left to right: previous_* take the owner before it is cleared.
  await conn.query(
    `UPDATE domain_claims
        SET previous_owner_name = owner_name, previous_owner_character_id = owner_character_id, previous_claimed_at = claimed_at,
            owner_character_id = NULL, owner_npc_id = NULL, owner_name = NULL, color = '#888888', is_abaton = 0, assigned_by = NULL
      WHERE owner_character_id = ? AND is_abaton = 0`, [charId]
  );
  await conn.query('DELETE FROM domain_guests WHERE character_id = ?', [charId]);
  await conn.query('DELETE FROM domain_residents WHERE character_id = ?', [charId]);

  // What it still had pending can no longer be granted to it: a Steward
  // approving its domain request would hand the division to the dead.
  await conn.query(
    "UPDATE domain_claim_requests SET status = 'rejected', resolved_at = NOW() WHERE character_id = ? AND status = 'pending'", [charId]
  );
  await conn.query(
    "UPDATE discipline_requests SET status = 'rejected', resolved_at = NOW(), admin_note = 'Character retired' WHERE character_id = ? AND status = 'pending'", [charId]
  );
  await conn.query(
    "UPDATE inventory_transfers SET status = 'cancelled' WHERE status IN ('open','pending') AND (from_character_id = ? OR to_character_id = ?)", [charId, charId]
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
  // Its comms come back with it.
  const [[a]] = await conn.query('SELECT id FROM users WHERE archived_character_id = ?', [charId]);
  if (a) await moveComms(conn, a.id, ch.retired_user_id);
  return ch.retired_user_id;
}

// SQL subquery: id of the character account `userCol` was playing at time
// `timeCol` (both SQL expressions). Use it to sign historical records (who
// recorded a boon, who called a Blood Hunt, who issued a decree), so they keep
// the name they were signed with after the player retires that character.
// Joining on `characters.user_id` instead would re-label them to the new one.
// The pick: not yet retired at that time, created by then if possible, earliest
// retirement first (a restored character has lost its old retired_at).
function characterAtSql(userCol, timeCol) {
  const t = `COALESCE(${timeCol}, NOW())`;
  return `(SELECT ca.id FROM characters ca
     WHERE (ca.user_id = ${userCol} OR ca.retired_user_id = ${userCol})
       AND (ca.retired_at IS NULL OR ca.retired_at > ${t})
     ORDER BY ca.created_at <= ${t} DESC, ca.retired_at IS NULL, ca.retired_at
     LIMIT 1)`;
}

module.exports = { retireCharacter, restoreCharacter, characterAtSql, isOutOfPlay, canStartNew };
