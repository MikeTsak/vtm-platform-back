// services/chatForward.js
//
// What a chat send route stores, read from its request (all four: DM, group,
// player->NPC, Storyteller-as-NPC). Either the typed message, or, with
// `forward_of: { kind: 'dm' | 'group' | 'npc', id }`, a copy of a message the
// sender can see, labelled with its author (forwarded_from, migration 0080):
// "Forwarded from Livia". The label is the author's in-universe name worked out
// here, never taken from the client, so a forward can't be faked, and a
// forward of a forward keeps the first author.
//
// An attachment must be one the sender may see (canAccessChatMedia): attaching
// an id shows it to everyone in that chat, so a guessed id used to expose
// someone else's private image.
const pool = require('../db');
const { isAdmin } = require('./guards');
const { canAccessChatMedia } = require('./chatMedia');

// The author's character name (or the retired character's, via its archive
// account), like the chat history shows it; the account name only as fallback.
const AUTHOR = 'COALESCE(c.name, u.display_name)';
const CHAR = 'LEFT JOIN characters c ON c.user_id = u.id OR c.id = u.archived_character_id';
const SOURCES = {
  dm: {
    sql: `SELECT m.body, m.attachment_id, m.forwarded_from, ${AUTHOR} AS author
            FROM chat_messages m JOIN users u ON u.id = m.sender_id ${CHAR}
           WHERE m.id = ? AND IFNULL(m.type, 'text') <> 'system' AND (? OR ? IN (m.sender_id, m.recipient_id)) LIMIT 1`,
    params: (id, admin, uid) => [id, admin, uid],
  },
  group: {
    sql: `SELECT m.body, m.attachment_id, m.forwarded_from, ${AUTHOR} AS author
            FROM chat_group_messages m JOIN users u ON u.id = m.sender_id ${CHAR}
           WHERE m.id = ? AND IFNULL(m.type, 'text') <> 'system'
             AND (? OR EXISTS (SELECT 1 FROM chat_group_members g WHERE g.group_id = m.group_id AND g.user_id = ?)) LIMIT 1`,
    params: (id, admin, uid) => [id, admin, uid],
  },
  npc: {
    sql: `SELECT m.body, m.attachment_id, m.forwarded_from, IF(m.from_side = 'npc', n.name, ${AUTHOR}) AS author
            FROM npc_messages m JOIN npcs n ON n.id = m.npc_id JOIN users u ON u.id = m.user_id ${CHAR}
           WHERE m.id = ? AND m.status <> 'queued' AND IFNULL(m.type, 'text') <> 'system' AND (? OR m.user_id = ?) LIMIT 1`,
    params: (id, admin, uid) => [id, admin, uid],
  },
};

// The message to forward, if `user` can see it; else null.
async function forwardSource(user, forwardOf) {
  const src = SOURCES[forwardOf?.kind];
  const id = Number(forwardOf?.id);
  if (!src || !Number.isInteger(id) || id <= 0) return null;
  const [[row]] = await pool.query(src.sql, src.params(id, isAdmin(user) ? 1 : 0, user.id));
  return row || null;
}

// Returns { body, attachment_id, reply_to_id, forwarded_from } for the route
// to store, or { status, error } to refuse with.
async function messageInput(req) {
  const b = req.body || {};
  if (b.forward_of) {
    const src = await forwardSource(req.user, b.forward_of);
    if (!src) return { status: 404, error: 'That message is no longer there to forward.' };
    return {
      body: src.body || '',
      attachment_id: src.attachment_id || null,
      reply_to_id: null,
      forwarded_from: String(src.forwarded_from || src.author || 'Unknown').slice(0, 255),
    };
  }
  const attachmentId = b.attachment_id ? Number(b.attachment_id) : null;
  if (attachmentId && !(await canAccessChatMedia(attachmentId, req.user))) {
    return { status: 403, error: 'That attachment is not yours to send.' };
  }
  return { body: b.body, attachment_id: attachmentId, reply_to_id: b.reply_to_id, forwarded_from: null };
}

module.exports = { messageInput, forwardSource };
