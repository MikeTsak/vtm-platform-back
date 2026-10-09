// routes/chat.js
//
// SchreckNet chat: direct messages, group rooms, reactions, media, and the
// edit/delete window. Realtime fan-out goes through fastify.io.

const { isAdmin: checkIsAdmin, isOwnerOrAdmin } = require('../services/guards');
const { idempotencyCheck, idempotencySave } = require('../utils/idempotency');
const { convKey, loadConvSettings, historyWindow, courtStanding, emojiSize } = require('../utils/chatConversation');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, moderateLimiter, uploadLimiter, sendPushNotification, sharp } = opts;

  // A chat_media row is visible to whoever uploaded it, or to a participant
  // of whichever message (DM / group / NPC) actually references it as its
  // attachment_id — not to any authenticated user who can guess its numeric
  // id. Admins can always see everything (moderation).
  async function canAccessChatMedia(mediaId, user) {
    if (!mediaId || !user) return false;
    if (user.role === 'admin') return true;

    const [rows] = await pool.query(
      `SELECT 1 FROM chat_media WHERE id = ? AND uploader_id = ?
       UNION
       SELECT 1 FROM chat_messages WHERE attachment_id = ? AND (sender_id = ? OR recipient_id = ?)
       UNION
       SELECT 1 FROM npc_messages WHERE attachment_id = ? AND user_id = ?
       UNION
       SELECT 1 FROM chat_group_messages gm
         JOIN chat_group_members mem ON mem.group_id = gm.group_id AND mem.user_id = ?
       WHERE gm.attachment_id = ?
       LIMIT 1`,
      [mediaId, user.id, mediaId, user.id, user.id, mediaId, user.id, user.id, mediaId]
    );
    return rows.length > 0;
  }

  // A member's display name for system-message text: character name if they
  // have one, else their account display name — same fallback the group
  // message queries already use (m.char_name || m.display_name).
  async function nameFor(userId) {
    const [[row]] = await pool.query(
      `SELECT u.display_name, c.name as char_name FROM users u
       LEFT JOIN characters c ON c.user_id = u.id WHERE u.id=?`,
      [userId]
    );
    return row?.char_name || row?.display_name || 'Someone';
  }

  // A reply may only quote a message from the same conversation; `sql` must
  // select that message's id scoped to the thread. Anything else (a forged
  // id, or a message deleted between tapping Reply and sending) is dropped
  // and the message goes out as a plain, non-reply message.
  async function validReplyTo(replyToId, sql, params) {
    const id = Number(replyToId);
    if (!Number.isInteger(id) || id <= 0) return null;
    const [rows] = await pool.query(sql, [id, ...params]);
    return rows.length ? id : null;
  }

  // Any current member (or a global admin) may rename a group, change its
  // icon, or add/kick members — this isn't creator-only.
  async function isMemberOrAdmin(groupId, user) {
    if (user.role === 'admin') return true;
    const [rows] = await pool.query('SELECT 1 FROM chat_group_members WHERE group_id=? AND user_id=?', [groupId, user.id]);
    return rows.length > 0;
  }

  // Inserts an auto-generated line (member added/removed, renamed, icon
  // changed) into a group's history and fans it out over the same
  // chat:refresh event real messages use, so it appears live without a
  // page reload. sender_id is the user who performed the action, kept for
  // attribution/avatar even though the body itself isn't something a
  // player typed.
  async function postSystemMessage(groupId, actorId, text) {
    const [r] = await pool.query(
      "INSERT INTO chat_group_messages (group_id, sender_id, body, type) VALUES (?,?,?,'system')",
      [groupId, actorId, text]
    );
    const [members] = await pool.query('SELECT user_id FROM chat_group_members WHERE group_id=?', [groupId]);
    if (fastify.io) {
      for (const m of members) fastify.io.to(`user_${m.user_id}`).emit('chat:refresh', { type: 'group', groupId });
      fastify.io.to(`group_${groupId}`).emit('chat:refresh', { type: 'group', groupId });
    }
    return r.insertId;
  }

  // Posts a system message to any conversation kind (group, DM, or NPC thread)
  // and notifies participants in real time.
  async function postConversationSystemMessage(conv, actorUser, text) {
    if (conv.kind === 'group' || conv.groupId) {
      const gId = conv.groupId || conv.id;
      return await postSystemMessage(gId, actorUser.id, text);
    }
    if (conv.kind === 'user') {
      const otherId = conv.otherUserId;
      const [r] = await pool.query(
        "INSERT INTO chat_messages (sender_id, recipient_id, body, type) VALUES (?, ?, ?, 'system')",
        [actorUser.id, otherId, text]
      );
      if (fastify.io) {
        fastify.io.to(`user_${actorUser.id}`).emit('chat:refresh', { type: 'player', partnerId: otherId });
        fastify.io.to(`user_${otherId}`).emit('chat:refresh', { type: 'player', partnerId: actorUser.id });
      }
      return r.insertId;
    }
    if (conv.kind === 'npc') {
      const [r] = await pool.query(
        "INSERT INTO npc_messages (npc_id, user_id, from_side, body, type) VALUES (?, ?, 'user', ?, 'system')",
        [conv.npcId, conv.playerId, text]
      );
      if (fastify.io) {
        fastify.io.to(`user_${conv.playerId}`).emit('chat:refresh', { type: 'npc', npcId: conv.npcId });
        fastify.io.to('admin_chat').emit('chat:refresh', { type: 'npc', npcId: conv.npcId });
      }
      return r.insertId;
    }
  }


  fastify.get('/api/chat/my-recent', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const userId = req.user.id;
      const limit = 20;

      // NPC Messages (Count unread from NPC to User)
      const [npcRows] = await pool.query(
        `SELECT m.id, m.npc_id AS partner_id, n.name AS partner_name, 
              m.body, m.created_at, 'npc' as type,
              COALESCE(u.unread_count, 0) as unread_count
       FROM npc_messages m
       JOIN npcs n ON n.id = m.npc_id
       LEFT JOIN (
         SELECT npc_id, COUNT(*) as unread_count
         FROM npc_messages
         WHERE user_id = ? AND from_side = 'npc' AND read_at IS NULL AND status != 'queued'
         GROUP BY npc_id
       ) u ON u.npc_id = m.npc_id
       WHERE m.user_id = ? AND IFNULL(n.is_disabled, 0) = 0 AND m.status != 'queued'
       ORDER BY m.created_at DESC LIMIT ?`,
        [userId, userId, limit]
      );

      // Player Messages (Count unread from Sender to User)
      const [playerRows] = await pool.query(
        `SELECT cm.id, 
              CASE WHEN cm.sender_id = ? THEN cm.recipient_id ELSE cm.sender_id END as partner_id,
              CASE WHEN cm.sender_id = ? THEN r.display_name ELSE s.display_name END as partner_name,
              cm.body, cm.created_at, 'player' as type,
              COALESCE(u.unread_count, 0) as unread_count
       FROM chat_messages cm
       JOIN users s ON cm.sender_id = s.id
       JOIN users r ON cm.recipient_id = r.id
       LEFT JOIN (
         SELECT sender_id, COUNT(*) as unread_count
         FROM chat_messages
         WHERE recipient_id = ? AND read_at IS NULL
         GROUP BY sender_id
       ) u ON u.sender_id = (CASE WHEN cm.sender_id = ? THEN cm.recipient_id ELSE cm.sender_id END)
       WHERE cm.sender_id = ? OR cm.recipient_id = ?
       ORDER BY cm.created_at DESC LIMIT ?`,
        [userId, userId, userId, userId, userId, userId, limit]
      );

      const all = [...npcRows, ...playerRows];

      const seenMap = new Map();
      const uniqueConvos = [];

      // Sort absolute latest first to extract the unique latest messages
      all.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

      for (const msg of all) {
        const key = `${msg.type}-${msg.partner_id}`;
        if (!seenMap.has(key)) {
          seenMap.set(key, true);
          uniqueConvos.push({
            id: msg.id,
            partnerName: msg.partner_name,
            lastMessage: msg.body,
            timestamp: msg.created_at,
            isNPC: msg.type === 'npc',
            linkId: msg.partner_id,
            unread_count: msg.unread_count || 0
          });
        }
        if (uniqueConvos.length >= limit) break;
      }
      reply.send({ conversations: uniqueConvos });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to load recent chats' });
    }
  });

  // Upload Image & Audio
  fastify.post('/api/chat/upload', { preHandler: [authRequired, uploadLimiter] }, async (req, reply) => {
    try {
      const fileData = await req.file();
      if (!fileData) return reply.status(400).send({ error: 'No file provided' });

      const mimetype = fileData.mimetype || '';
      if (!mimetype.startsWith('image/') && !mimetype.startsWith('audio/')) {
        return reply.status(400).send({ error: 'Invalid file type. Only images and audio allowed.' });
      }

      const rawBuffer = await fileData.toBuffer();
      let finalBuffer = rawBuffer;
      let finalMime = mimetype;
      let finalSize = rawBuffer.length;
      let finalFilename = fileData.filename || 'uploaded_chat_media';

      if (mimetype.startsWith('image/')) {
        finalBuffer = await sharp(rawBuffer)
          .resize(1000, 1000, { fit: 'inside', withoutEnlargement: true })
          .webp({ quality: 80 })
          .toBuffer();
        finalMime = 'image/webp';
        finalSize = finalBuffer.length;
        finalFilename = finalFilename.replace(/\.[^/.]+$/, "") + ".webp";
      }

      // Insert into DB
      const [ins] = await pool.query(
        'INSERT INTO chat_media (uploader_id, filename, mime, size, data) VALUES (?,?,?,?,?)',
        [req.user.id, finalFilename, finalMime, finalSize, finalBuffer]
      );

      log.ok('Chat media uploaded', { user_id: req.user.id, media_id: ins.insertId });
      reply.send({ id: ins.insertId, url: `/api/chat/media/${ins.insertId}` });
    } catch (e) {
      log.err('Chat upload failed', { message: e.message, stack: e.stack });
      reply.status(500).send({ error: 'Upload failed' });
    }
  });

  // Serve Image
  // In server.js

  // Replace the existing GET /api/chat/media/:id route with this:

  fastify.get('/api/chat/media/:id', { preHandler: [authRequired] }, async (req, reply) => {
    // Auth is handled by authRequired (Authorization header or the httpOnly
    // session cookie — <img> tags send the cookie automatically for same-origin
    // requests, so there's no need for a token in the URL).
    try {
      const id = Number(req.params.id);
      if (!(await canAccessChatMedia(id, req.user))) return reply.status(404).send('Not found');

      const [rows] = await pool.query('SELECT mime, size, data FROM chat_media WHERE id=?', [id]);
      if (!rows.length) return reply.status(404).send('Not found');

      const { mime, size, data } = rows[0];
      reply.header('Content-Type', mime);
      reply.header('Content-Length', size);
      reply.header('Cache-Control', 'private, max-age=31536000');
      reply.send(data);
    } catch (e) {
      reply.status(404).send('Not found');
    }
  });

  /* -------------------- Chat -------------------- */
  // NOTE TO USER: You may need to add 'chat' to your logger configuration if it's a custom one.

  /* -------------------- Group Chat Routes (NEW) -------------------- */

  // List groups for the current user (with metadata)
  // Total unread across DMs, groups and NPC threads — drives the SchreckNet
  // badge in the nav. Mirrors the per-contact counts of /chat/users, /chat/groups
  // and /chat/npcs (admins count players' unread messages to any NPC).
  fastify.get('/api/chat/unread-count', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const userId = req.user.id;
      const isAdmin = checkIsAdmin(req.user);
      const npcSql = isAdmin
        ? `SELECT COUNT(*) FROM npc_messages m JOIN npcs n ON n.id = m.npc_id
           WHERE m.from_side = 'user' AND m.read_at IS NULL AND IFNULL(n.is_disabled, 0) = 0`
        : `SELECT COUNT(*) FROM npc_messages m JOIN npcs n ON n.id = m.npc_id
           WHERE m.user_id = ? AND m.from_side = 'npc' AND m.read_at IS NULL AND m.status != 'queued'
             AND IFNULL(n.is_disabled, 0) = 0`;
      const [[row]] = await pool.query(`
        SELECT
          (SELECT COUNT(*) FROM chat_messages WHERE recipient_id = ? AND read_at IS NULL) AS dms,
          (SELECT COUNT(*) FROM chat_group_messages gm
             JOIN chat_group_members m ON m.group_id = gm.group_id AND m.user_id = ?
            WHERE gm.created_at > m.last_read_at AND gm.sender_id != ?) AS grp,
          (${npcSql}) AS npc
      `, isAdmin ? [userId, userId, userId] : [userId, userId, userId, userId]);
      reply.send({ count: Number(row.dms) + Number(row.grp) + Number(row.npc) });
    } catch (e) {
      log.err('Failed to count unread chat', { message: e.message });
      reply.status(500).json({ error: 'Failed to count unread' });
    }
  });

  fastify.get('/api/chat/groups', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const userId = req.user.id;
      // Χρήση COALESCE για να μπαίνει η ημερομηνία δημιουργίας αν δεν υπάρχει μήνυμα.
      // Προσθήκη unread_count: Μετράει πόσα μηνύματα (που ΔΕΝ έστειλε ο ίδιος ο χρήστης) 
      // έχουν δημιουργηθεί μετά το last_read_at του συγκεκριμένου χρήστη στην ομάδα.
      // Ταξινόμηση ώστε οι ομάδες με αδιάβαστα να πηγαίνουν πάνω, και μετά να ταξινομούνται ανά παλαιότητα.
      const [rows] = await pool.query(`
      SELECT
        g.id, g.name, g.icon, g.created_by, g.created_at as group_created_at,
        COALESCE(
          (
            SELECT created_at 
            FROM chat_group_messages 
            WHERE group_id = g.id 
            ORDER BY created_at DESC LIMIT 1
          ), 
          g.created_at
        ) as last_message_at,
        (
          SELECT COUNT(*) 
          FROM chat_group_messages 
          WHERE group_id = g.id AND created_at > m.last_read_at AND sender_id != ?
        ) as unread_count
      FROM chat_groups g
      JOIN chat_group_members m ON m.group_id = g.id
      WHERE m.user_id = ?
      ORDER BY unread_count DESC, last_message_at DESC
    `, [userId, userId]); // <-- Προσοχή: Βάλαμε το userId δύο φορές στα parameters!

      reply.send({ groups: rows });
    } catch (e) {
      log.err('Failed to get chat groups', { message: e.message });
      reply.status(500).json({ error: 'Failed to get groups' });
    }
  });

  // Mark all messages in a group as read (updates last_read_at)
  fastify.post('/api/chat/groups/:id/read', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const groupId = Number(req.params.id);
      await pool.query(
        'UPDATE chat_group_members SET last_read_at = NOW() WHERE group_id = ? AND user_id = ?',
        [groupId, req.user.id]
      );
      if (fastify.io) fastify.io.to(`user_${req.user.id}`).emit('chat:refresh', { type: 'read', groupId });
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to mark group as read' });
    }
  });

  // Create a new group
  fastify.post('/api/chat/groups', { preHandler: [authRequired, moderateLimiter] }, async (req, reply) => {
    const conn = await pool.getConnection();
    try {
      const { name, members = [], icon } = req.body; // members is array of user_ids
      if (!name || !members.length) {
        return reply.status(400).json({ error: 'Name and at least one other member required' });
      }
      // icon: a literal emoji character, or a ':Clan_Name:' crest token
      // (same convention as chat_message_reactions.emoji) — capped the same
      // way for the same reason (varchar column, arbitrary client input).
      const groupIcon = typeof icon === 'string' && icon.trim() && icon.length <= 32 ? icon.trim() : null;

      await conn.beginTransaction();

      // 1. Create Group
      const [g] = await conn.query('INSERT INTO chat_groups (name, icon, created_by) VALUES (?, ?, ?)', [name.trim(), groupIcon, req.user.id]);
      const groupId = g.insertId;

      // 2. Add Creator to Members
      const allMembers = [req.user.id, ...members.map(Number)].filter((v, i, a) => a.indexOf(v) === i && !isNaN(v));
      const values = allMembers.map(uid => [groupId, uid]);

      await conn.query('INSERT INTO chat_group_members (group_id, user_id) VALUES ?', [values]);

      await conn.commit();

      // Fetch and return the new group object
      const [rows] = await pool.query('SELECT * FROM chat_groups WHERE id=?', [groupId]);
      log.ok('Group created', { user_id: req.user.id, group_id: groupId, name });
      reply.status(201).json({ group: rows[0] });

    } catch (e) {
      await conn.rollback();
      log.err('Failed to create group', { message: e.message });
      reply.status(500).json({ error: 'Failed to create group' });
    } finally {
      conn.release();
    }
  });

  // Get history for a specific group
  fastify.get('/api/chat/groups/:id/history', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const groupId = Number(req.params.id);
      const userId = req.user.id;

      // 1. Verify Membership
      const [m] = await pool.query('SELECT 1 FROM chat_group_members WHERE group_id=? AND user_id=?', [groupId, userId]);
      if (!m.length) return reply.status(403).json({ error: 'Not a member of this group' });

      // 2. Fetch Messages
      const w = await historyWindow(pool, 'chat_group_messages', 'm', req.query);
      const [messages] = await pool.query(`
      SELECT * FROM (
      SELECT m.id, m.sender_id, m.body, m.created_at, m.type, m.edited, m.emoji_size,
            m.attachment_id, m.reply_to_id,
            u.display_name, c.name as char_name, c.clan,
            r.id AS reply_found, LEFT(r.body, 300) AS reply_body, r.sender_id AS reply_sender_id,
            r.attachment_id AS reply_attachment_id, COALESCE(rc.name, ru.display_name) AS reply_sender_name
      FROM chat_group_messages m
      LEFT JOIN users u ON m.sender_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      LEFT JOIN chat_group_messages r ON r.id = m.reply_to_id
      LEFT JOIN users ru ON ru.id = r.sender_id
      LEFT JOIN characters rc ON rc.user_id = r.sender_id
      WHERE m.group_id = ?${w.sql}
      ${w.order}
      ) sub
      ORDER BY created_at ASC, id ASC
    `, [groupId, ...w.params]);

      const settings = await loadConvSettings(pool, convKey('group', groupId));
      reply.send({ messages, has_more: w.hasMore(messages), settings });
    } catch (e) {
      log.err('Failed to get group history', { message: e.message });
      reply.status(500).json({ error: 'Failed to get history' });
    }
  });

  // Get members of a specific group
  fastify.get('/api/chat/groups/:id/members', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const groupId = Number(req.params.id);

      // Check if user is in group or is admin
      const [m] = await pool.query('SELECT 1 FROM chat_group_members WHERE group_id=? AND user_id=?', [groupId, req.user.id]);
      if (!m.length && req.user.role !== 'admin') return reply.status(403).json({ error: 'Not a member' });

      const [members] = await pool.query(`
      SELECT u.id, u.display_name, c.name as char_name, c.clan,
             c.camarilla_titles AS titles, c.status AS court_status, c.is_hidden
      FROM chat_group_members cgm
      JOIN users u ON cgm.user_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE cgm.group_id = ?
      ORDER BY COALESCE(c.name, u.display_name) ASC
    `, [groupId]);
      reply.send({ members: members.map(({ titles, court_status, is_hidden, ...m }) => ({ ...m, ...courtStanding({ titles, court_status, is_hidden }) })) });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to get members' });
    }
  });

  // Add members to an existing group — any current member can invite
  // someone else in, not just the creator.
  fastify.post('/api/chat/groups/:id/members', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const groupId = Number(req.params.id);
      const { members } = req.body;
      if (!members || !members.length) return reply.status(400).json({ error: 'No members provided' });

      const [g] = await pool.query('SELECT created_by FROM chat_groups WHERE id=?', [groupId]);
      if (!g.length) return reply.status(404).json({ error: 'Group not found' });
      if (!(await isMemberOrAdmin(groupId, req.user))) return reply.status(403).json({ error: 'Not a member of this group' });

      const requestedIds = members.map(Number).filter(v => !isNaN(v));
      if (!requestedIds.length) return reply.status(400).json({ error: 'No members provided' });

      // Only the ids that weren't already members get a system line — an
      // INSERT IGNORE on an existing member is a silent no-op and shouldn't
      // announce anything.
      const [existing] = await pool.query(
        'SELECT user_id FROM chat_group_members WHERE group_id=? AND user_id IN (?)',
        [groupId, requestedIds]
      );
      const existingIds = new Set(existing.map(r => r.user_id));
      const newIds = requestedIds.filter(id => !existingIds.has(id));

      const values = requestedIds.map(uid => [groupId, uid]);
      await pool.query('INSERT IGNORE INTO chat_group_members (group_id, user_id) VALUES ?', [values]);

      if (newIds.length) {
        const actorName = await nameFor(req.user.id);
        for (const id of newIds) {
          const targetName = await nameFor(id);
          await postSystemMessage(groupId, req.user.id, `${actorName} added ${targetName}`);
        }
      }

      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to add members' });
    }
  });

  // Remove a member from a group — any current member can kick another
  // member (or leave themself); the creator can't be kicked by anyone,
  // only replaced by deleting the group.
  fastify.delete('/api/chat/groups/:id/members/:userId', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const groupId = Number(req.params.id);
      const targetUserId = Number(req.params.userId);

      const [g] = await pool.query('SELECT created_by FROM chat_groups WHERE id=?', [groupId]);
      if (!g.length) return reply.status(404).json({ error: 'Group not found' });

      if (!(await isMemberOrAdmin(groupId, req.user))) return reply.status(403).json({ error: 'Not a member of this group' });

      if (g[0].created_by === targetUserId) return reply.status(400).json({ error: 'Cannot remove creator' });

      await pool.query('DELETE FROM chat_group_members WHERE group_id=? AND user_id=?', [groupId, targetUserId]);

      const actorName = await nameFor(req.user.id);
      const text = req.user.id === targetUserId
        ? `${actorName} left the group chat`
        : `${actorName} removed ${await nameFor(targetUserId)} from the group chat`;
      await postSystemMessage(groupId, req.user.id, text);

      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to remove member' });
    }
  });

  // Delete a group entirely (Creator/Admin only)
  fastify.delete('/api/chat/groups/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const groupId = Number(req.params.id);
      const [g] = await pool.query('SELECT created_by FROM chat_groups WHERE id=?', [groupId]);
      if (!g.length) return reply.status(404).json({ error: 'Group not found' });
      if (!isOwnerOrAdmin(req.user, g[0].created_by)) return reply.status(403).json({ error: 'Only the creator can delete this group' });

      // ON DELETE CASCADE will automatically wipe the chat_group_members and chat_group_messages
      await pool.query('DELETE FROM chat_groups WHERE id=?', [groupId]);
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to delete group' });
    }
  });

  // Set/change a group's picture — a literal emoji or a ':Clan_Name:' crest
  // token. Any current member can change it, not just the creator.
  fastify.put('/api/chat/groups/:id/icon', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const groupId = Number(req.params.id);
      const { icon } = req.body || {};
      const groupIcon = typeof icon === 'string' && icon.trim() && icon.length <= 32 ? icon.trim() : null;

      const [g] = await pool.query('SELECT created_by FROM chat_groups WHERE id=?', [groupId]);
      if (!g.length) return reply.status(404).json({ error: 'Group not found' });
      if (!(await isMemberOrAdmin(groupId, req.user))) return reply.status(403).json({ error: 'Not a member of this group' });

      await pool.query('UPDATE chat_groups SET icon=? WHERE id=?', [groupIcon, groupId]);

      const actorName = await nameFor(req.user.id);
      await postSystemMessage(groupId, req.user.id, groupIcon
        ? `${actorName} set the group icon to ${groupIcon}`
        : `${actorName} removed the group icon`);

      reply.send({ ok: true, icon: groupIcon });
    } catch (e) {
      log.err('Failed to update group icon', { message: e.message });
      reply.status(500).json({ error: 'Failed to update group picture' });
    }
  });

  // Rename a group. Any current member can rename it, not just the creator.
  fastify.put('/api/chat/groups/:id/name', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const groupId = Number(req.params.id);
      const { name } = req.body || {};
      const newName = typeof name === 'string' ? name.trim() : '';
      if (!newName || newName.length > 100) return reply.status(400).json({ error: 'Name must be 1-100 characters' });

      const [g] = await pool.query('SELECT created_by, name FROM chat_groups WHERE id=?', [groupId]);
      if (!g.length) return reply.status(404).json({ error: 'Group not found' });
      if (!(await isMemberOrAdmin(groupId, req.user))) return reply.status(403).json({ error: 'Not a member of this group' });

      const oldName = g[0].name;
      if (newName === oldName) return reply.send({ ok: true, name: newName });

      await pool.query('UPDATE chat_groups SET name=? WHERE id=?', [newName, groupId]);

      const actorName = await nameFor(req.user.id);
      await postSystemMessage(groupId, req.user.id, `${actorName} changed the name of the groupchat from ${oldName} to ${newName}`);

      reply.send({ ok: true, name: newName });
    } catch (e) {
      log.err('Failed to rename group', { message: e.message });
      reply.status(500).json({ error: 'Failed to rename group' });
    }
  });

  // Send a message to a group
  fastify.post('/api/chat/groups/:id/messages', { preHandler: [authRequired, idempotencyCheck], onSend: [idempotencySave] }, async (req, reply) => {
    try {
      const groupId = Number(req.params.id);
      const { body, attachment_id, reply_to_id } = req.body;

      // Verify membership ... (keep existing check)
      const [m] = await pool.query('SELECT 1 FROM chat_group_members WHERE group_id=? AND user_id=?', [groupId, req.user.id]);
      if (!m.length) return reply.status(403).json({ error: 'Not a member' });

      if (!attachment_id && (!body || !body.trim())) return reply.status(400).json({ error: 'Content required' });

      const replyTo = await validReplyTo(reply_to_id,
        "SELECT id FROM chat_group_messages WHERE id=? AND group_id=? AND type != 'system'", [groupId]);

      const [r] = await pool.query('INSERT INTO chat_group_messages (group_id, sender_id, body, attachment_id, reply_to_id, emoji_size) VALUES (?,?,?,?,?,?)',
        [groupId, req.user.id, body ? body.trim() : '', attachment_id || null, replyTo, attachment_id ? null : emojiSize(body, req.body.emoji_size)]);

      const [[message]] = await pool.query(`
      SELECT m.id, m.sender_id, m.body, m.created_at, m.attachment_id, m.type, m.reply_to_id, m.emoji_size,
             u.display_name, c.name as char_name, c.clan
      FROM chat_group_messages m
      LEFT JOIN users u ON m.sender_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE m.id = ?
    `, [r.insertId]);

      // Every member except the sender: used both for push notifications and for
      // the realtime fan-out below. Declared out here on purpose — it used to be
      // scoped to the try block yet referenced again in the socket.io block, so
      // every group send threw a ReferenceError, fell into the outer catch and
      // answered 500 (after having already stored the message), and no client
      // ever received the chat:refresh event.
      let members = [];

      // --- NEW: PUSH NOTIFICATIONS ΓΙΑ ΟΜΑΔΙΚΕΣ ---
      try {
        // 1. Βρίσκουμε το όνομα της ομάδας
        const [[groupInfo]] = await pool.query('SELECT name, icon FROM chat_groups WHERE id=?', [groupId]);
        const groupName = groupInfo?.name || 'Group Chat';
        const senderName = message.char_name || message.display_name || 'Someone';

        // 2. Φτιάχνουμε το περιεχόμενο της ειδοποίησης
        const notifTitle = `Erebus Portal - 💬 ${groupName} (${senderName})`;
        const notifBody = message.attachment_id ? '📷 Image Attachment' : message.body;

        let iconUrl = null;
        if (groupInfo?.icon) {
          if (!groupInfo.icon.startsWith(':')) {
            const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">${groupInfo.icon}</text></svg>`;
            iconUrl = `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;
          }
        }

        // 3. Βρίσκουμε όλα τα μέλη εκτός από τον αποστολέα
        [members] = await pool.query('SELECT user_id FROM chat_group_members WHERE group_id=? AND user_id!=?', [groupId, req.user.id]);

        // 4. Στέλνουμε push notification στο κάθε μέλος
        // Not awaited: the sender's request used to wait on every member's
        // web push in turn, so one slow push endpoint made the send look
        // stuck, and the retry stored the message twice.
        for (const member of members) {
          sendPushNotification(member.user_id, notifTitle, notifBody, { url: '/schrecknet', icon: iconUrl }, 'chat').catch(() => { });
        }
      } catch (pushErr) {
        log.err('Failed to notify group members', { error: pushErr.message });
      }
      // --------------------------------------------

      if (fastify.io) {
        fastify.io.to(`group_${groupId}`).emit('chat:refresh', { type: 'group', groupId });
        for (const member of members) {
          fastify.io.to(`user_${member.user_id}`).emit('chat:refresh', { type: 'group', groupId });
        }
        fastify.io.to(`user_${req.user.id}`).emit('chat:refresh', { type: 'group', groupId });
      }

      reply.status(201).json({ message });
    } catch (e) {
      log.err('Group send failed', { message: e.message });
      reply.status(500).json({ error: 'Failed' });
    }
  });

  // Admin: List all groups
  fastify.get('/api/admin/chat/groups', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [groups] = await pool.query(`
      SELECT g.*, u.display_name as creator_name,
             COALESCE(m.member_count, 0) as member_count,
             msg.last_active
      FROM chat_groups g
      LEFT JOIN users u ON g.created_by = u.id
      LEFT JOIN (
        SELECT group_id, COUNT(*) as member_count
        FROM chat_group_members
        GROUP BY group_id
      ) m ON m.group_id = g.id
      LEFT JOIN (
        SELECT group_id, MAX(created_at) as last_active
        FROM chat_group_messages
        GROUP BY group_id
      ) msg ON msg.group_id = g.id
      ORDER BY last_active DESC
    `);
      reply.send({ groups });
    } catch (e) {
      reply.status(500).json({ error: 'Failed' });
    }
  });

  // ADMIN: Get all group messages (for stats)
  fastify.get('/api/admin/chat/groups/messages/all', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [messages] = await pool.query('SELECT * FROM chat_group_messages');
      reply.send({ messages });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch group messages' });
    }
  });

  // Admin: Get group history
  fastify.get('/api/admin/chat/groups/:id/history', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const groupId = Number(req.params.id);
      const [messages] = await pool.query(`
      SELECT m.id, m.sender_id, m.body, m.created_at,
            m.attachment_id, m.edited,
            u.display_name, c.name as char_name, c.clan
      FROM chat_group_messages m
      LEFT JOIN users u ON m.sender_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE m.group_id = ?
      ORDER BY m.created_at ASC
    `, [groupId]);

      reply.send({ messages });
    } catch (e) {
      reply.status(500).json({ error: 'Failed' });
    }
  });

  // Get list of users to chat with (Sorted by Recency & Unread)
  fastify.get('/api/chat/users', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const myId = req.user.id;

      // This query fetches users and calculates:
      // 1. last_msg: The timestamp of the latest message (sent OR received)
      // 2. unread: The count of messages sent BY this user TO me that are unread
      const [rows] = await pool.query(
        `
      SELECT
        u.id,
        u.display_name,
        u.role,
        CASE WHEN u.role = 'admin' THEN 1 ELSE 0 END AS is_admin,
        MAX(c.id)   AS char_id,
        MAX(c.name) AS char_name,
        MAX(c.clan) AS clan,
        MAX(c.image_url) AS image_url,
        (
          SELECT created_at 
          FROM chat_messages 
          WHERE (sender_id = u.id AND recipient_id = ?) OR (sender_id = ? AND recipient_id = u.id)
          ORDER BY created_at DESC LIMIT 1
        ) as last_message_at,
        (
          SELECT COUNT(*) 
          FROM chat_messages 
          WHERE sender_id = u.id AND recipient_id = ? AND read_at IS NULL
        ) as unread_count
      FROM users u
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE (? = 1 OR u.id <> ?)
      GROUP BY u.id, u.display_name, u.role
      ORDER BY 
        unread_count DESC,   -- Unread first
        last_message_at DESC, -- Then most recent
        u.display_name ASC    -- Then alphabetical
      `,
        [myId, myId, myId, req.query.include_self ? 1 : 0, myId]
      );

      const [standings] = await pool.query(
        'SELECT user_id, camarilla_titles AS titles, status AS court_status, is_hidden FROM characters'
      );
      const standingByUser = new Map(standings.map(c => [c.user_id, courtStanding(c)]));

      const users = rows.map(r => ({
        ...r,
        ...(standingByUser.get(r.id) || courtStanding(null)),
        is_admin: !!r.is_admin,
        char_id: r.char_id ? Number(r.char_id) : null,
        unread_count: Number(r.unread_count || 0)
      }));

      reply.send({ users });
    } catch (e) {
      log.err('Failed to get chat users', { message: e.message, stack: e.stack });
      reply.status(500).json({ error: 'Failed to get users' });
    }
  });

  // List all NPCs (Sorted by Recency)
  fastify.get('/api/chat/npcs', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const myId = req.user.id;
      const isAdmin = checkIsAdmin(req.user);
      let query, params;

      if (isAdmin) {
        // Admins see if ANY player has sent an unread message to the NPC
        query = `SELECT n.id, n.name, n.clan, n.image_url,
             n.camarilla_titles AS titles, n.status AS court_status, n.is_hidden,
             m.last_message_at,
             COALESCE(m.unread_count, 0) as unread_count
      FROM npcs n
      LEFT JOIN (
        SELECT npc_id,
               MAX(CASE WHEN status != 'queued' THEN created_at END) as last_message_at,
               COUNT(CASE WHEN from_side = 'user' AND read_at IS NULL THEN 1 END) as unread_count
        FROM npc_messages
        GROUP BY npc_id
      ) m ON m.npc_id = n.id
      WHERE IFNULL(n.is_disabled, 0) = 0
      ORDER BY unread_count DESC, last_message_at DESC, n.name ASC`;
        params = [];
      } else {
        // Players see if the NPC has sent them an unread message
        query = `SELECT n.id, n.name, n.clan, n.image_url,
             n.camarilla_titles AS titles, n.status AS court_status, n.is_hidden,
             m.last_message_at,
             COALESCE(m.unread_count, 0) as unread_count
      FROM npcs n
      LEFT JOIN (
        SELECT npc_id,
               MAX(CASE WHEN status != 'queued' THEN created_at END) as last_message_at,
               COUNT(CASE WHEN from_side = 'npc' AND read_at IS NULL AND status != 'queued' THEN 1 END) as unread_count
        FROM npc_messages
        WHERE user_id = ?
        GROUP BY npc_id
      ) m ON m.npc_id = n.id
      WHERE IFNULL(n.is_disabled, 0) = 0
      ORDER BY unread_count DESC, last_message_at DESC, n.name ASC`;
        params = [myId];
      }
      const [rows] = await pool.query(query, params);
      reply.send({ npcs: rows.map(({ titles, court_status, is_hidden, ...n }) => ({ ...n, ...courtStanding({ titles, court_status, is_hidden }) })) });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to list NPCs' });
    }
  });


  // Get message history with another user
  fastify.get('/api/chat/history/:otherUserId', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const otherUserId = Number(req.params.otherUserId);
      const myId = req.user.id;
      const w = await historyWindow(pool, 'chat_messages', 'cm', req.query);

      const [messages] = await pool.query(
        `SELECT * FROM (
         SELECT cm.id, cm.sender_id, cm.recipient_id, cm.body, cm.created_at,
                cm.read_at, cm.delivered_at, cm.edited, cm.emoji_size, cm.type,
                cm.attachment_id, cm.reply_to_id,
                u_sender.display_name as sender_name,
                r.id AS reply_found, LEFT(r.body, 300) AS reply_body,
                r.sender_id AS reply_sender_id, r.attachment_id AS reply_attachment_id
         FROM chat_messages cm
         JOIN users u_sender ON cm.sender_id = u_sender.id
         LEFT JOIN chat_messages r ON r.id = cm.reply_to_id
         WHERE ((cm.sender_id = ? AND cm.recipient_id = ?) OR (cm.sender_id = ? AND cm.recipient_id = ?))${w.sql}
         ${w.order}
       ) sub
       ORDER BY created_at ASC, id ASC`,
        [myId, otherUserId, otherUserId, myId, ...w.params]
      );

      const settings = await loadConvSettings(pool, convKey('user', Number(myId), otherUserId));
      reply.send({ messages, has_more: w.hasMore(messages), settings });
    } catch (e) {
      log.err('Failed to get chat history', { message: e.message });
      reply.status(500).json({ error: 'Failed to get history' });
    }
  });


  // Send a message
  fastify.post('/api/chat/messages', { preHandler: [authRequired, idempotencyCheck], onSend: [idempotencySave] }, async (req, reply) => {
    try {
      // Added attachment_id to destructuring
      const { recipient_id, body, attachment_id, reply_to_id } = req.body;

      // Allow empty body ONLY if there is an attachment
      if (!recipient_id || (!attachment_id && (!body || !body.trim()))) {
        return reply.status(400).send({ error: 'Recipient and content required' });
      }

      const replyTo = await validReplyTo(reply_to_id,
        "SELECT id FROM chat_messages WHERE id=? AND ((sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)) AND IFNULL(type, 'text') != 'system'",
        [req.user.id, recipient_id, recipient_id, req.user.id]);

      const [r] = await pool.query(
        'INSERT INTO chat_messages (sender_id, recipient_id, body, attachment_id, reply_to_id, emoji_size) VALUES (?, ?, ?, ?, ?, ?)',
        [req.user.id, recipient_id, body ? body.trim() : '', attachment_id || null, replyTo, attachment_id ? null : emojiSize(body, req.body.emoji_size)]
      );

      // Fetch back with attachment info
      const [[message]] = await pool.query(
        `SELECT cm.id, cm.sender_id, cm.recipient_id, cm.body, cm.created_at, cm.attachment_id, cm.reply_to_id, cm.emoji_size,
              u_sender.display_name as sender_name,
              c.name as char_name
       FROM chat_messages cm
       JOIN users u_sender ON cm.sender_id = u_sender.id
       LEFT JOIN characters c ON c.user_id = cm.sender_id
       WHERE cm.id = ?`,
        [r.insertId]
      );

      // Was missing category: 'chat' — it fell through to the default
      // 'system' category, so a player who'd only enabled chat
      // notifications (not system) never got pushed for a DM at all.
      const finalSenderName = message.char_name || message.sender_name;
      sendPushNotification(
        recipient_id,
        `Erebus Portal - ${finalSenderName}`,
        message.attachment_id ? '📷 Image Attachment' : message.body,
        { url: '/schrecknet', icon: `/api/users/${req.user.id}/avatar` },
        'chat'
      ).catch(() => {});

      if (fastify.io) {
        fastify.io.to(`user_${recipient_id}`).emit('chat:refresh', { type: 'user', partnerId: req.user.id });
        fastify.io.to(`user_${req.user.id}`).emit('chat:refresh', { type: 'user', partnerId: recipient_id });
      }

      reply.status(201).send({ message });
    } catch (e) {
      log.err('Failed to send message', { message: e.message });
      reply.status(500).send({ error: 'Failed' });
    }
  });

  // Socket rooms whose clients are showing a given message: both sides of a
  // DM, the group's room, or the player plus the admin room for NPC chats.
  async function messageRooms(table, messageId) {
    if (table === 'chat_messages') {
      const [[m]] = await pool.query('SELECT sender_id, recipient_id FROM chat_messages WHERE id=?', [messageId]);
      return m ? [`user_${m.sender_id}`, `user_${m.recipient_id}`] : [];
    }
    if (table === 'chat_group_messages') {
      const [[m]] = await pool.query('SELECT group_id FROM chat_group_messages WHERE id=?', [messageId]);
      return m ? [`group_${m.group_id}`] : [];
    }
    if (table === 'npc_messages') {
      const [[m]] = await pool.query('SELECT user_id FROM npc_messages WHERE id=?', [messageId]);
      return m ? [`user_${m.user_id}`, 'admin_chat'] : [];
    }
    return [];
  }

  // Edits and deletes don't create a newer message, so without this the other
  // side kept showing the old text (or the deleted message) until it reopened the chat.
  const emitMessageChanged = (rooms, table, messageId, change) => {
    if (!fastify.io) return;
    for (const room of rooms) fastify.io.to(room).emit('chat:refresh', { type: change, table, messageId });
  };

  /* --- Chat Reactions --- */
  const ALLOWED_REACTION_TABLES = ['chat_messages', 'npc_messages', 'chat_group_messages'];

  fastify.post('/api/chat/messages/:id/reactions', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const messageId = Number(req.params.id);
      const { table, emoji } = req.body || {};
      const userId = req.user.id;

      if (!messageId || !table || !emoji || !ALLOWED_REACTION_TABLES.includes(table)) {
        return reply.status(400).send({ error: 'Invalid reaction parameters' });
      }

      // emoji is varchar(32). Without this a longer body is silently
      // truncated (or 500s under strict mode) instead of being rejected.
      if (typeof emoji !== 'string' || emoji.length > 32) {
        return reply.status(400).send({ error: 'Invalid reaction' });
      }

      // Disallow reactions on system messages
      const [[targetMsg]] = await pool.query(`SELECT type FROM ${table} WHERE id=? LIMIT 1`, [messageId]);
      if (targetMsg && targetMsg.type === 'system') {
        return reply.status(400).send({ error: 'Cannot react to system messages' });
      }

      // Toggle reaction: delete if exists, otherwise insert
      const [existing] = await pool.query(
        'SELECT id FROM chat_message_reactions WHERE message_table = ? AND message_id = ? AND user_id = ? AND emoji = ?',
        [table, messageId, userId, emoji]
      );

      if (existing.length > 0) {
        await pool.query('DELETE FROM chat_message_reactions WHERE id = ?', [existing[0].id]);
      } else {
        await pool.query(
          'INSERT INTO chat_message_reactions (message_table, message_id, user_id, emoji) VALUES (?, ?, ?, ?)',
          [table, messageId, userId, emoji]
        );
      }

      // Fetch updated aggregate reactions for this message with user details
      const [rows] = await pool.query(
        `SELECT r.emoji, r.user_id,
                CASE
                  WHEN r.message_table = 'npc_messages' AND u.role = 'admin' THEN COALESCE(n.name, 'Storyteller')
                  ELSE COALESCE(c.name, u.display_name, 'Unknown')
                END as user_name,
                CASE
                  WHEN r.message_table = 'npc_messages' AND u.role = 'admin' THEN n.clan
                  ELSE c.clan
                END as clan,
                CASE
                  WHEN r.message_table = 'npc_messages' AND u.role = 'admin' THEN n.id
                  ELSE NULL
                END as npc_id
         FROM chat_message_reactions r
         LEFT JOIN users u ON u.id = r.user_id
         LEFT JOIN characters c ON c.user_id = u.id
         LEFT JOIN npc_messages nm ON (r.message_table = 'npc_messages' AND nm.id = r.message_id)
         LEFT JOIN npcs n ON n.id = nm.npc_id
         WHERE r.message_table = ? AND r.message_id = ?
         ORDER BY r.id ASC`,
        [table, messageId]
      );

      const emojiMap = {};
      for (const r of rows) {
        if (!emojiMap[r.emoji]) {
          emojiMap[r.emoji] = {
            emoji: r.emoji,
            count: 0,
            users: [],
            reactors: []
          };
        }
        emojiMap[r.emoji].count += 1;
        emojiMap[r.emoji].users.push(Number(r.user_id));
        emojiMap[r.emoji].reactors.push({
          id: Number(r.user_id),
          name: r.user_name,
          clan: r.clan || null,
          npcId: r.npc_id ? Number(r.npc_id) : null
        });
      }

      const reactions = Object.values(emojiMap);

      if (fastify.io) {
        const payload = { table, messageId };
        let rooms = [];
        try {
          rooms = await messageRooms(table, messageId);
        } catch (e) { /* fall through to a best-effort broadcast below */ }

        if (rooms.length) {
          for (const room of rooms) {
            fastify.io.to(room).emit('chat:reactions', payload);
            fastify.io.to(room).emit('chat:refresh', { type: 'reaction', ...payload });
          }
        } else {
          fastify.io.emit('chat:reactions', payload);
          fastify.io.emit('chat:refresh', { type: 'reaction', ...payload });
        }
      }

      reply.send({ reactions });
    } catch (e) {
      log.err('Failed to toggle reaction', { error: e.message });
      reply.status(500).send({ error: 'Failed to toggle reaction' });
    }
  });

  fastify.post('/api/chat/messages/reactions/batch', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { table, ids } = req.body || {};

      if (!table || !ALLOWED_REACTION_TABLES.includes(table) || !Array.isArray(ids) || ids.length === 0) {
        return reply.send({ reactions: {} });
      }

      const cleanIds = ids.map(Number).filter(n => Number.isInteger(n) && n > 0).slice(0, 150);
      if (cleanIds.length === 0) {
        return reply.send({ reactions: {} });
      }

      const [rows] = await pool.query(
        `SELECT r.message_id, r.emoji, r.user_id,
                CASE
                  WHEN r.message_table = 'npc_messages' AND u.role = 'admin' THEN COALESCE(n.name, 'Storyteller')
                  ELSE COALESCE(c.name, u.display_name, 'Unknown')
                END as user_name,
                CASE
                  WHEN r.message_table = 'npc_messages' AND u.role = 'admin' THEN n.clan
                  ELSE c.clan
                END as clan,
                CASE
                  WHEN r.message_table = 'npc_messages' AND u.role = 'admin' THEN n.id
                  ELSE NULL
                END as npc_id
         FROM chat_message_reactions r
         LEFT JOIN users u ON u.id = r.user_id
         LEFT JOIN characters c ON c.user_id = u.id
         LEFT JOIN npc_messages nm ON (r.message_table = 'npc_messages' AND nm.id = r.message_id)
         LEFT JOIN npcs n ON n.id = nm.npc_id
         WHERE r.message_table = ? AND r.message_id IN (?)
         ORDER BY r.id ASC`,
        [table, cleanIds]
      );

      const map = {};
      for (const r of rows) {
        if (!map[r.message_id]) map[r.message_id] = {};
        if (!map[r.message_id][r.emoji]) {
          map[r.message_id][r.emoji] = {
            emoji: r.emoji,
            count: 0,
            users: [],
            reactors: []
          };
        }
        map[r.message_id][r.emoji].count += 1;
        map[r.message_id][r.emoji].users.push(Number(r.user_id));
        map[r.message_id][r.emoji].reactors.push({
          id: Number(r.user_id),
          name: r.user_name,
          clan: r.clan || null,
          npcId: r.npc_id ? Number(r.npc_id) : null
        });
      }

      const resultMap = {};
      for (const [msgId, eMap] of Object.entries(map)) {
        resultMap[msgId] = Object.values(eMap);
      }

      reply.send({ reactions: resultMap });
    } catch (e) {
      log.err('Failed to batch fetch reactions', { error: e.message });
      reply.status(500).send({ error: 'Failed to batch fetch reactions' });
    }
  });


  /* --- Chat Media --- */

  // POST /api/chat/upload
  // DUP: fastify.post('/api/chat/upload', { preHandler: [authRequired, async (req, reply) => { /* TODO: Implement multipart parsing here */ }] }, async (req, reply) => {
  // DUP:   if (!req.file) return reply.status(400).json({ error: 'No file uploaded' });
  // DUP:   try {
  // DUP:     const fileBlob = new Blob([req.file.buffer], { type: req.file.mimetype });
  // DUP:     const ext = req.file.originalname ? req.file.originalname.split('.').pop() : 'bin';
  // DUP:     const filename = 'chat_media_' + Date.now() + '.' + ext;
  // DUP: 
  // DUP:     const uploadRes = await imageClient.uploadImage(fileBlob, filename);
  // DUP:     if (!uploadRes.success) throw new Error('Upload failed: ' + uploadRes.error);
  // DUP: 
  // DUP:     const [ins] = await pool.query(
  // DUP:       'INSERT INTO chat_media (uploader_id, filename, mime, size, data_url, data) VALUES (?, ?, ?, ?, ?, ?)',
  // DUP:       [req.user.id, req.file.originalname || filename, req.file.mimetype, req.file.size, uploadRes.url, req.file.buffer]
  // DUP:     );
  // DUP: 
  // DUP:     reply.send({ id: ins.insertId, url: uploadRes.url, mime: req.file.mimetype });
  // DUP:   } catch (e) {
  // DUP:     log.err('Chat upload failed', { message: e.message });
  // DUP:     reply.status(500).json({ error: 'Upload failed' });
  // DUP:   }
  // DUP: });

  // GET /api/chat/media/:id/info
  fastify.get('/api/chat/media/:id/info', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const id = Number(req.params.id);
      if (!(await canAccessChatMedia(id, req.user))) return reply.status(404).send('Not found');

      const [rows] = await pool.query('SELECT data_url, data, mime FROM chat_media WHERE id=?', [id]);
      if (!rows.length) return reply.status(404).send('Not found');

      let url = rows[0].data_url;
      if (!url && typeof rows[0].data === 'string' && rows[0].data.startsWith('http')) {
        url = rows[0].data;
      }

      reply.send({ url: url || null, mime: rows[0].mime });
    } catch (e) {
      reply.status(500).json({ error: 'Error fetching media info' });
    }
  });

  // Backward compatibility or direct DB fetch: Redirect /api/chat/media/:id to external URL
  // DUP: fastify.get('/api/chat/media/:id', { preHandler: [authRequired] }, async (req, reply) => {
  // DUP:   try {
  // DUP:     const [rows] = await pool.query('SELECT data_url, data, mime FROM chat_media WHERE id=?', [req.params.id]);
  // DUP:     if (!rows.length) return reply.status(404).send('Not found');
  // DUP:     
  // DUP:     if (rows[0].data_url) return reply.redirect(302, rows[0].data_url);
  // DUP:     if (!rows[0].data) return reply.status(404).send('Not found');
  // DUP:     
  // DUP:     if (typeof rows[0].data === 'string' && rows[0].data.startsWith('http')) {
  // DUP:       return reply.redirect(302, rows[0].data);
  // DUP:     }
  // DUP:     
  // DUP:     if (rows[0].mime) reply.header('Content-Type', rows[0].mime);
  // DUP:     reply.send(rows[0].data);
  // DUP:   } catch (e) {
  // DUP:     reply.status(500).json({ error: 'Error fetching media' });
  // DUP:   }
  // DUP: });

  /* --- Edit & Delete Messages (4-Hour Window) --- */

  // Has the other side of this conversation sent anything since `msg` was
  // sent? If so, it's already been "answered" and can no longer be edited —
  // changing it after the fact would retroactively rewrite what the other
  // party actually replied to.
  async function hasBeenAnsweredSince(tableName, msg) {
    if (tableName === 'chat_messages') {
      const [rows] = await pool.query(
        `SELECT 1 FROM chat_messages
         WHERE created_at > ? AND sender_id = ? AND recipient_id = ?
         LIMIT 1`,
        [msg.created_at, msg.recipient_id, msg.sender_id]
      );
      return rows.length > 0;
    }
    if (tableName === 'chat_group_messages') {
      const [rows] = await pool.query(
        `SELECT 1 FROM chat_group_messages
         WHERE group_id = ? AND created_at > ? AND sender_id != ?
         LIMIT 1`,
        [msg.group_id, msg.created_at, msg.sender_id]
      );
      return rows.length > 0;
    }
    if (tableName === 'npc_messages') {
      const otherSide = msg.from_side === 'user' ? 'npc' : 'user';
      const [rows] = await pool.query(
        `SELECT 1 FROM npc_messages
         WHERE npc_id = ? AND user_id = ? AND created_at > ? AND from_side = ?
         LIMIT 1`,
        [msg.npc_id, msg.user_id, msg.created_at, otherSide]
      );
      return rows.length > 0;
    }
    return false;
  }

  // Message IDs are per-table and collide across DMs / groups / NPC threads,
  // so edit & delete must be told which table the message lives in.
  const EDITABLE_MESSAGE_TABLES = {
    chat_messages: { senderCol: 'sender_id' },
    chat_group_messages: { senderCol: 'sender_id' },
    // Players may only touch their own side of an NPC thread; admins may touch either side.
    npc_messages: { senderCol: 'user_id', playerCondition: "from_side = 'user'" }
  };
  const FOUR_HOURS = 4 * 60 * 60 * 1000;

  // Resolves the target message and enforces ownership / age rules. Returns { msg } or { error, status }.
  async function loadOwnMessage(req, table, verb) {
    const cfg = EDITABLE_MESSAGE_TABLES[table];
    if (!cfg) return { status: 400, error: 'Invalid message table.' };
    const msgId = Number(req.params.id);
    const isAdmin = checkIsAdmin(req.user);
    const extraWhere = !isAdmin && cfg.playerCondition ? ` AND ${cfg.playerCondition}` : '';
    const [rows] = await pool.query(`SELECT *, ${cfg.senderCol} as sender_id FROM ${table} WHERE id = ?${extraWhere}`, [msgId]);
    if (rows.length === 0) return { status: 404, error: 'Message not found.' };
    const msg = rows[0];
    if (msg.type === 'system') return { status: 403, error: 'Cannot modify system messages.' };
    if (isAdmin) return { msg, isAdmin };
    if (String(msg.sender_id) !== String(req.user.id)) {
      return { status: 403, error: `You can only ${verb} your own messages.` };
    }
    if (Date.now() - new Date(msg.created_at).getTime() > FOUR_HOURS) {
      return { status: 403, error: `You can only ${verb} a message within 4 hours of sending.` };
    }
    return { msg, isAdmin };
  }

  // Universal Edit Message Route
  fastify.put('/api/chat/messages/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { body, table } = req.body || {};
      if (!body || !body.trim()) return reply.status(400).json({ error: 'Message body cannot be empty.' });

      const { msg, isAdmin, status, error } = await loadOwnMessage(req, table, 'edit');
      if (error) return reply.status(status).json({ error });
      if (!isAdmin && await hasBeenAnsweredSince(table, msg)) {
        return reply.status(403).json({ error: 'This message has already been answered and can no longer be edited.' });
      }

      await pool.query(`UPDATE ${table} SET body = ?, edited = 1 WHERE id = ?`, [body.trim(), msg.id]);
      emitMessageChanged(await messageRooms(table, msg.id).catch(() => []), table, msg.id, 'edit');
      return reply.send({ ok: true, edited: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to edit message.' });
    }
  });

  // Universal Delete Message Route
  fastify.delete('/api/chat/messages/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const table = req.query.table;
      const { msg, status, error } = await loadOwnMessage(req, table, 'delete');
      if (error) return reply.status(status).json({ error });

      const rooms = await messageRooms(table, msg.id).catch(() => []);
      await pool.query(`DELETE FROM ${table} WHERE id = ?`, [msg.id]);
      emitMessageChanged(rooms, table, msg.id, 'delete');
      return reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to delete message.' });
    }
  });

  // Mark messages as delivered (Call this when the chat app loads new messages)
  fastify.post('/api/chat/delivered', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { sender_id } = req.body;
      if (!sender_id) return reply.status(400).json({ error: 'sender_id is required' });

      await pool.query(
        'UPDATE chat_messages SET delivered_at = NOW() WHERE sender_id = ? AND recipient_id = ? AND delivered_at IS NULL',
        [sender_id, req.user.id]
      );
      reply.send({ ok: true });
    } catch (e) {
      log.err('Failed to mark messages as delivered', { message: e.message });
      reply.status(500).json({ error: 'Failed' });
    }
  });

  // Mark messages from a specific user as read
  fastify.post('/api/chat/read', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { sender_id, npc_id, is_admin_reading_npc } = req.body;

      if (npc_id && is_admin_reading_npc) {
        // Admin is reading a player's messages to an NPC
        await pool.query(
          "UPDATE npc_messages SET read_at = NOW() WHERE npc_id = ? AND user_id = ? AND from_side = 'user' AND read_at IS NULL",
          [npc_id, sender_id]
        );
      } else if (npc_id) {
        // Player is reading an NPC's messages
        await pool.query(
          "UPDATE npc_messages SET read_at = NOW() WHERE npc_id = ? AND user_id = ? AND from_side = 'npc' AND read_at IS NULL",
          [npc_id, req.user.id]
        );
      } else if (sender_id) {
        // Normal Player to Player chat
        await pool.query(
          'UPDATE chat_messages SET read_at = NOW() WHERE sender_id = ? AND recipient_id = ? AND read_at IS NULL',
          [sender_id, req.user.id]
        );
      }

      if (fastify.io) {
        fastify.io.to(`user_${req.user.id}`).emit('chat:refresh', { type: 'read', sender_id, npc_id });
        if (sender_id) {
          fastify.io.to(`user_${sender_id}`).emit('chat:refresh', { type: 'read', reader_id: req.user.id });
        }
        if (npc_id && is_admin_reading_npc) {
          fastify.io.to('admin_chat').emit('chat:refresh', { type: 'read', npc_id, sender_id });
        }
      }

      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to mark as read' });
    }
  });

  /* --- Conversation details (SchreckNet side panel) ---
   * One resolver for the three chat kinds, so settings, search and media all
   * apply the same access rules as the history endpoints:
   *   user:  DM with another user (any signed-in user)
   *   group: members only
   *   npc:   a player's own thread; admins pass user_id for the player's side
   */
  async function resolveConversation(req, kind, rawId, rawUserId) {
    const me = Number(req.user.id);
    const id = Number(rawId);
    if (!id) return { error: 400 };
    if (kind === 'user') {
      return {
        kind: 'user', otherUserId: id, me,
        table: 'chat_messages', where: "((m.sender_id=? AND m.recipient_id=?) OR (m.sender_id=? AND m.recipient_id=?)) AND IFNULL(m.type, 'text') <> 'system'",
        params: [me, id, id, me], sender: 'm.sender_id, NULL AS from_side',
        key: convKey('user', me, id), rooms: [`user_${me}`, `user_${id}`],
      };
    }
    if (kind === 'group') {
      const [rows] = await pool.query('SELECT 1 FROM chat_group_members WHERE group_id=? AND user_id=?', [id, me]);
      if (!rows.length) return { error: 403 };
      return {
        kind: 'group', groupId: id,
        table: 'chat_group_messages', where: "m.group_id=? AND IFNULL(m.type, 'text') <> 'system'",
        params: [id], sender: 'm.sender_id, NULL AS from_side',
        key: convKey('group', id), rooms: [`group_${id}`],
      };
    }
    if (kind === 'npc') {
      const player = checkIsAdmin(req.user) ? Number(rawUserId) : me;
      if (!player) return { error: 400 };
      return {
        kind: 'npc', npcId: id, playerId: player,
        table: 'npc_messages', where: "m.npc_id=? AND m.user_id=? AND m.status <> 'queued' AND IFNULL(m.type, 'text') <> 'system'",
        params: [id, player], sender: 'NULL AS sender_id, m.from_side',
        key: convKey('npc', id, player), rooms: [`user_${player}`, 'admin_chat'],
      };
    }
    return { error: 400 };
  }

  const THEME_RE = /^[A-Za-z][A-Za-z _-]{0,31}$/;

  // Shared theme / conversation emoji: anyone in the conversation can change
  // it and everyone sees it. Sends a system message into the conversation
  // stating who made the change.
  fastify.put('/api/chat/settings', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { kind, id, user_id } = req.body || {};
      const conv = await resolveConversation(req, kind, id, user_id);
      if (conv.error) return reply.status(conv.error).json({ error: 'Conversation not found' });

      const current = await loadConvSettings(pool, conv.key);
      const next = { ...current };
      if ('theme' in req.body) {
        const theme = req.body.theme || null;
        if (theme !== null && !THEME_RE.test(theme)) return reply.status(400).json({ error: 'Invalid theme' });
        next.theme = theme;
      }
      if ('emoji' in req.body) {
        const emoji = req.body.emoji ? String(req.body.emoji).trim() : null;
        if (emoji !== null && (!emoji || emoji.length > 32)) return reply.status(400).json({ error: 'Invalid emoji' });
        next.emoji = emoji;
      }

      await pool.query(
        `INSERT INTO chat_conversation_settings (conv_key, theme, emoji, updated_by) VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE theme = VALUES(theme), emoji = VALUES(emoji), updated_by = VALUES(updated_by)`,
        [conv.key, next.theme, next.emoji, req.user.id]
      );

      const who = await nameFor(req.user.id);
      if (next.theme !== current.theme) {
        const themeText = next.theme ? `${who} changed the theme to ${next.theme}` : `${who} reset the theme`;
        await postConversationSystemMessage(conv, req.user, themeText);
      }
      if (next.emoji !== current.emoji) {
        const emojiText = next.emoji ? `${who} set the conversation emoji to ${next.emoji}` : `${who} reset the conversation emoji`;
        await postConversationSystemMessage(conv, req.user, emojiText);
      }
      if (fastify.io) for (const room of conv.rooms) fastify.io.to(room).emit('chat:refresh', { type: 'settings' });

      reply.send({ settings: next });
    } catch (e) {
      log.err('Failed to save chat settings', { message: e.message });
      reply.status(500).json({ error: 'Failed to save settings' });
    }
  });

  // Search one conversation's text. Server-side because the client only holds
  // the pages that have been scrolled into view.
  fastify.get('/api/chat/search', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { kind, id, user_id } = req.query;
      const q = String(req.query.q || '').trim();
      if (q.length < 2) return reply.send({ results: [] });
      const conv = await resolveConversation(req, kind, id, user_id);
      if (conv.error) return reply.status(conv.error).json({ error: 'Conversation not found' });

      const like = `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
      const [results] = await pool.query(
        `SELECT m.id, m.body, m.created_at, ${conv.sender}
         FROM ${conv.table} m
         WHERE ${conv.where} AND m.body LIKE ?
         ORDER BY m.created_at DESC, m.id DESC
         LIMIT 50`,
        [...conv.params, like]
      );
      reply.send({ results });
    } catch (e) {
      log.err('Chat search failed', { message: e.message });
      reply.status(500).json({ error: 'Search failed' });
    }
  });

  // Attachments shared in one conversation, newest first, 30 per page.
  fastify.get('/api/chat/media-list', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { kind, id, user_id, before } = req.query;
      const conv = await resolveConversation(req, kind, id, user_id);
      if (conv.error) return reply.status(conv.error).json({ error: 'Conversation not found' });

      const LIMIT = 30;
      const [media] = await pool.query(
        `SELECT m.id, m.attachment_id, m.created_at
         FROM ${conv.table} m
         WHERE ${conv.where} AND m.attachment_id IS NOT NULL${before ? ' AND m.id < ?' : ''}
         ORDER BY m.id DESC
         LIMIT ${LIMIT}`,
        before ? [...conv.params, Number(before)] : conv.params
      );
      reply.send({ media, has_more: media.length === LIMIT });
    } catch (e) {
      log.err('Chat media list failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to load media' });
    }
  });

  // ADMIN: Get all chat messages
  fastify.get('/api/admin/chat/all', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [messages] = await pool.query(
        `SELECT
                cm.id, cm.body, cm.created_at, cm.attachment_id, cm.edited,
                cm.read_at, cm.delivered_at,
                s.id as sender_id, s.display_name as sender_name,
                cs.name as sender_char_name, cs.clan as sender_clan,
                r.id as recipient_id, r.display_name as recipient_name,
                cr.name as recipient_char_name, cr.clan as recipient_clan
            FROM chat_messages cm
            JOIN users s ON cm.sender_id = s.id
            JOIN users r ON cm.recipient_id = r.id
            LEFT JOIN characters cs ON cs.user_id = s.id
            LEFT JOIN characters cr ON cr.user_id = r.id
            ORDER BY cm.created_at DESC`
      );
      log.adm('Admin fetched all chat messages', { count: messages.length });
      reply.send({ messages });
    } catch (e) {
      log.err('Failed to get all chat messages for admin', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch messages' });
    }
  });
};
