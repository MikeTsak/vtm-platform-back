// routes/chat.js
//
// SchreckNet chat: direct messages, group rooms, reactions, media, and the
// edit/delete window. Realtime fan-out goes through fastify.io.

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, moderateLimiter, uploadLimiter, sendPushNotification, sharp } = opts;

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
         WHERE user_id = ? AND from_side = 'npc' AND read_at IS NULL
         GROUP BY npc_id
       ) u ON u.npc_id = m.npc_id
       WHERE m.user_id = ? AND IFNULL(n.is_disabled, 0) = 0
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
  fastify.get('/api/chat/groups', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const userId = req.user.id;
      // Χρήση COALESCE για να μπαίνει η ημερομηνία δημιουργίας αν δεν υπάρχει μήνυμα.
      // Προσθήκη unread_count: Μετράει πόσα μηνύματα (που ΔΕΝ έστειλε ο ίδιος ο χρήστης) 
      // έχουν δημιουργηθεί μετά το last_read_at του συγκεκριμένου χρήστη στην ομάδα.
      // Ταξινόμηση ώστε οι ομάδες με αδιάβαστα να πηγαίνουν πάνω, και μετά να ταξινομούνται ανά παλαιότητα.
      const [rows] = await pool.query(`
      SELECT 
        g.id, g.name, g.created_by, g.created_at as group_created_at,
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
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to mark group as read' });
    }
  });

  // Create a new group
  fastify.post('/api/chat/groups', { preHandler: [authRequired, moderateLimiter] }, async (req, reply) => {
    const conn = await pool.getConnection();
    try {
      const { name, members = [] } = req.body; // members is array of user_ids
      if (!name || !members.length) {
        return reply.status(400).json({ error: 'Name and at least one other member required' });
      }

      await conn.beginTransaction();

      // 1. Create Group
      const [g] = await conn.query('INSERT INTO chat_groups (name, created_by) VALUES (?, ?)', [name.trim(), req.user.id]);
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
      const [messages] = await pool.query(`
      SELECT m.id, m.sender_id, m.body, m.created_at,
            m.attachment_id,
            u.display_name, c.name as char_name, c.clan
      FROM chat_group_messages m
      LEFT JOIN users u ON m.sender_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE m.group_id = ?
      ORDER BY m.created_at ASC
    `, [groupId]);


      reply.send({ messages });
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
      SELECT u.id, u.display_name, c.name as char_name 
      FROM chat_group_members cgm
      JOIN users u ON cgm.user_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE cgm.group_id = ?
      ORDER BY u.display_name ASC
    `, [groupId]);
      reply.send({ members });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to get members' });
    }
  });

  // Add members to an existing group (Creator/Admin only)
  fastify.post('/api/chat/groups/:id/members', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const groupId = Number(req.params.id);
      const { members } = req.body;
      if (!members || !members.length) return reply.status(400).json({ error: 'No members provided' });

      const [g] = await pool.query('SELECT created_by FROM chat_groups WHERE id=?', [groupId]);
      if (!g.length) return reply.status(404).json({ error: 'Group not found' });
      if (g[0].created_by !== req.user.id && req.user.role !== 'admin') return reply.status(403).json({ error: 'Not authorized' });

      const values = members.map(uid => [groupId, Number(uid)]);
      await pool.query('INSERT IGNORE INTO chat_group_members (group_id, user_id) VALUES ?', [values]);
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to add members' });
    }
  });

  // Remove a member from a group (Creator/Admin, or User leaving)
  fastify.delete('/api/chat/groups/:id/members/:userId', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const groupId = Number(req.params.id);
      const targetUserId = Number(req.params.userId);

      const [g] = await pool.query('SELECT created_by FROM chat_groups WHERE id=?', [groupId]);
      if (!g.length) return reply.status(404).json({ error: 'Group not found' });

      // Check if requester is Creator, Admin, OR the user trying to leave
      if (g[0].created_by !== req.user.id && req.user.role !== 'admin' && req.user.id !== targetUserId) {
        return reply.status(403).json({ error: 'Not authorized' });
      }

      if (g[0].created_by === targetUserId) return reply.status(400).json({ error: 'Cannot remove creator' });

      await pool.query('DELETE FROM chat_group_members WHERE group_id=? AND user_id=?', [groupId, targetUserId]);
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
      if (g[0].created_by !== req.user.id && req.user.role !== 'admin') return reply.status(403).json({ error: 'Only the creator can delete this group' });

      // ON DELETE CASCADE will automatically wipe the chat_group_members and chat_group_messages
      await pool.query('DELETE FROM chat_groups WHERE id=?', [groupId]);
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to delete group' });
    }
  });

  // Send a message to a group
  fastify.post('/api/chat/groups/:id/messages', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const groupId = Number(req.params.id);
      const { body, attachment_id } = req.body;

      // Verify membership ... (keep existing check)
      const [m] = await pool.query('SELECT 1 FROM chat_group_members WHERE group_id=? AND user_id=?', [groupId, req.user.id]);
      if (!m.length) return reply.status(403).json({ error: 'Not a member' });

      if (!attachment_id && (!body || !body.trim())) return reply.status(400).json({ error: 'Content required' });

      const [r] = await pool.query('INSERT INTO chat_group_messages (group_id, sender_id, body, attachment_id) VALUES (?,?,?,?)',
        [groupId, req.user.id, body ? body.trim() : '', attachment_id || null]);

      const [[message]] = await pool.query(`
      SELECT m.id, m.sender_id, m.body, m.created_at, m.attachment_id,
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
        const [[groupInfo]] = await pool.query('SELECT name FROM chat_groups WHERE id=?', [groupId]);
        const groupName = groupInfo?.name || 'Group Chat';
        const senderName = message.char_name || message.display_name || 'Someone';

        // 2. Φτιάχνουμε το περιεχόμενο της ειδοποίησης
        const notifTitle = `💬 ${groupName} (${senderName})`;
        const notifBody = message.attachment_id ? '📷 Image Attachment' : message.body;

        // 3. Βρίσκουμε όλα τα μέλη εκτός από τον αποστολέα
        [members] = await pool.query('SELECT user_id FROM chat_group_members WHERE group_id=? AND user_id!=?', [groupId, req.user.id]);

        // 4. Στέλνουμε push notification στο κάθε μέλος
        for (const member of members) {
          await sendPushNotification(member.user_id, notifTitle, notifBody, { url: '/schrecknet' }, 'chat').catch(() => { });
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
            m.attachment_id,
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

      const users = rows.map(r => ({
        ...r,
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
      const isAdmin = req.user.role === 'admin' || req.user.permission_level === 'admin';
      let query, params;

      if (isAdmin) {
        // Admins see if ANY player has sent an unread message to the NPC
        query = `SELECT n.id, n.name, n.clan, n.image_url,
             m.last_message_at,
             COALESCE(m.unread_count, 0) as unread_count
      FROM npcs n
      LEFT JOIN (
        SELECT npc_id,
               MAX(created_at) as last_message_at,
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
             m.last_message_at,
             COALESCE(m.unread_count, 0) as unread_count
      FROM npcs n
      LEFT JOIN (
        SELECT npc_id,
               MAX(created_at) as last_message_at,
               COUNT(CASE WHEN from_side = 'npc' AND read_at IS NULL THEN 1 END) as unread_count
        FROM npc_messages
        WHERE user_id = ?
        GROUP BY npc_id
      ) m ON m.npc_id = n.id
      WHERE IFNULL(n.is_disabled, 0) = 0
      ORDER BY unread_count DESC, last_message_at DESC, n.name ASC`;
        params = [myId];
      }
      const [rows] = await pool.query(query, params);
      reply.send({ npcs: rows });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to list NPCs' });
    }
  });


  // Get message history with another user
  fastify.get('/api/chat/history/:otherUserId', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const otherUserId = Number(req.params.otherUserId);
      const myId = req.user.id;

      const [messages] = await pool.query(
        `SELECT * FROM (
         SELECT cm.id, cm.sender_id, cm.recipient_id, cm.body, cm.created_at,
                cm.read_at, cm.delivered_at,
                cm.attachment_id,
                u_sender.display_name as sender_name
         FROM chat_messages cm
         JOIN users u_sender ON cm.sender_id = u_sender.id
         WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
         ORDER BY created_at DESC
         LIMIT 500
       ) sub
       ORDER BY created_at ASC`,
        [myId, otherUserId, otherUserId, myId]
      );

      reply.send({ messages });
    } catch (e) {
      log.err('Failed to get chat history', { message: e.message });
      reply.status(500).json({ error: 'Failed to get history' });
    }
  });


  // Send a message
  fastify.post('/api/chat/messages', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      // Added attachment_id to destructuring
      const { recipient_id, body, attachment_id } = req.body;

      // Allow empty body ONLY if there is an attachment
      if (!recipient_id || (!attachment_id && (!body || !body.trim()))) {
        return reply.status(400).send({ error: 'Recipient and content required' });
      }

      const [r] = await pool.query(
        'INSERT INTO chat_messages (sender_id, recipient_id, body, attachment_id) VALUES (?, ?, ?, ?)',
        [req.user.id, recipient_id, body ? body.trim() : '', attachment_id || null]
      );

      // Fetch back with attachment info
      const [[message]] = await pool.query(
        `SELECT cm.id, cm.sender_id, cm.recipient_id, cm.body, cm.created_at, cm.attachment_id,
              u_sender.display_name as sender_name
       FROM chat_messages cm
       JOIN users u_sender ON cm.sender_id = u_sender.id
       WHERE cm.id = ?`,
        [r.insertId]
      );

      sendPushNotification(
        recipient_id,
        message.sender_name,
        message.attachment_id ? '📷 Image Attachment' : message.body
      );

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

      // Fetch updated aggregate reactions for this message
      const [rows] = await pool.query(
        `SELECT emoji, COUNT(*) as count, GROUP_CONCAT(user_id) as users
       FROM chat_message_reactions
       WHERE message_table = ? AND message_id = ?
       GROUP BY emoji`,
        [table, messageId]
      );

      const reactions = rows.map(r => ({
        emoji: r.emoji,
        count: Number(r.count),
        users: r.users ? r.users.split(',').map(Number) : []
      }));

      if (fastify.io) {
        fastify.io.emit('chat:reactions', { table, messageId });
        fastify.io.emit('chat:refresh', { type: 'reaction', table, messageId });
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
        `SELECT message_id, emoji, COUNT(*) as count, GROUP_CONCAT(user_id) as users
       FROM chat_message_reactions
       WHERE message_table = ? AND message_id IN (?)
       GROUP BY message_id, emoji`,
        [table, cleanIds]
      );

      const map = {};
      for (const r of rows) {
        if (!map[r.message_id]) map[r.message_id] = [];
        map[r.message_id].push({
          emoji: r.emoji,
          count: Number(r.count),
          users: r.users ? r.users.split(',').map(Number) : []
        });
      }

      reply.send({ reactions: map });
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
      const [rows] = await pool.query('SELECT data_url, data, mime FROM chat_media WHERE id=?', [req.params.id]);
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

  // Universal Edit Message Route
  fastify.put('/api/chat/messages/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const msgId = Number(req.params.id);
      const { body } = req.body;
      const userId = req.user.id;
      const isAdmin = req.user.role === 'admin' || req.user.permission_level === 'admin';

      if (!body || !body.trim()) return reply.status(400).json({ error: 'Message body cannot be empty.' });

      const FOUR_HOURS = 4 * 60 * 60 * 1000;

      const tables = [
        { name: 'chat_messages', senderCol: 'sender_id' },
        { name: 'chat_group_messages', senderCol: 'sender_id' },
        { name: 'npc_messages', senderCol: 'user_id', extraCondition: "from_side = 'user'" }
      ];

      let found = false;

      for (const table of tables) {
        const extraWhere = table.extraCondition ? ` AND ${table.extraCondition}` : '';
        const [rows] = await pool.query(`SELECT id, ${table.senderCol} as sender_id, created_at FROM ${table.name} WHERE id = ?${extraWhere}`, [msgId]);

        if (rows.length > 0) {
          const msg = rows[0];
          found = true;

          // FIX: Cast both to Strings to prevent Strict Equality ( !== ) Type Bugs
          if (String(msg.sender_id) !== String(userId) && !isAdmin) {
            return reply.status(403).json({ error: 'You can only edit your own messages.' });
          }
          if (Date.now() - new Date(msg.created_at).getTime() > FOUR_HOURS && !isAdmin) {
            return reply.status(403).json({ error: 'You can only edit a message within 4 hours of sending.' });
          }

          await pool.query(`UPDATE ${table.name} SET body = ?, edited = 1 WHERE id = ?`, [body.trim(), msgId]);
          return reply.send({ ok: true, edited: true });
        }
      }

      if (isAdmin && !found) {
        const [npcRows] = await pool.query(`SELECT id FROM npc_messages WHERE id = ? AND from_side = 'npc'`, [msgId]);
        if (npcRows.length > 0) {
          await pool.query(`UPDATE npc_messages SET body = ?, edited = 1 WHERE id = ?`, [body.trim(), msgId]);
          return reply.send({ ok: true, edited: true });
        }
      }

      if (!found) return reply.status(404).json({ error: 'Message not found.' });

    } catch (e) {
      reply.status(500).json({ error: 'Failed to edit message.' });
    }
  });

  // Universal Delete Message Route
  fastify.delete('/api/chat/messages/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const msgId = Number(req.params.id);
      const userId = req.user.id;
      const isAdmin = req.user.role === 'admin' || req.user.permission_level === 'admin';
      const FOUR_HOURS = 4 * 60 * 60 * 1000;

      const tables = [
        { name: 'chat_messages', senderCol: 'sender_id' },
        { name: 'chat_group_messages', senderCol: 'sender_id' },
        { name: 'npc_messages', senderCol: 'user_id', extraCondition: "from_side = 'user'" }
      ];

      let found = false;

      for (const table of tables) {
        const extraWhere = table.extraCondition ? ` AND ${table.extraCondition}` : '';
        const [rows] = await pool.query(`SELECT id, ${table.senderCol} as sender_id, created_at FROM ${table.name} WHERE id = ?${extraWhere}`, [msgId]);

        if (rows.length > 0) {
          const msg = rows[0];
          found = true;

          // FIX: Cast both to Strings to prevent Strict Equality ( !== ) Type Bugs
          if (String(msg.sender_id) !== String(userId) && !isAdmin) {
            return reply.status(403).json({ error: 'You can only delete your own messages.' });
          }
          if (Date.now() - new Date(msg.created_at).getTime() > FOUR_HOURS && !isAdmin) {
            return reply.status(403).json({ error: 'You can only delete a message within 4 hours of sending.' });
          }

          await pool.query(`DELETE FROM ${table.name} WHERE id = ?`, [msgId]);
          return reply.send({ ok: true });
        }
      }

      if (isAdmin && !found) {
        const [npcRows] = await pool.query(`SELECT id FROM npc_messages WHERE id = ? AND from_side = 'npc'`, [msgId]);
        if (npcRows.length > 0) {
          await pool.query(`DELETE FROM npc_messages WHERE id = ?`, [msgId]);
          return reply.send({ ok: true });
        }
      }

      if (!found) return reply.status(404).json({ error: 'Message not found.' });

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
      }

      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to mark as read' });
    }
  });

  // ADMIN: Get all chat messages
  fastify.get('/api/admin/chat/all', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [messages] = await pool.query(
        `SELECT
                cm.id, cm.body, cm.created_at,
                s.id as sender_id, s.display_name as sender_name,
                r.id as recipient_id, r.display_name as recipient_name
            FROM chat_messages cm
            JOIN users s ON cm.sender_id = s.id
            JOIN users r ON cm.recipient_id = r.id
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
