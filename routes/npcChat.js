// routes/npcChat.js
//
// Player <-> NPC direct messages, and the Storyteller side that answers them.
const axios = require('axios');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, requireCourt, sendPushNotification } = opts;

  fastify.get('/api/admin/chat/npc-conversations/:npcId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const npcId = Number(req.params.npcId);
    try {
      const [rows] = await pool.query(`
      SELECT 
        u.id AS user_id, 
        u.display_name, 
        c.name AS char_name, 
        MAX(m.created_at) AS last_message_at,
        COUNT(CASE WHEN m.from_side = 'user' AND m.read_at IS NULL THEN 1 END) as unread_count
      FROM npc_messages m
      JOIN users u ON m.user_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id -- FIXED: Changed from u.character_id = c.id
      WHERE m.npc_id = ?
      GROUP BY u.id, u.display_name, c.name
      ORDER BY unread_count DESC, last_message_at DESC
    `, [npcId]);
      reply.send({ conversations: rows });
    } catch (e) {
      // Pro-tip: Log the actual error here temporarily if you ever get another 500!
      // console.error("NPC Convo Error:", e);
      reply.status(500).json({ error: 'Failed to fetch NPC conversations' });
    }
  });

  /** Admin: Get chat history between a specific NPC and a specific User */
  fastify.get('/api/admin/chat/npc-history/:npcId/:userId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const npcId = Number(req.params.npcId);
    const userId = Number(req.params.userId);

    try {
      // FIX: Changed to npc_messages
      const [messages] = await pool.query(
        `SELECT id, body, from_side, created_at, attachment_id
        FROM npc_messages
        WHERE npc_id = ? AND user_id = ?
        ORDER BY created_at ASC`,
        [npcId, userId]
      );


      reply.send({ messages });
    } catch (e) {
      log.err('Admin fetch NPC chat history failed', { message: e.message, stack: e.stack });
      reply.status(500).json({ error: 'Failed to fetch chat history' });
    }
  });

  /** Admin: Send a message from an NPC to a User */
  fastify.post('/api/admin/chat/reply-as-npc/:npcId/:userId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const npcId = Number(req.params.npcId);
    const userId = Number(req.params.userId);
  const { body } = req.body;

    if (!body || body.trim().length === 0) {
      return reply.status(400).json({ error: 'Message body is required' });
    }

    try {
      // Basic validation (NPC/User existence, assuming tables/data models)
      const [npcRows] = await pool.query('SELECT id FROM npcs WHERE id=?', [npcId]);
      if (npcRows.length === 0) {
        return reply.status(404).json({ error: 'NPC not found' });
      }
      const [userRows] = await pool.query('SELECT id FROM users WHERE id=?', [userId]);
      if (userRows.length === 0) {
        return reply.status(404).json({ error: 'Target user not found' });
      }

      // Insert message into the NPC chat table, sent from the 'npc' side
      await pool.query(
        'INSERT INTO npc_messages (user_id, npc_id, body, from_side) VALUES (?, ?, ?, ?)',
        [userId, npcId, body, 'npc']
      );

      log.adm('Admin replied as NPC', { admin_id: req.user.id, npc_id: npcId, to_user_id: userId });

      if (fastify.io) {
        fastify.io.to(`user_${userId}`).emit('chat:refresh', { type: 'npc', partnerId: Number(npcId) });
        fastify.io.to('admin_chat').emit('chat:refresh', { type: 'npc', partnerId: Number(npcId), userId: Number(userId) });
      }

      reply.send({ ok: true, message: 'Message sent as NPC' });
    } catch (e) {
      log.err('Admin reply as NPC failed', { message: e.message, stack: e.stack });
      reply.status(500).json({ error: 'Failed to send message as NPC' });
    }
  });

  // Player: get my conversation with an NPC
  fastify.get('/api/chat/npc-history/:npcId', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const npcId = Number(req.params.npcId);
      const userId = req.user.id;

      const [rows] = await pool.query(
        `SELECT id, npc_id, user_id, from_side, body, created_at, attachment_id
        FROM npc_messages
        WHERE npc_id=? AND user_id=?
        ORDER BY created_at ASC`,
        [npcId, userId]
      );

      reply.send({ messages: rows });
    } catch (e) {
      log.err('Failed to get NPC chat history', { message: e.message });
      reply.status(500).json({ error: 'Failed to get history' });
    }
  });

  // Player: send message to an NPC
  fastify.post('/api/chat/npc/messages', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const userId = req.user.id;
      const { npc_id, body, attachment_id } = req.body || {};

      if (!npc_id || (!attachment_id && (!body || !body.trim()))) {
        return reply.status(400).json({ error: 'NPC and content required' });
      }

      const [npcRows] = await pool.query('SELECT is_disabled FROM npcs WHERE id=?', [Number(npc_id)]);
      if (!npcRows.length || npcRows[0].is_disabled) {
        return reply.status(403).json({ error: 'Cannot send message to this NPC at this time.' });
      }

      const [r] = await pool.query(
        'INSERT INTO npc_messages (npc_id, user_id, from_side, body, attachment_id) VALUES (?,?,?,?,?)',
        [Number(npc_id), userId, 'user', body ? body.trim() : '', attachment_id || null]
      );

      // FIX: Define the message object so notifications and the response don't crash
      const message = {
        id: r.insertId,
        npc_id: Number(npc_id),
        user_id: userId,
        from_side: 'user',
        body: body ? body.trim() : '',
        attachment_id: attachment_id || null,
        created_at: new Date()
      };

      // --- NEW: PUSH NOTIFICATIONS FOR ALL ADMINS ---
      try {
        // 1. Get NPC name and Player name for the notification title
        const [[npcInfo]] = await pool.query('SELECT name FROM npcs WHERE id=?', [npc_id]);
        const [[playerInfo]] = await pool.query('SELECT display_name FROM users WHERE id=?', [userId]);
        const [[charInfo]] = await pool.query('SELECT name FROM characters WHERE user_id=?', [userId]);

        const npcName = npcInfo?.name || 'NPC';
        const playerName = charInfo?.name || playerInfo?.display_name || 'Player';

        const notifTitle = `💬 ${npcName} (from ${playerName})`;
        const notifBody = message.attachment_id ? '📷 Image Attachment' : message.body;

        // 2. Find all admins and their ntfy topic + subscriptions
        const [admins] = await pool.query("SELECT id, ntfy_topic, ntfy_subscribed_npcs FROM users WHERE role = 'admin'");

        // 3. Send a push to each admin
        for (const admin of admins) {
          // Prevent sending a push to the admin if the admin is the one testing/playing as a user
          if (admin.id !== userId) {
            // Web Push
            await sendPushNotification(admin.id, notifTitle, notifBody).catch(() => { });

            // Ntfy Push (Only if subscribed)
            if (admin.ntfy_topic && admin.ntfy_subscribed_npcs) {
              let prefs = [];
              try { prefs = typeof admin.ntfy_subscribed_npcs === 'string' ? JSON.parse(admin.ntfy_subscribed_npcs) : admin.ntfy_subscribed_npcs; } catch (e) { }
              if (Array.isArray(prefs) && prefs.includes(Number(npc_id))) {
                axios.post(`https://ntfy.sh/${admin.ntfy_topic}`, notifBody, {
                  headers: { 'Title': notifTitle, 'Tags': 'speech_balloon' }
                }).catch(() => { });
              }
            }
          }
        }
      } catch (pushErr) {
        log.err('Failed to notify admins of NPC message', { error: pushErr.message });
      }
      // ----------------------------------------------

      if (fastify.io) {
        fastify.io.to('admin_chat').emit('chat:refresh', { type: 'npc', partnerId: Number(npc_id), userId });
        fastify.io.to(`user_${userId}`).emit('chat:refresh', { type: 'npc', partnerId: Number(npc_id) });
      }

      reply.status(201).json({ message });
    } catch (e) {
      log.err('NPC send failed', { message: e.message });
      reply.status(500).json({ error: 'Failed' });
    }
  });
  // --- Admin: reply as NPC to a specific player ---
  fastify.get('/api/admin/chat/npc/history', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const npcId = Number(req.query.npc_id);
      const userId = Number(req.query.user_id);
      if (!npcId || !userId) return reply.status(400).json({ error: 'npc_id and user_id are required' });

      const [rows] = await pool.query(
        `SELECT id, npc_id, user_id, from_side, body, created_at, attachment_id
        FROM npc_messages
        WHERE npc_id=? AND user_id=?
        ORDER BY created_at ASC`,
        [npcId, userId]
      );

      reply.send({ messages: rows });
    } catch (e) {
      log.err('Admin: NPC history failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to get history' });
    }
  });

  fastify.post('/api/admin/chat/summarize', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    // AI generation has been disabled entirely for memory optimization
    reply.status(501).json({ error: 'AI features have been disabled to optimize server memory.' });
  });

  fastify.post('/api/admin/chat/npc/messages', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { npc_id, user_id, body, attachment_id } = req.body || {};
      if (!npc_id || !user_id || (!attachment_id && (!body || !body.trim()))) {
        return reply.status(400).json({ error: 'Missing fields' });
      }

      const [r] = await pool.query(
        'INSERT INTO npc_messages (npc_id, user_id, from_side, body, attachment_id) VALUES (?,?,?,?,?)',
        [Number(npc_id), Number(user_id), 'npc', body ? body.trim() : '', attachment_id || null]
      );

      // FIX: Define the message object so notifications and the response don't crash
      const message = {
        id: r.insertId,
        npc_id: Number(npc_id),
        user_id: Number(user_id),
        from_side: 'npc',
        body: body ? body.trim() : '',
        attachment_id: attachment_id || null,
        created_at: new Date()
      };

      // --- NEW: PUSH NOTIFICATION TO PLAYER ---
      try {
        // Find the NPC name so the player knows who is replying
        const [[npcInfo]] = await pool.query('SELECT name FROM npcs WHERE id=?', [npc_id]);
        const npcName = npcInfo?.name || 'NPC';
        const notifBody = message.attachment_id ? '📷 Image Attachment' : message.body;

        // Send push directly to the player
        await sendPushNotification(user_id, npcName, notifBody).catch(() => { });
      } catch (pushErr) {
        log.err('Failed to notify player of NPC reply', { error: pushErr.message });
      }
      // ----------------------------------------

      if (fastify.io) {
        fastify.io.to(`user_${user_id}`).emit('chat:refresh', { type: 'npc', partnerId: Number(npc_id) });
        fastify.io.to('admin_chat').emit('chat:refresh', { type: 'npc', partnerId: Number(npc_id), userId: Number(user_id) });
      }

      reply.status(201).json({ message });
    } catch (e) {
      reply.status(500).json({ error: 'Failed' });
    }
  });

  // Admin: fetch ALL NPC chat messages (flat list)
  fastify.get('/api/admin/chat/npc/all', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
      SELECT id, npc_id, user_id, from_side, body, created_at
      FROM npc_messages
      ORDER BY created_at ASC
    `);

      reply.send({ messages: rows });
    } catch (e) {
      log.err('Admin fetch ALL NPC messages failed', { message: e.message, stack: e.stack });
      reply.status(500).json({ error: 'Failed to fetch NPC messages' });
    }
  });

  // Court/Admin: fetch ALL NPC messages
  fastify.get('/api/court/chat/npc/all', { preHandler: [authRequired, requireCourt] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
      SELECT id, npc_id, user_id, from_side, body, created_at
      FROM npc_messages
      ORDER BY created_at ASC
    `);
      reply.send({ messages: rows });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch NPC messages' });
    }
  });
};
