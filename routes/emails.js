// routes/emails.js
//
// The in-fiction email client: Storyteller identities and threads on one side,
// the player inbox on the other.

const { isAdmin: checkIsAdmin } = require('../services/guards');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, sendPushNotification } = opts;

  /* -------------------- SIMULATED EMAIL SYSTEM (HUMAN COMMS) -------------------- */

  // --- ADMIN ROUTES ---

  // 1. List all "Allowed" Email Identities
  fastify.get('/api/admin/emails/identities', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`SELECT * FROM email_identities ORDER BY email_address ASC`);
      reply.send({ identities: rows });
    } catch (e) {
      log.err('Admin list identities failed', { message: e.message });
      reply.status(500).json({ error: 'Failed' });
    }
  });

  // 2. Create a new "Human" Email Identity (Standalone)
  fastify.post('/api/admin/emails/identities', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { email_address, display_name } = req.body;
      if (!display_name || !email_address) return reply.status(400).json({ error: 'Missing fields' });

      const email = email_address.trim().toLowerCase();
      if (!email.includes('@')) return reply.status(400).json({ error: 'Invalid email format' });

      await pool.query(`
      INSERT INTO email_identities (email_address, display_name)
      VALUES (?, ?)
    `, [email, display_name]);

      log.adm('Created human email identity', { admin: req.user.id, email });
      reply.send({ ok: true });
    } catch (e) {
      if (e.code === 'ER_DUP_ENTRY') return reply.status(409).json({ error: 'Email already exists' });
      log.err('Create identity failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to create identity' });
    }
  });

  // 3. Delete an identity
  fastify.delete('/api/admin/emails/identities/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      await pool.query('DELETE FROM email_identities WHERE id=?', [req.params.id]);
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed' });
    }
  });

  // 4. Admin Inbox (View all threads sent to any identity)
  fastify.get('/api/admin/emails/threads', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [threads] = await pool.query(`
      SELECT t.id, t.subject, t.updated_at,
             t.user_id, t.identity_id,
             u.display_name as user_name, c.name as char_name,
             i.email_address, i.display_name as identity_name,
             COALESCE(um.unread_count, 0) as unread_count
      FROM email_threads t
      JOIN users u ON u.id = t.user_id
      LEFT JOIN characters c ON c.user_id = u.id
      JOIN email_identities i ON i.id = t.identity_id
      LEFT JOIN (
        SELECT thread_id, COUNT(*) as unread_count
        FROM email_messages
        WHERE sender_type = 'user' AND is_read = 0
        GROUP BY thread_id
      ) um ON um.thread_id = t.id
      ORDER BY t.updated_at DESC
    `);
      reply.send({ threads });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch threads' });
    }
  });

  // 5. Get Messages (Admin View)
  fastify.get('/api/admin/emails/threads/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [messages] = await pool.query(`
      SELECT m.* FROM email_messages m
      WHERE m.thread_id = ?
      ORDER BY m.created_at ASC
    `, [req.params.id]);

      // Mark user messages as read
      await pool.query(`UPDATE email_messages SET is_read=1 WHERE thread_id=? AND sender_type='user'`, [req.params.id]);
      if (fastify.io) fastify.io.to(`user_${req.user.id}`).emit('emails:refresh', { type: 'read' });

      reply.send({ messages });
    } catch (e) {
      reply.status(500).json({ error: 'Failed' });
    }
  });

  // 6. Reply as the Identity (Admin View & Player Push)
  fastify.post('/api/admin/emails/reply', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { thread_id, body, queue } = req.body;
      if (!body || !thread_id) return reply.status(400).json({ error: 'Missing body' });

      const status = queue ? 'queued' : 'sent';
      await pool.query(`INSERT INTO email_messages (thread_id, sender_type, body, is_read, status) VALUES (?, 'identity', ?, 0, ?)`, [thread_id, body, status]);

      if (status === 'sent') {
        await pool.query(`UPDATE email_threads SET updated_at=NOW() WHERE id=?`, [thread_id]);

        // --- NEW: SEND PUSH TO PLAYER ---
        try {
          const [[thread]] = await pool.query('SELECT user_id, identity_id, subject FROM email_threads WHERE id=?', [thread_id]);
          if (fastify.io) fastify.io.to(`user_${thread.user_id}`).emit('emails:refresh', { type: 'new' });
          const [[identity]] = await pool.query('SELECT display_name FROM email_identities WHERE id=?', [thread.identity_id]);

          const pushTitle = `📧 Reply from ${identity?.display_name || 'NPC'}`;
          const pushBody = `Re: ${thread.subject}`;

          await sendPushNotification(thread.user_id, pushTitle, pushBody, { url: '/surfaceweb', icon: `/api/identities/${thread.identity_id}/avatar` }, 'chat').catch(() => { });
        } catch (e) { log.err('Email push to player failed', { error: e.message }); }
        // --------------------------------
      }

      reply.send({ ok: true, status });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to reply' });
    }
  });

  // --- USER ROUTES ---

  // Unread count for the Surface Web badge in the nav. Same semantics as the
  // inbox lists: players count sent identity mail, admins count player mail.
  fastify.get('/api/emails/unread-count', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const isAdmin = checkIsAdmin(req.user);
      const [[row]] = isAdmin
        ? await pool.query(`SELECT COUNT(*) AS count FROM email_messages WHERE sender_type = 'user' AND is_read = 0`)
        : await pool.query(`
            SELECT COUNT(*) AS count FROM email_messages m
            JOIN email_threads t ON t.id = m.thread_id
            WHERE t.user_id = ? AND m.sender_type = 'identity' AND m.is_read = 0 AND m.status = 'sent'
          `, [req.user.id]);
      reply.send({ count: Number(row.count) });
    } catch (e) {
      log.err('Failed to count unread emails', { message: e.message });
      reply.status(500).json({ error: 'Failed to count unread' });
    }
  });

  // 1. Player Inbox
  fastify.get('/api/emails/my-inbox', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [threads] = await pool.query(`
      SELECT t.id, t.subject, t.updated_at,
             t.identity_id,
             i.email_address as from_email, i.display_name as from_name,
             snip.body as snippet,
             COALESCE(um.unread_count, 0) as unread_count
      FROM email_threads t
      JOIN email_identities i ON i.id = t.identity_id
      LEFT JOIN (
        SELECT thread_id, body
        FROM (
          SELECT thread_id, body,
                 ROW_NUMBER() OVER (PARTITION BY thread_id ORDER BY created_at DESC) as rn
          FROM email_messages
          WHERE status = 'sent'
        ) ordered_msgs
        WHERE rn = 1
      ) snip ON snip.thread_id = t.id
      LEFT JOIN (
        SELECT thread_id, COUNT(*) as unread_count
        FROM email_messages
        WHERE sender_type = 'identity' AND is_read = 0 AND status = 'sent'
        GROUP BY thread_id
      ) um ON um.thread_id = t.id
      WHERE t.user_id = ?
        AND EXISTS (SELECT 1 FROM email_messages em WHERE em.thread_id = t.id AND em.status = 'sent')
      ORDER BY t.updated_at DESC
    `, [req.user.id]);
      reply.send({ threads });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to load inbox' });
    }
  });

  // 2. Read Thread
  fastify.get('/api/emails/thread/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [check] = await pool.query('SELECT 1 FROM email_threads WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
      if (!check.length) return reply.status(403).json({ error: 'Forbidden' });

      const [messages] = await pool.query(`
      SELECT * FROM email_messages WHERE thread_id=? AND status='sent' ORDER BY created_at ASC
    `, [req.params.id]);

      await pool.query(`UPDATE email_messages SET is_read=1 WHERE thread_id=? AND sender_type='identity' AND status='sent'`, [req.params.id]);
      if (fastify.io) fastify.io.to(`user_${req.user.id}`).emit('emails:refresh', { type: 'read' });

      reply.send({ messages });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to load email' });
    }
  });

  // 3. Send Email (Validation Logic & Admin Push)
  fastify.post('/api/emails/send', { preHandler: [authRequired] }, async (req, reply) => {
    const conn = await pool.getConnection();
    try {
      const { to_email, subject, body, thread_id } = req.body;
      let finalThreadId = thread_id;
      let identityId = null;
      let identityName = 'NPC';

      if (thread_id) {
        // REPLY to existing thread
        const [check] = await conn.query('SELECT identity_id FROM email_threads WHERE id=? AND user_id=?', [thread_id, req.user.id]);
        if (!check.length) return reply.status(403).json({ error: 'Thread not found' });
        identityId = check[0].identity_id;

        await conn.query(`INSERT INTO email_messages (thread_id, sender_type, body, is_read) VALUES (?, 'user', ?, 0)`, [thread_id, body]);
        await conn.query(`UPDATE email_threads SET updated_at=NOW() WHERE id=?`, [thread_id]);
      } else {
        // NEW THREAD
        if (!to_email || !subject || !body) return reply.status(400).json({ error: 'Missing fields' });
        const emailLower = to_email.trim().toLowerCase();
        const [identity] = await conn.query('SELECT id, display_name FROM email_identities WHERE email_address = ?', [emailLower]);

        if (identity.length === 0) return reply.status(404).json({ error: 'Delivery Status Notification (Failure): Address not found.' });
        identityId = identity[0].id;
        identityName = identity[0].display_name;

        await conn.beginTransaction();
        const [t] = await conn.query(`INSERT INTO email_threads (user_id, identity_id, subject) VALUES (?, ?, ?)`, [req.user.id, identityId, subject]);
        finalThreadId = t.insertId;
        await conn.query(`INSERT INTO email_messages (thread_id, sender_type, body, is_read) VALUES (?, 'user', ?, 0)`, [finalThreadId, body]);
        await conn.commit();
      }

      // --- NEW: SEND PUSH TO ADMINS ---
      try {
        const [[idRow]] = await pool.query('SELECT display_name FROM email_identities WHERE id=?', [identityId]);
        const [[player]] = await pool.query('SELECT display_name FROM users WHERE id=?', [req.user.id]);
        const [admins] = await pool.query("SELECT id FROM users WHERE role = 'admin'");

        const pushTitle = `📧 Email to ${idRow?.display_name || identityName}`;
        const pushBody = `From ${player?.display_name}: ${subject || 'New Reply'}`;

        for (const admin of admins) {
          if (admin.id !== req.user.id) await sendPushNotification(admin.id, pushTitle, pushBody, { url: '/surfaceweb', icon: `/api/users/${req.user.id}/avatar` }, 'chat').catch(() => { });
        }
      } catch (e) { log.err('Email push to admin failed', { error: e.message }); }
      // --------------------------------

      if (fastify.io) fastify.io.to('admin_chat').emit('emails:refresh', { type: 'new' });
      reply.send({ ok: true, thread_id: finalThreadId });
    } catch (e) {
      await conn.rollback();
      log.err('Email send failed', { message: e.message });
      reply.status(500).json({ error: 'Send failed' });
    } finally {
      conn.release();
    }
  });

  // ADMIN: Get all email messages (for stats)
  // Excludes still-queued drafts — a message that hasn't actually been sent
  // yet shouldn't count toward sent-message stats.
  fastify.get('/api/admin/emails/messages/all', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [messages] = await pool.query(`SELECT * FROM email_messages WHERE status = 'sent'`);
      reply.send({ messages });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch email messages' });
    }
  });

  // 7. Admin Direct Message — create identity on-the-fly and open a DM thread with a player
  fastify.post('/api/admin/emails/dm', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const conn = await pool.getConnection();
    try {
      const { email_address, display_name, user_id, subject, body, queue } = req.body;
      if (!email_address || !display_name || !user_id || !subject || !body) {
        return reply.status(400).json({ error: 'Missing required fields' });
      }
      const status = queue ? 'queued' : 'sent';

      const email = email_address.trim().toLowerCase();
      if (!email.includes('@')) return reply.status(400).json({ error: 'Invalid email format' });

      // Verify the target player exists
      const [[targetUser]] = await conn.query('SELECT id, display_name FROM users WHERE id=?', [user_id]);
      if (!targetUser) return reply.status(404).json({ error: 'Target player not found' });

      await conn.beginTransaction();

      // Upsert the email identity — create it if it doesn't exist yet
      await conn.query(`
        INSERT INTO email_identities (email_address, display_name)
        VALUES (?, ?)
        ON DUPLICATE KEY UPDATE display_name = VALUES(display_name)
      `, [email, display_name]);

      const [[identity]] = await conn.query('SELECT id FROM email_identities WHERE email_address=?', [email]);

      // Create thread linked to the target player
      const [t] = await conn.query(
        `INSERT INTO email_threads (user_id, identity_id, subject) VALUES (?, ?, ?)`,
        [user_id, identity.id, subject]
      );
      const threadId = t.insertId;

      // Insert first message as the identity (admin speaking as NPC)
      await conn.query(
        `INSERT INTO email_messages (thread_id, sender_type, body, is_read, status) VALUES (?, 'identity', ?, 0, ?)`,
        [threadId, body, status]
      );

      await conn.commit();

      if (status === 'sent') {
        // Push notification to the target player
        try {
          const pushTitle = `📧 New message from ${display_name}`;
          const pushBody = `Re: ${subject}`;
          await sendPushNotification(user_id, pushTitle, pushBody, { url: '/surfaceweb', icon: `/api/identities/${identity.id}/avatar` }, 'chat').catch(() => {});
        } catch (e) { log.err('Admin DM push failed', { error: e.message }); }
      }

      log.adm('Admin created DM thread', { admin: req.user.id, target_user: user_id, identity: email, status });
      reply.send({ ok: true, thread_id: threadId, identity_id: identity.id, status });
    } catch (e) {
      await conn.rollback();
      log.err('Admin DM failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to create DM' });
    } finally {
      conn.release();
    }
  });

  // 8. Admin: list all currently-queued NPC-identity emails, across every thread
  fastify.get('/api/admin/emails/queued', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
        SELECT m.id, m.thread_id, m.body, m.created_at,
               t.subject, t.user_id, u.display_name AS user_display_name, c.name AS char_name,
               i.display_name AS identity_name, i.email_address
        FROM email_messages m
        JOIN email_threads t ON t.id = m.thread_id
        JOIN users u ON u.id = t.user_id
        LEFT JOIN characters c ON c.user_id = u.id
        JOIN email_identities i ON i.id = t.identity_id
        WHERE m.status = 'queued'
        ORDER BY m.created_at ASC
      `);
      reply.send({ queued: rows });
    } catch (e) {
      log.err('Admin fetch queued emails failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch queued emails' });
    }
  });

  // 9. Admin: cancel a queued email before it sends
  fastify.delete('/api/admin/emails/queued/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [[msg]] = await pool.query(`SELECT thread_id FROM email_messages WHERE id=? AND status='queued'`, [req.params.id]);
      if (!msg) return reply.status(404).json({ error: 'Queued message not found' });

      await pool.query(`DELETE FROM email_messages WHERE id=?`, [req.params.id]);

      // If that was a brand-new DM thread's only message, don't leave an
      // empty thread behind in the admin's inbox.
      const [[remaining]] = await pool.query(`SELECT COUNT(*) AS c FROM email_messages WHERE thread_id=?`, [msg.thread_id]);
      if (remaining.c === 0) {
        await pool.query(`DELETE FROM email_threads WHERE id=?`, [msg.thread_id]);
      }

      reply.send({ ok: true });
    } catch (e) {
      log.err('Admin cancel queued email failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to cancel queued email' });
    }
  });
};
