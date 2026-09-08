// routes/emails.js
//
// The in-fiction email client: Storyteller identities and threads on one side,
// the player inbox on the other.

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

      reply.send({ messages });
    } catch (e) {
      reply.status(500).json({ error: 'Failed' });
    }
  });

  // 6. Reply as the Identity (Admin View & Player Push)
  fastify.post('/api/admin/emails/reply', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { thread_id, body } = req.body;
      if (!body || !thread_id) return reply.status(400).json({ error: 'Missing body' });

      await pool.query(`INSERT INTO email_messages (thread_id, sender_type, body, is_read) VALUES (?, 'identity', ?, 0)`, [thread_id, body]);
      await pool.query(`UPDATE email_threads SET updated_at=NOW() WHERE id=?`, [thread_id]);

      // --- NEW: SEND PUSH TO PLAYER ---
      try {
        const [[thread]] = await pool.query('SELECT user_id, identity_id, subject FROM email_threads WHERE id=?', [thread_id]);
        const [[identity]] = await pool.query('SELECT display_name FROM email_identities WHERE id=?', [thread.identity_id]);

        const pushTitle = `📧 Reply from ${identity?.display_name || 'NPC'}`;
        const pushBody = `Re: ${thread.subject}`;

        await sendPushNotification(thread.user_id, pushTitle, pushBody).catch(() => { });
      } catch (e) { log.err('Email push to player failed', { error: e.message }); }
      // --------------------------------

      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to reply' });
    }
  });

  // --- USER ROUTES ---

  // 1. Player Inbox
  fastify.get('/api/emails/my-inbox', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [threads] = await pool.query(`
      SELECT t.id, t.subject, t.updated_at,
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
        ) ordered_msgs
        WHERE rn = 1
      ) snip ON snip.thread_id = t.id
      LEFT JOIN (
        SELECT thread_id, COUNT(*) as unread_count
        FROM email_messages
        WHERE sender_type = 'identity' AND is_read = 0
        GROUP BY thread_id
      ) um ON um.thread_id = t.id
      WHERE t.user_id = ?
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
      SELECT * FROM email_messages WHERE thread_id=? ORDER BY created_at ASC
    `, [req.params.id]);

      await pool.query(`UPDATE email_messages SET is_read=1 WHERE thread_id=? AND sender_type='identity'`, [req.params.id]);

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
          if (admin.id !== req.user.id) await sendPushNotification(admin.id, pushTitle, pushBody).catch(() => { });
        }
      } catch (e) { log.err('Email push to admin failed', { error: e.message }); }
      // --------------------------------

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
  fastify.get('/api/admin/emails/messages/all', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [messages] = await pool.query('SELECT * FROM email_messages');
      reply.send({ messages });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch email messages' });
    }
  });
};
