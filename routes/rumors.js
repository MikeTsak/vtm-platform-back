// routes/rumors.js
//
// Rumours: short in-fiction posts with optional broadcast to Discord/ntfy.
const axios = require('axios');
const { getSetting } = require('../utils/settings');
const { sanitizeRichText } = require('../utils/sanitize');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, broadcastNtfyAlert } = opts;

  // ================= RUMORS API =================

  // GET /api/rumors - Fetch all rumors
  fastify.get('/api/rumors', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
      SELECT r.*, u.display_name as author_real_name,
             c.name as char_name, c.camarilla_titles as char_titles, c.image_url as char_image
      FROM rumors r
      LEFT JOIN users u ON r.author_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      ORDER BY r.created_at DESC
      LIMIT 100
    `);
      // Send back with theme 'RUMOR' so frontend can identify it easily if needed,
      // though the frontend now explicitly queries /rumors
      reply.send({ items: rows.map(r => ({ ...r, theme: 'RUMOR', type: 'news' })) });
    } catch (e) {
      log.err('Fetch rumors failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to load rumors' });
    }
  });

  // GET /api/rumors/:id
  fastify.get('/api/rumors/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT * FROM rumors WHERE id = ?', [req.params.id]);
      if (!rows.length) return reply.status(404).json({ error: 'Rumor not found' });
      reply.send(rows[0]);
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch rumor' });
    }
  });

  // POST /api/rumors - Create Rumor
  fastify.post('/api/rumors', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { title, body, media_url, discord_prefix } = req.body;

      if (req.user.role !== 'admin' && req.user.role !== 'courtuser') {
        const [chars] = await pool.query('SELECT id, sheet FROM characters WHERE user_id = ?', [req.user.id]);
        let isActive = false;
        if (chars.length > 0) {
          try {
            const sheetData = typeof chars[0].sheet === 'string' ? JSON.parse(chars[0].sheet) : chars[0].sheet;
            if (sheetData && sheetData.is_active) isActive = true;
          } catch (e) { }
        }
        if (!isActive) {
          return reply.status(403).json({ error: 'You must have an active character to post rumors.' });
        }
      }

      if (!title || !body) return reply.status(400).json({ error: 'Title and Body are required' });

      const safeBody = sanitizeRichText(body); // strip active markup before persisting (XSS)

      const [insertResult] = await pool.query(
        `INSERT INTO rumors (author_id, title, body, media_url) VALUES (?, ?, ?, ?)`,
        [req.user.id, title, safeBody, media_url || null]
      );

      broadcastNtfyAlert(`A new rumor has hit the streets:\n\n> *${title}*`, { title: 'New Rumor', tags: 'shushing_face', priority: 'default' });

      // --- DISCORD BROADCAST (REST API) ---
      const discordEnabled = await getSetting('discord_enabled', 'true') === 'true';
      if (discordEnabled && process.env.DISCORD_BOT_TOKEN) {
        try {
          const channelId = await getSetting('discord_channel_id', null);
          if (channelId) {
            const appBase = (process.env.APP_BASE_URL || req.headers.origin || '').replace(/\/$/, '') || 'http://localhost:3000';
            const rumorLink = `${appBase}/rumors`;

            const prefix = discord_prefix || "🤫 A new whisper echoes in the night...";

            let plainBody = safeBody.replace(/<[^>]*>?/gm, '').trim();
            if (plainBody.length > 1500) {
              plainBody = plainBody.substring(0, 1500) + '...';
            }

            const broadcast = `# ${prefix}\n\n**${title}**\n\n_${plainBody}_\n\n**Investigate the Rumors:**\n${rumorLink}`;

            await axios.post(`https://discord.com/api/v10/channels/${channelId}/messages`, {
              content: broadcast
            }, {
              headers: {
                'Authorization': `Bot ${process.env.DISCORD_BOT_TOKEN}`,
                'Content-Type': 'application/json'
              }
            });
          }
        } catch (discordErr) {
          log.err('Discord rumor broadcast failed', { error: discordErr.response?.data ? JSON.stringify(discordErr.response.data) : discordErr.message });
        }
      }
      // -----------------------------------

      log.ok('Rumor created', { user_id: req.user.id, title });
      reply.send({ ok: true });
    } catch (e) {
      log.err('Create rumor failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to post' });
    }
  });

  // POST /api/rumors/:id/broadcast (Admin Only)
  fastify.post('/api/rumors/:id/broadcast', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT * FROM rumors WHERE id = ?', [req.params.id]);
      if (rows.length === 0) return reply.status(404).send({ error: 'Rumor not found' });

      const rumor = rows[0];
      const { title, body } = rumor;

      const discordEnabled = await getSetting('discord_enabled', 'true') === 'true';
      const tokenPresent = !!process.env.DISCORD_BOT_TOKEN;

      if (!discordEnabled || !tokenPresent) {
        return reply.status(400).send({ error: 'Discord broadcasting is disabled or bot token is missing.' });
      }

      const channelId = await getSetting('discord_channel_id', null);
      if (!channelId) {
        return reply.status(400).send({ error: 'Discord channel not configured.' });
      }

      const appBase = (process.env.APP_BASE_URL || req.headers.origin || '').replace(/\/$/, '') || 'http://localhost:3000';
      const rumorLink = `${appBase}/rumors`;

      const prefix = req.body?.discord_prefix || "🤫 A new whisper echoes in the night...";

      let plainBody = body.replace(/<[^>]*>?/gm, '').trim();
      if (plainBody.length > 1500) {
        plainBody = plainBody.substring(0, 1500) + '...';
      }

      const broadcast = `# ${prefix}\n\n**${title}**\n\n_${plainBody}_\n\n**Investigate the Rumors:**\n${rumorLink}`;

      await axios.post(`https://discord.com/api/v10/channels/${channelId}/messages`, {
        content: broadcast
      }, {
        headers: {
          'Authorization': `Bot ${process.env.DISCORD_BOT_TOKEN}`,
          'Content-Type': 'application/json'
        }
      });

      log.ok('Rumor rebroadcast triggered', { user_id: req.user.id, rumor_id: req.params.id });
      reply.send({ success: true });
    } catch (e) {
      log.err('Rebroadcast failed', { error: e.response?.data || e.message });
      reply.status(500).send({ error: 'Failed to rebroadcast rumor' });
    }
  });

  // DELETE /api/rumors/:id (Admin Only)
  fastify.delete('/api/rumors/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      await pool.query('DELETE FROM rumors WHERE id=?', [req.params.id]);
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Delete failed' });
    }
  });
};
