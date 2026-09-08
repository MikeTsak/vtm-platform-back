// routes/news.js
//
// News and announcements: public feed, sitemap, authoring, per-theme
// permissions, media, and broadcast.
const axios = require('axios');
const { getSetting } = require('../utils/settings');
const { sanitizeRichText } = require('../utils/sanitize');
const { xmlEscape, getAuthorSignature } = require('../services/news');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, imageClient } = opts;

  // GET /api/news/public - Fetch only news, no rumors (No auth required)
  fastify.get('/api/news/public', async (req, reply) => {
    try {
      const [rows] = await pool.query(`
      SELECT n.*, u.display_name as author_real_name,
             c.name as char_name, c.camarilla_titles as char_titles, c.image_url as char_image
      FROM news_entries n
      LEFT JOIN users u ON n.author_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE n.type = 'news' AND n.theme != 'RUMOR' AND n.is_private = 0
      ORDER BY n.created_at DESC
      LIMIT 100
    `);
      reply.send({ items: rows });
    } catch (e) {
      log.err('Fetch public news failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to load public news' });
    }
  });

  // GET /api/news/public/:id - Fetch single news article (No auth required)
  fastify.get('/api/news/public/:id', async (req, reply) => {
    try {
      const [rows] = await pool.query(`
      SELECT n.*, u.display_name as author_real_name,
             c.name as char_name, c.camarilla_titles as char_titles, c.image_url as char_image
      FROM news_entries n
      LEFT JOIN users u ON n.author_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE n.id = ? AND n.type IN ('news', 'announcement') AND n.theme != 'RUMOR'
    `, [req.params.id]);

      if (rows.length === 0) {
        return reply.status(404).json({ error: 'Article not found' });
      }
      reply.send({ item: rows[0] });
    } catch (e) {
      log.err('Fetch public article failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to load article' });
    }
  });

  fastify.get('/api/sitemap-news.xml', async (req, reply) => {
    try {
      const [rows] = await pool.query(`
      SELECT id, created_at
      FROM news_entries
      WHERE type = 'news' AND theme != 'RUMOR' AND is_private = 0
      ORDER BY created_at DESC
      LIMIT 5000
    `);

      const urls = rows.map((row) => {
        const loc = `https://portal.attlarp.gr/news/${row.id}`;
        const lastmod = new Date(row.created_at).toISOString().slice(0, 10);
        return `  <url>\n    <loc>${xmlEscape(loc)}</loc>\n    <lastmod>${lastmod}</lastmod>\n    <changefreq>monthly</changefreq>\n    <priority>0.6</priority>\n  </url>`;
      }).join('\n');

      const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`;

      reply.header('Content-Type', 'application/xml; charset=utf-8');
      reply.send(xml);
    } catch (e) {
      log.err('Failed to generate news sitemap', { message: e.message });
      reply.status(500).send('Failed to generate sitemap');
    }
  });

  // GET /api/news (Public/Auth) - Fetch all items
  fastify.get('/api/news', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      // Join with users to get the real name for Announcements
      const [rows] = await pool.query(`
      SELECT n.*, u.display_name as author_real_name,
             c.name as char_name, c.camarilla_titles as char_titles, c.image_url as char_image
      FROM news_entries n
      LEFT JOIN users u ON n.author_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE n.is_private = 0
      ORDER BY n.created_at DESC
      LIMIT 100
    `);
      reply.send({ items: rows });
    } catch (e) {
      log.err('Fetch news failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to load news' });
    }
  });

  // GET /api/news/recent (For Dashboard) - Lightweight headlines only
  fastify.get('/api/news/recent', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const limit = 5;
      // Only fetch necessary fields, not the full body
      const [rows] = await pool.query(`
      SELECT id, type, title, theme, created_at
      FROM news_entries
      WHERE is_private = 0
      ORDER BY created_at DESC
      LIMIT ?
    `, [limit]);
      reply.send({ news: rows });
    } catch (e) {
      log.err('Fetch recent news headlines failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to load headlines' });
    }
  });


  // POST /api/news/upload (Admin/Court) - Upload media
  fastify.post('/api/news/upload', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      // Check permissions: Admin or Court or has any news permission
      if (req.user.role !== 'admin' && req.user.role !== 'courtuser') {
        const [perms] = await pool.query('SELECT id FROM user_news_permissions WHERE user_id=? LIMIT 1', [req.user.id]);
        if (perms.length === 0) {
          return reply.status(403).send({ error: 'Forbidden' });
        }
      }

      const fileData = await req.file();
      if (!fileData) return reply.status(400).send({ error: 'File required' });

      const originalname = fileData.filename || 'upload';
      const mimetype = fileData.mimetype || 'application/octet-stream';
      const buffer = await fileData.toBuffer();
      const size = buffer.length;

      const ext = originalname ? originalname.split('.').pop() : 'bin';
      const filenameToUpload = 'news_media_' + Date.now() + '.' + ext;
      const result = await imageClient.uploadImage(buffer, filenameToUpload);
      if (!result || !result.success) throw new Error((result && result.error) || 'CDN upload failed');
      const resultUrl = result.url;

      // CDN-only — no BLOB fallback.
      const [ins] = await pool.query(
        'INSERT INTO news_media (filename, mime, size, data_url, data) VALUES (?,?,?,?,NULL)',
        [originalname, mimetype, size, resultUrl]
      );

      reply.send({ url: resultUrl });
    } catch (e) {
      log.err('News upload failed', { message: e.message });
      reply.status(500).send({ error: `Upload failed: ${e.message}` });
    }
  });

  // GET /api/news/media/:id - Stream media (WITH VIDEO SUPPORT)
  fastify.get('/api/news/media/:id', async (req, reply) => {
    try {
      const id = Number(req.params.id);
      const [rows] = await pool.query('SELECT data_url, mime, size, data FROM news_media WHERE id=? LIMIT 1', [id]);
      if (!rows.length) return reply.status(404).send('Not found');

      const { data_url, mime, size, data } = rows[0];

      if (data_url) return reply.redirect(302, data_url);
      if (!data) return reply.status(404).send('Not found');

      if (typeof data === 'string' && data.startsWith('http')) {
        return reply.redirect(302, data);
      }

      // Handle HTML5 Video Range Requests (Crucial for iOS/Safari & scrubbing)
      const range = req.headers.range;
      if (range && mime.startsWith('video/')) {
        const parts = range.replace(/bytes=/, "").split("-");
        const partialstart = parts[0];
        const partialend = parts[1];

        const start = parseInt(partialstart, 10);
        const end = partialend ? parseInt(partialend, 10) : size - 1;
        const chunksize = (end - start) + 1;

        reply.raw.writeHead(206, {
          'Content-Range': `bytes ${start}-${end}/${size}`,
          'Accept-Ranges': 'bytes',
          'Content-Length': chunksize,
          'Content-Type': mime,
        });
        // Send only the requested slice of the buffer
        reply.send(data.subarray(start, end + 1));
      } else {
        // Standard image/file serving
        reply.header('Content-Type', mime || 'application/octet-stream');
        reply.header('Content-Length', size);
        reply.header('Cache-Control', 'public, max-age=86400'); // Cache for 1 day
        reply.send(data);
      }
    } catch (e) {
      reply.status(404).send('Not found');
    }
  });

  // --- NEWS PERMISSIONS ---

  // User fetching their allowed themes
  fastify.get('/api/news/my-themes', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      if (req.user.role === 'admin') {
        return reply.send({ all: true });
      }
      const [rows] = await pool.query(`
      SELECT theme 
      FROM user_news_permissions 
      WHERE user_id = ?
    `, [req.user.id]);
      return reply.send(rows.map(r => r.theme));
    } catch (e) {
      log.err('Error fetching user themes', e);
      return reply.status(500).send({ error: 'Server error' });
    }
  });

  // Admin: Get permissions
  fastify.get('/api/admin/news-permissions', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
      SELECT p.id, p.user_id, p.theme, u.display_name as username
      FROM user_news_permissions p
      JOIN users u ON p.user_id = u.id
      ORDER BY p.created_at DESC
    `);
      return reply.send(rows);
    } catch (e) {
      return reply.status(500).send({ error: 'Server error' });
    }
  });

  // Admin: Grant permission
  fastify.post('/api/admin/news-permissions', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { user_id, theme } = req.body;
      await pool.query(
        'INSERT IGNORE INTO user_news_permissions (user_id, theme) VALUES (?, ?)',
        [user_id, theme]
      );
      return reply.send({ success: true });
    } catch (e) {
      return reply.status(500).send({ error: 'Server error' });
    }
  });

  // Admin: Revoke permission
  fastify.delete('/api/admin/news-permissions/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      await pool.query('DELETE FROM user_news_permissions WHERE id=?', [req.params.id]);
      return reply.send({ success: true });
    } catch (e) {
      return reply.status(500).send({ error: 'Server error' });
    }
  });

  // POST /api/news - Create Entry
  fastify.post('/api/news', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { type, title, subtitle, body, theme, journalist_name, media_url, is_private } = req.body;

      // --- PERMISSION CHECK ---
      if (type === 'news') {
        if (req.user.role !== 'admin') {
          // Check if user has permission for the requested theme
          const [perms] = await pool.query('SELECT id FROM user_news_permissions WHERE user_id=? AND theme=?', [req.user.id, theme]);
          if (perms.length === 0) {
            return reply.status(403).send({ error: 'You do not have permission to post under this theme' });
          }
        }
      } else if (type === 'announcement') {
        if (req.user.role !== 'admin' && req.user.role !== 'courtuser') {
          return reply.status(403).send({ error: 'Only Court/Admin can post Announcements' });
        }
      } else {
        return reply.status(400).send({ error: 'Invalid type' });
      }

      if (!title || !body) return reply.status(400).send({ error: 'Title and Body are required' });

      const safeBody = sanitizeRichText(body); // strip active markup before persisting (XSS)

      const [insertResult] = await pool.query(
        `INSERT INTO news_entries
      (author_id, type, title, subtitle, body, theme, journalist_name, media_url, is_private)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          req.user.id,
          type,
          title,
          subtitle || null,
          safeBody, // Stored as sanitised HTML
          theme || 'Neutral',
          journalist_name || null,
          media_url || null,
          is_private ? 1 : 0
        ]
      );

      // --- DISCORD BROADCAST (REST API) ---
      const discordEnabled = await getSetting('discord_enabled', 'true') === 'true';
      const notifyPrems = await getSetting('discord_notify_news', 'true') === 'true';
      const tokenPresent = !!process.env.DISCORD_BOT_TOKEN;

      log.info('Discord News Broadcast Check', { discordEnabled, notifyPrems, tokenPresent });

      if (discordEnabled && notifyPrems && tokenPresent && !is_private) {
        try {
          const channelId = await getSetting('discord_channel_id', null);
          if (channelId) {
            const appBase = (process.env.APP_BASE_URL || req.headers.origin || '').replace(/\/$/, '') || 'http://localhost:3000';
            const isAnnouncement = type === 'announcement';
            const articleLink = isAnnouncement
              ? `${appBase}/court/announcements/${insertResult.insertId}`
              : `${appBase}/news/${insertResult.insertId}`;

            const defaultPrefix = isAnnouncement
              ? `📜 **New Court Announcement!** 📜`
              : `🔥 **Hot news from the mortal world!** 🔥`;

            const prefix = req.body?.discord_prefix || defaultPrefix;
            let broadcast = `# ${prefix}\n\n**${title}**\n`;
            if (subtitle) broadcast += `*${subtitle}*\n`;

            if (!isAnnouncement) {
              const outletNames = {
                'ERT': 'ERT News', 'SKAI': 'SKAI.gr', 'ALPHA': 'Alpha News',
                'MEGA': 'Mega Gegonota', 'KATHIMERINI': 'Kathimerini',
                'GOSSIP': 'Gossip-tv', 'OPENTV': 'Open TV'
              };
              const sourceName = outletNames[theme] || theme || 'Unknown';
              broadcast += `\n**Source:** ${sourceName}`;
              broadcast += `\n**Read the full article:**\n${articleLink}`;
            } else {
              const sig = await getAuthorSignature(req.user.id, pool);
              broadcast += `\n*${sig}*`;
              broadcast += `\n\n**Read the full announcement here:**\n${articleLink}`;
            }

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
          log.err('Discord news broadcast failed', { error: discordErr.response?.data ? JSON.stringify(discordErr.response.data) : discordErr.message });
        }
      }
      // -----------------------------------

      log.ok('News entry created', { user_id: req.user.id, type, title });
      reply.send({ ok: true });
    } catch (e) {
      log.err('Create news failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to post' });
    }
  });

  // POST /api/news/:id/broadcast (Admin Only)
  fastify.post('/api/news/:id/broadcast', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT * FROM news_entries WHERE id = ?', [req.params.id]);
      if (rows.length === 0) return reply.status(404).send({ error: 'Entry not found' });

      const entry = rows[0];
      const { type, title, subtitle, theme } = entry;

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
      const isAnnouncement = type === 'announcement';
      const articleLink = isAnnouncement
        ? `${appBase}/court/announcements/${entry.id}`
        : `${appBase}/news/${entry.id}`;

      const defaultPrefix = isAnnouncement
        ? `📜 **New Court Announcement!** 📜`
        : `🔥 **Hot news from the mortal world!** 🔥`;

      const prefix = req.body?.discord_prefix || defaultPrefix;
      let broadcast = `# ${prefix}\n\n**${title}**\n`;
      if (subtitle) broadcast += `*${subtitle}*\n`;

      if (!isAnnouncement) {
        const outletNames = {
          'ERT': 'ERT News', 'SKAI': 'SKAI.gr', 'ALPHA': 'Alpha News',
          'MEGA': 'Mega Gegonota', 'KATHIMERINI': 'Kathimerini',
          'GOSSIP': 'Gossip-tv', 'OPENTV': 'Open TV'
        };
        const sourceName = outletNames[theme] || theme || 'Unknown';
        broadcast += `\n**Source:** ${sourceName}`;
        broadcast += `\n**Read the full article:**\n${articleLink}`;
      } else {
        const sig = await getAuthorSignature(entry.author_id, pool);
        broadcast += `\n*${sig}*`;
        broadcast += `\n\n**Read the full announcement here:**\n${articleLink}`;
      }

      await axios.post(`https://discord.com/api/v10/channels/${channelId}/messages`, {
        content: broadcast
      }, {
        headers: {
          'Authorization': `Bot ${process.env.DISCORD_BOT_TOKEN}`,
          'Content-Type': 'application/json'
        }
      });

      log.ok('News/Announcement rebroadcast triggered', { user_id: req.user.id, entry_id: req.params.id });
      reply.send({ success: true });
    } catch (e) {
      log.err('Rebroadcast failed', { error: e.response?.data || e.message });
      reply.status(500).send({ error: 'Failed to rebroadcast' });
    }
  });

  // PATCH /api/news/:id/publish - Publish a private news entry (Admin only)
  fastify.patch('/api/news/:id/publish', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT * FROM news_entries WHERE id = ?', [req.params.id]);
      if (rows.length === 0) return reply.status(404).send({ error: 'Not found' });

      const entry = rows[0];
      if (entry.is_private === 0) {
        return reply.send({ success: true, message: 'Already published' });
      }

      await pool.query('UPDATE news_entries SET is_private = 0 WHERE id = ?', [req.params.id]);

      // We can reuse the same broadcast logic as the POST /api/news/:id/broadcast or just trigger it via fetch.
      // Or we can just let the admin click the "Broadcast" button from the UI after publishing.
      // Wait, the user said "i sould be able to push it to public form there to ap;piar in official new s and the discord bot."
      // Let's trigger the broadcast endpoint internally.
      try {
        await axios.post(`http://127.0.0.1:${process.env.PORT || 3001}/api/news/${req.params.id}/broadcast`, {}, {
          headers: {
            'Cookie': req.headers.cookie, // Pass the cookie for auth
          }
        });
      } catch (err) {
        log.err('Failed to auto-broadcast published news', { error: err.message });
      }

      reply.send({ success: true, message: 'Published successfully' });
    } catch (e) {
      log.err('Publish news failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to publish news' });
    }
  });

  // GET /api/admin/news - Fetch all news including private (Admin only)
  fastify.get('/api/admin/news', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
      SELECT n.*, u.display_name as author_real_name,
             c.name as char_name, c.camarilla_titles as char_titles, c.image_url as char_image
      FROM news_entries n
      LEFT JOIN users u ON n.author_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE n.type = 'news' OR n.type = 'announcement'
      ORDER BY n.created_at DESC
      LIMIT 200
    `);
      reply.send({ items: rows });
    } catch (e) {
      log.err('Fetch admin news failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to load admin news' });
    }
  });

  // DELETE /api/news/:id (Admin Only)
  fastify.delete('/api/news/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      await pool.query('DELETE FROM news_entries WHERE id=?', [req.params.id]);
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Delete failed' });
    }
  });
};
