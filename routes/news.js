// routes/news.js
//
// News and announcements: public feed, sitemap, authoring, per-theme
// permissions, media, and broadcast.
const sharp = require('sharp');
const { getSetting } = require('../utils/settings');
const { sanitizeRichText } = require('../utils/sanitize');
const { xmlEscape, getAuthorSignature, isVideoUrl, resolveMediaUrl, redactNewsAuthor, broadcastNewsEntry, NEWS_AUTHOR_COLUMNS, NEWS_AUTHOR_JOINS } = require('../services/news');

const guards = require('../services/guards');
module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, optionalAuth, requireAdmin, imageClient } = opts;

  // GET /api/news/public - Fetch only news, no rumors (No auth required)
  // Optional: ?theme=SKAI to filter by outlet
  fastify.get('/api/news/public', async (req, reply) => {
    try {
      const { theme } = req.query;
      let sql = `
      SELECT n.*
      FROM news_entries n
      WHERE n.type = 'news' AND n.theme != 'RUMOR' AND n.is_private = 0`;
      const params = [];
      if (theme && typeof theme === 'string' && theme.length <= 30) {
        sql += ` AND n.theme = ?`;
        params.push(theme.toUpperCase());
      }
      sql += `
      ORDER BY n.created_at DESC
      LIMIT 100`;
      const [rows] = await pool.query(sql, params);
      reply.send({ items: rows.map(redactNewsAuthor) });
    } catch (e) {
      log.err('Fetch public news failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load public news' });
    }
  });

  // GET /api/news/public/:id - Fetch single news article (No auth required)
  fastify.get('/api/news/public/:id', async (req, reply) => {
    try {
      const [rows] = await pool.query(`
      SELECT n.*, ${NEWS_AUTHOR_COLUMNS}
      FROM news_entries n ${NEWS_AUTHOR_JOINS}
      WHERE n.id = ? AND n.type IN ('news', 'announcement') AND n.theme != 'RUMOR'
    `, [req.params.id]);

      if (rows.length === 0) {
        return reply.status(404).send({ error: 'Article not found' });
      }

      // Public page, but remember logged-in readers. Admins (and admins
      // impersonating a player) are skipped so previewing doesn't pollute it.
      await optionalAuth(req);
      const isAdminUser = Boolean(req.user && guards.isAdmin(req.user) && !req.user.imp);

      // Track public views for non-admin visits (including anonymous visitors and players)
      const ua = req.headers['user-agent'] || '';
      const isBot = /bot|spider|crawl|slurp|headless|mediapartners/i.test(ua);
      if (!isAdminUser && !isBot) {
        pool.query(
          'UPDATE news_entries SET views = COALESCE(views, 0) + 1 WHERE id = ?',
          [rows[0].id]
        ).catch((e) => log.err('Increment news views failed', { message: e.message }));
      }

      if (req.user && !guards.isAdmin(req.user) && !req.user.imp) {
        pool.query(
          `INSERT INTO news_reads (news_id, user_id) VALUES (?, ?)
           ON DUPLICATE KEY UPDATE open_count = open_count + 1, last_read_at = NOW()`,
          [rows[0].id, req.user.id]
        ).catch((e) => log.err('Record news read failed', { message: e.message }));
      }

      reply.send({ item: redactNewsAuthor(rows[0]) });
    } catch (e) {
      log.err('Fetch public article failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load article' });
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
      SELECT n.*, ${NEWS_AUTHOR_COLUMNS}
      FROM news_entries n ${NEWS_AUTHOR_JOINS}
      WHERE n.is_private = 0
      ORDER BY n.created_at DESC
      LIMIT 100
    `);
      reply.send({ items: rows.map(redactNewsAuthor) });
    } catch (e) {
      log.err('Fetch news failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load news' });
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
      reply.status(500).send({ error: 'Failed to load headlines' });
    }
  });


  // POST /api/news/upload (Admin/Court) - Upload media
  fastify.post('/api/news/upload', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      // Check permissions: Admin or Court or has any news permission
      if (!guards.isCourt(req.user)) {
        const [perms] = await pool.query('SELECT id FROM user_news_permissions WHERE user_id=? LIMIT 1', [req.user.id]);
        if (perms.length === 0) {
          return reply.status(403).send({ error: 'Forbidden' });
        }
      }

      const fileData = await req.file();
      if (!fileData) return reply.status(400).send({ error: 'File required' });

      const originalname = fileData.filename || 'upload';
      const rawBuffer = await fileData.toBuffer();
      let buffer = rawBuffer;
      let mimetype = fileData.mimetype || 'application/octet-stream';
      let ext = originalname ? originalname.split('.').pop() : 'bin';

      // The CDN's own re-encoder silently drops the pixel data (200 OK,
      // correct Content-Type, zero-byte body) for indexed/palette PNGs —
      // normalize every image to a flat truecolor webp ourselves before it
      // ever reaches that path, same as chat/avatar uploads already do.
      if (mimetype.startsWith('image/')) {
        buffer = await sharp(rawBuffer)
          .resize(2000, 2000, { fit: 'inside', withoutEnlargement: true })
          .webp({ quality: 85 })
          .toBuffer();
        mimetype = 'image/webp';
        ext = 'webp';
      }
      const size = buffer.length;

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
      if (guards.isAdmin(req.user)) {
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
        if (!guards.isAdmin(req.user)) {
          // Check if user has permission for the requested theme
          const [perms] = await pool.query('SELECT id FROM user_news_permissions WHERE user_id=? AND theme=?', [req.user.id, theme]);
          if (perms.length === 0) {
            return reply.status(403).send({ error: 'You do not have permission to post under this theme' });
          }
        }
      } else if (type === 'announcement') {
        if (!guards.isCourt(req.user)) {
          return reply.status(403).send({ error: 'Only Court/Admin can post Announcements' });
        }
      } else {
        return reply.status(400).send({ error: 'Invalid type' });
      }

      if (!title || !body) return reply.status(400).send({ error: 'Title and Body are required' });

      // An admin may issue a decree in an NPC's name (shown with the NPC's
      // name, titles and portrait; author_id still records the real poster).
      let npcId = null;
      if (req.body.npc_id != null && req.body.npc_id !== '') {
        if (type !== 'announcement' || !guards.isAdmin(req.user)) {
          return reply.status(403).send({ error: 'Only admins can issue decrees as an NPC' });
        }
        const [[npc]] = await pool.query('SELECT id FROM npcs WHERE id = ?', [Number(req.body.npc_id)]);
        if (!npc) return reply.status(400).send({ error: 'NPC not found' });
        npcId = npc.id;
      }

      const safeBody = sanitizeRichText(body); // strip active markup before persisting (XSS)

      const isPriv = is_private ? 1 : 0;
      const [insertResult] = await pool.query(
        `INSERT INTO news_entries
      (author_id, npc_id, type, title, subtitle, body, theme, journalist_name, media_url, is_private, published_by, published_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          req.user.id,
          npcId,
          type,
          title,
          subtitle || null,
          safeBody, // Stored as sanitised HTML
          theme || 'Neutral',
          journalist_name || null,
          media_url || null,
          isPriv,
          isPriv ? null : req.user.id,
          isPriv ? null : new Date()
        ]
      );

      // --- DISCORD BROADCAST (REST API) ---
      const discordEnabled = await getSetting('discord_enabled', 'true') === 'true';
      const notifyPrems = await getSetting('discord_notify_news', 'true') === 'true';
      const tokenPresent = !!process.env.DISCORD_BOT_TOKEN;

      log.info('Discord News Broadcast Check', { discordEnabled, notifyPrems, tokenPresent });

      if (discordEnabled && notifyPrems && tokenPresent && !is_private) {
        try {
          const appBase = (process.env.APP_BASE_URL || req.headers.origin || '').replace(/\/$/, '') || 'http://localhost:3000';
          await broadcastNewsEntry(
            { id: insertResult.insertId, type, title, subtitle, theme, media_url },
            { pool, log, discordPrefix: req.body?.discord_prefix, appBase }
          );
        } catch (discordErr) {
          log.err('Discord news broadcast failed', { error: discordErr.response?.data ? JSON.stringify(discordErr.response.data) : discordErr.message });
        }
      }
      // -----------------------------------

      log.ok('News entry created', { user_id: req.user.id, type, title });
      reply.send({ ok: true, id: insertResult.insertId });
    } catch (e) {
      log.err('Create news failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to post' });
    }
  });

  // POST /api/news/:id/broadcast (Admin Only)
  fastify.post('/api/news/:id/broadcast', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT * FROM news_entries WHERE id = ?', [req.params.id]);
      if (rows.length === 0) return reply.status(404).send({ error: 'Entry not found' });

      const entry = rows[0];
      const appBase = (process.env.APP_BASE_URL || req.headers.origin || '').replace(/\/$/, '') || 'http://localhost:3000';

      const res = await broadcastNewsEntry(entry, {
        pool,
        log,
        discordPrefix: req.body?.discord_prefix,
        appBase
      });

      if (!res.ok) {
        return reply.status(400).send({ error: res.reason || 'Failed to broadcast to Discord' });
      }

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
      const appBase = (process.env.APP_BASE_URL || req.headers.origin || '').replace(/\/$/, '') || 'http://localhost:3000';

      if (entry.is_private === 0) {
        if (!req.body?.skip_discord) {
          const res = await broadcastNewsEntry(entry, {
            pool,
            log,
            discordPrefix: req.body?.discord_prefix,
            appBase
          }).catch(err => {
            log.err('Broadcast for already published news failed', { error: err.message });
            return { ok: false, reason: err.message };
          });
          return reply.send({ success: true, message: 'Already published', discordSent: Boolean(res?.ok) });
        }
        return reply.send({ success: true, message: 'Already published' });
      }

      await pool.query('UPDATE news_entries SET is_private = 0, published_by = ?, published_at = NOW() WHERE id = ?', [req.user.id, req.params.id]);

      let discordSent = false;
      if (!req.body?.skip_discord) {
        try {
          const res = await broadcastNewsEntry(entry, {
            pool,
            log,
            discordPrefix: req.body?.discord_prefix,
            appBase
          });
          discordSent = Boolean(res?.ok);
        } catch (err) {
          log.err('Failed to auto-broadcast published news', { error: err.message });
        }
      }

      log.ok('News entry published', { entry_id: req.params.id, admin_id: req.user.id, discordSent });
      reply.send({ success: true, message: 'Published successfully', discordSent });
    } catch (e) {
      log.err('Publish news failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to publish news' });
    }
  });

  // GET /api/admin/news - Fetch all news including private (Admin only)
  fastify.get('/api/admin/news', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
      SELECT n.*, ${NEWS_AUTHOR_COLUMNS},
             (SELECT COUNT(*) FROM news_reads r WHERE r.news_id = n.id) as reader_count,
             (SELECT COALESCE(SUM(r.open_count), 0) FROM news_reads r WHERE r.news_id = n.id) as open_total
      FROM news_entries n ${NEWS_AUTHOR_JOINS}
      WHERE n.type = 'news' OR n.type = 'announcement'
      ORDER BY n.created_at DESC
      LIMIT 200
    `);
      reply.send({ items: rows });
    } catch (e) {
      log.err('Fetch admin news failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load admin news' });
    }
  });

  // GET /api/admin/news/:id/reads - Logged-in readers of one article (Admin only)
  fastify.get('/api/admin/news/:id/reads', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const newsId = Number(req.params.id);
      const [rows] = await pool.query(
        `SELECT r.user_id, r.first_read_at, r.last_read_at, r.open_count,
                u.display_name, c.name as char_name, c.clan
         FROM news_reads r
         JOIN users u ON u.id = r.user_id
         LEFT JOIN characters c ON c.user_id = u.id
         WHERE r.news_id = ?
         ORDER BY r.last_read_at DESC`,
        [newsId]
      );
      const [entryRows] = await pool.query('SELECT views FROM news_entries WHERE id = ?', [newsId]);
      reply.send({ readers: rows, views: Number(entryRows[0]?.views || 0) });
    } catch (e) {
      log.err('Fetch news readers failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load readers' });
    }
  });

  // DELETE /api/news/:id (Admin Only)
  fastify.delete('/api/news/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      await pool.query('DELETE FROM news_entries WHERE id=?', [req.params.id]);
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).send({ error: 'Delete failed' });
    }
  });

  // GET /api/news/:id/reactions - Get reactions for an announcement
  fastify.get('/api/news/:id/reactions', async (req, reply) => {
    try {
      const entryId = Number(req.params.id);
      if (!entryId) return reply.status(400).send({ error: 'Invalid id' });

      const [rows] = await pool.query(
        `SELECT r.emoji, r.user_id, COALESCE(c.name, u.display_name, 'Unknown') as user_name, c.clan
         FROM announcement_reactions r
         LEFT JOIN users u ON u.id = r.user_id
         LEFT JOIN characters c ON c.user_id = u.id
         WHERE r.announcement_id = ?
         ORDER BY r.id ASC`,
        [entryId]
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
          clan: r.clan || null
        });
      }

      reply.send({ reactions: Object.values(emojiMap) });
    } catch (e) {
      log.err('Fetch news reactions failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load reactions' });
    }
  });

  // POST /api/news/:id/reactions - Toggle reaction for an announcement
  fastify.post('/api/news/:id/reactions', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const entryId = Number(req.params.id);
      const { emoji } = req.body || {};
      const userId = req.user.id;

      if (!entryId || !emoji || typeof emoji !== 'string' || emoji.length > 32) {
        return reply.status(400).send({ error: 'Invalid reaction parameters' });
      }

      const [news] = await pool.query('SELECT id FROM news_entries WHERE id = ?', [entryId]);
      if (news.length === 0) {
        return reply.status(404).send({ error: 'Announcement not found' });
      }

      const [existing] = await pool.query(
        'SELECT id FROM announcement_reactions WHERE announcement_id = ? AND user_id = ? AND emoji = ?',
        [entryId, userId, emoji]
      );

      if (existing.length > 0) {
        await pool.query('DELETE FROM announcement_reactions WHERE id = ?', [existing[0].id]);
      } else {
        await pool.query(
          'INSERT INTO announcement_reactions (announcement_id, user_id, emoji) VALUES (?, ?, ?)',
          [entryId, userId, emoji]
        );
      }

      const [rows] = await pool.query(
        `SELECT r.emoji, r.user_id, COALESCE(c.name, u.display_name, 'Unknown') as user_name, c.clan
         FROM announcement_reactions r
         LEFT JOIN users u ON u.id = r.user_id
         LEFT JOIN characters c ON c.user_id = u.id
         WHERE r.announcement_id = ?
         ORDER BY r.id ASC`,
        [entryId]
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
          clan: r.clan || null
        });
      }

      const reactions = Object.values(emojiMap);
      if (fastify.io) {
        const payload = { announcementId: entryId, messageId: entryId };
        fastify.io.emit('announcements:reactions', payload);
      }

      reply.send({ reactions });
    } catch (e) {
      log.err('Toggle news reaction failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to toggle reaction' });
    }
  });

  // POST /api/news/reactions/batch - Batch fetch reactions for multiple announcements
  fastify.post('/api/news/reactions/batch', async (req, reply) => {
    try {
      const { ids } = req.body || {};
      if (!Array.isArray(ids) || ids.length === 0) {
        return reply.send({ reactions: {} });
      }

      const cleanIds = ids.map(Number).filter(n => Number.isInteger(n) && n > 0).slice(0, 150);
      if (cleanIds.length === 0) {
        return reply.send({ reactions: {} });
      }

      const [rows] = await pool.query(
        `SELECT r.announcement_id, r.emoji, r.user_id, COALESCE(c.name, u.display_name, 'Unknown') as user_name, c.clan
         FROM announcement_reactions r
         LEFT JOIN users u ON u.id = r.user_id
         LEFT JOIN characters c ON c.user_id = u.id
         WHERE r.announcement_id IN (?)
         ORDER BY r.id ASC`,
        [cleanIds]
      );

      const map = {};
      for (const r of rows) {
        if (!map[r.announcement_id]) map[r.announcement_id] = {};
        if (!map[r.announcement_id][r.emoji]) {
          map[r.announcement_id][r.emoji] = {
            emoji: r.emoji,
            count: 0,
            users: [],
            reactors: []
          };
        }
        map[r.announcement_id][r.emoji].count += 1;
        map[r.announcement_id][r.emoji].users.push(Number(r.user_id));
        map[r.announcement_id][r.emoji].reactors.push({
          id: Number(r.user_id),
          name: r.user_name,
          clan: r.clan || null
        });
      }

      const resultMap = {};
      for (const [annId, eMap] of Object.entries(map)) {
        resultMap[annId] = Object.values(eMap);
      }

      reply.send({ reactions: resultMap });
    } catch (e) {
      log.err('Batch fetch announcement reactions failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to batch fetch reactions' });
    }
  });

  // --- NEWS DRAFTS ---

  const canAuthorNews = async (user) => {
    if (guards.isAdmin(user)) return true;
    const [perms] = await pool.query('SELECT id FROM user_news_permissions WHERE user_id=? LIMIT 1', [user.id]);
    return perms.length > 0;
  };

  // GET /api/news/drafts - List drafts
  fastify.get('/api/news/drafts', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const isAllowed = await canAuthorNews(req.user);
      if (!isAllowed) {
        return reply.status(403).send({ error: 'Forbidden' });
      }

      const isAdminUser = guards.isAdmin(req.user);
      let sql = `
        SELECT d.*, 
               u.display_name AS author_name,
               c.name AS author_char_name,
               c.clan AS author_clan
        FROM news_article_drafts d
        JOIN users u ON u.id = d.user_id
        LEFT JOIN characters c ON c.user_id = u.id
      `;
      const params = [];
      if (!isAdminUser) {
        sql += ` WHERE d.user_id = ?`;
        params.push(req.user.id);
      }
      sql += ` ORDER BY d.updated_at DESC LIMIT 100`;

      const [rows] = await pool.query(sql, params);
      reply.send({ drafts: rows });
    } catch (e) {
      log.err('Fetch news drafts failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load news drafts' });
    }
  });

  // GET /api/news/drafts/:id - Fetch single draft
  fastify.get('/api/news/drafts/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const isAllowed = await canAuthorNews(req.user);
      if (!isAllowed) return reply.status(403).send({ error: 'Forbidden' });

      const [rows] = await pool.query(
        `SELECT d.*, u.display_name AS author_name
         FROM news_article_drafts d
         JOIN users u ON u.id = d.user_id
         WHERE d.id = ? LIMIT 1`,
        [req.params.id]
      );
      if (rows.length === 0) {
        return reply.status(404).send({ error: 'Draft not found' });
      }

      const draft = rows[0];
      if (!guards.isAdmin(req.user) && Number(draft.user_id) !== Number(req.user.id)) {
        return reply.status(403).send({ error: 'Forbidden' });
      }

      reply.send({ draft });
    } catch (e) {
      log.err('Fetch news draft failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load draft' });
    }
  });

  // POST /api/news/drafts - Save new draft
  fastify.post('/api/news/drafts', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const isAllowed = await canAuthorNews(req.user);
      if (!isAllowed) return reply.status(403).send({ error: 'Forbidden' });

      const {
        title = '',
        subtitle = null,
        body = '',
        theme = 'ERT',
        journalist_name = null,
        discord_prefix = null,
        is_custom_prefix = 0,
        is_private = 0,
        media_url = null
      } = req.body || {};

      const safeBody = sanitizeRichText(body || '');

      const [res] = await pool.query(
        `INSERT INTO news_article_drafts
         (user_id, title, subtitle, body, theme, journalist_name, discord_prefix, is_custom_prefix, is_private, media_url)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          req.user.id,
          String(title || '').slice(0, 255),
          subtitle ? String(subtitle).slice(0, 255) : null,
          safeBody,
          theme || 'ERT',
          journalist_name ? String(journalist_name).slice(0, 100) : null,
          discord_prefix ? String(discord_prefix).slice(0, 255) : null,
          is_custom_prefix ? 1 : 0,
          is_private ? 1 : 0,
          media_url || null
        ]
      );

      const [created] = await pool.query('SELECT * FROM news_article_drafts WHERE id = ?', [res.insertId]);
      reply.status(201).send({ draft: created[0] });
    } catch (e) {
      log.err('Create news draft failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to save news draft' });
    }
  });

  // PUT /api/news/drafts/:id - Update existing draft
  fastify.put('/api/news/drafts/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const isAllowed = await canAuthorNews(req.user);
      if (!isAllowed) return reply.status(403).send({ error: 'Forbidden' });

      const [existing] = await pool.query('SELECT * FROM news_article_drafts WHERE id = ? LIMIT 1', [req.params.id]);
      if (existing.length === 0) return reply.status(404).send({ error: 'Draft not found' });

      const draft = existing[0];
      if (!guards.isAdmin(req.user) && Number(draft.user_id) !== Number(req.user.id)) {
        return reply.status(403).send({ error: 'Forbidden' });
      }

      const {
        title = draft.title,
        subtitle = draft.subtitle,
        body = draft.body,
        theme = draft.theme,
        journalist_name = draft.journalist_name,
        discord_prefix = draft.discord_prefix,
        is_custom_prefix = draft.is_custom_prefix,
        is_private = draft.is_private,
        media_url = draft.media_url
      } = req.body || {};

      const safeBody = sanitizeRichText(body || '');

      await pool.query(
        `UPDATE news_article_drafts
         SET title = ?, subtitle = ?, body = ?, theme = ?, journalist_name = ?,
             discord_prefix = ?, is_custom_prefix = ?, is_private = ?, media_url = ?, updated_at = NOW()
         WHERE id = ?`,
        [
          String(title || '').slice(0, 255),
          subtitle ? String(subtitle).slice(0, 255) : null,
          safeBody,
          theme || 'ERT',
          journalist_name ? String(journalist_name).slice(0, 100) : null,
          discord_prefix ? String(discord_prefix).slice(0, 255) : null,
          is_custom_prefix ? 1 : 0,
          is_private ? 1 : 0,
          media_url || null,
          req.params.id
        ]
      );

      const [updated] = await pool.query('SELECT * FROM news_article_drafts WHERE id = ?', [req.params.id]);
      reply.send({ draft: updated[0] });
    } catch (e) {
      log.err('Update news draft failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to update news draft' });
    }
  });

  // DELETE /api/news/drafts/:id - Delete draft
  fastify.delete('/api/news/drafts/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const isAllowed = await canAuthorNews(req.user);
      if (!isAllowed) return reply.status(403).send({ error: 'Forbidden' });

      const [existing] = await pool.query('SELECT user_id FROM news_article_drafts WHERE id = ? LIMIT 1', [req.params.id]);
      if (existing.length === 0) return reply.status(404).send({ error: 'Draft not found' });

      if (!guards.isAdmin(req.user) && Number(existing[0].user_id) !== Number(req.user.id)) {
        return reply.status(403).send({ error: 'Forbidden' });
      }

      await pool.query('DELETE FROM news_article_drafts WHERE id = ?', [req.params.id]);
      reply.send({ success: true });
    } catch (e) {
      log.err('Delete news draft failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to delete news draft' });
    }
  });
};
