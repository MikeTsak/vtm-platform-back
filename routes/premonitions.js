// routes/premonitions.js
//
// Malkavian premonitions: Storyteller authoring and delivery, player inbox,
// and the attached media.
const { getSetting } = require('../utils/settings');
const { discordClient } = require('../services/discord');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, imageClient } = opts;

  /* -------------------- NEW PREMONITION ROUTES -------------------- */

  // ADMIN: List all premonitions (+ recipients)
  fastify.get('/api/admin/premonitions', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {

      // Base list
      const [prems] = await pool.query(`
      SELECT p.id, p.sender_id, u.display_name AS sender_name,
             p.content_type, p.content_text, p.content_url, p.created_at
      FROM premonitions p
      LEFT JOIN users u ON u.id = p.sender_id
      ORDER BY p.created_at DESC
      LIMIT 500
    `);

      if (prems.length === 0) return reply.send({ premonitions: [] });

      // Recipients per premonition
      const ids = prems.map(p => p.id);
      const [recips] = await pool.query(`
      SELECT pr.premonition_id, pr.user_id, pr.viewed_at,
             u.display_name, COALESCE(c.name,'') AS char_name
      FROM premonition_recipients pr
      JOIN users u ON u.id = pr.user_id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE pr.premonition_id IN (${ids.map(() => '?').join(',')})
      ORDER BY u.display_name ASC
    `, ids);

      const byPrem = new Map();
      for (const r of recips) {
        if (!byPrem.has(r.premonition_id)) byPrem.set(r.premonition_id, []);
        byPrem.get(r.premonition_id).push({
          user_id: r.user_id,
          display_name: r.display_name,
          char_name: r.char_name || null,
          viewed_at: r.viewed_at
        });
      }

      reply.send({
        premonitions: prems.map(p => ({
          ...p,
          recipients: byPrem.get(p.id) || []
        }))
      });
    } catch (e) {
      log.err('Admin list premonitions failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to load premonitions' });
    }
  });


  // ADMIN: Get list of Malkavian players  ✅ REPLACE THIS ROUTE
  fastify.get('/api/admin/premonitions/malkavians', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {

      // One row per user that has at least one Malkavian character
      const [rows] = await pool.query(`
      SELECT 
        u.id,
        u.display_name,
        COALESCE(MAX(c.name), '(no character)') AS char_name
      FROM users u
      LEFT JOIN characters c 
        ON c.user_id = u.id
      WHERE u.role <> 'admin'
        AND EXISTS (
          SELECT 1
          FROM characters c2
          WHERE c2.user_id = u.id
            AND LOWER(TRIM(c2.clan)) = 'malkavian'
        )
      GROUP BY u.id, u.display_name
      ORDER BY u.display_name ASC
    `);

      reply.send({ malkavians: rows });
    } catch (e) {
      log.err('Failed to get Malkavian list', { message: e.message });
      reply.status(500).json({ error: 'Failed to get Malkavians' });
    }
  });

  // ADMIN: Upload media and store it in the DB
  fastify.post('/api/admin/premonitions/upload', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const fileData = await req.file();
      if (!fileData) {
        return reply.status(400).send({ error: 'File is required' });
      }
      const originalname = fileData.filename || 'upload';
      const mimetype = fileData.mimetype || 'application/octet-stream';
      const buffer = await fileData.toBuffer();
      const size = buffer.length;

      const ext = originalname ? originalname.split('.').pop() : 'bin';
      const filenameToUpload = 'premonitions_media_' + Date.now() + '.' + ext;
      const result = await imageClient.uploadImage(buffer, filenameToUpload);
      if (!result || !result.success) throw new Error((result && result.error) || 'CDN upload failed');
      const resultUrl = result.url;

      // CDN-only — no BLOB fallback.
      const [ins] = await pool.query(
        'INSERT INTO premonition_media (filename, mime, size, data_url, data) VALUES (?,?,?,?,NULL)',
        [originalname, mimetype, size, resultUrl]
      );
      const media_id = ins.insertId;

      reply.send({
        media_id,
        media_mime: mimetype,
        media_stream_url: resultUrl || `/api/premonitions/media/${media_id}`
      });
    } catch (e) {
      log.err('Premonition media upload failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to upload media' });
    }
  });

  // ADMIN: Create and send a new premonition
  fastify.post('/api/admin/premonitions/send', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { content_type, content_text, content_url, user_ids = [] } = req.body;
      const sendToAllMalks = user_ids.includes('all_malkavians');

      if (!content_type || (!content_text && !content_url)) {
        return reply.status(400).json({ error: 'Type and content (text or URL) are required' });
      }

      // 1. Create the premonition content
      const [ins] = await pool.query(
        `INSERT INTO premonitions (sender_id, content_type, content_text, content_url)
       VALUES (?, ?, ?, ?)`,
        [req.user.id, content_type, content_text || null, content_url || null]
      );
      const premonitionId = ins.insertId;

      // 2. Figure out who to send it to
      let targetUserIds = [];
      if (sendToAllMalks) {
        // Get all non-admin Malkavian user IDs
        const [malks] = await pool.query(`
        SELECT DISTINCT u.id
        FROM users u
        JOIN characters c ON c.user_id = u.id
        WHERE u.role <> 'admin'
          AND LOWER(TRIM(c.clan)) = 'malkavian'
      `);
        targetUserIds = malks.map(m => m.id);
      } else {
        // Use the specific list, filtering out any non-numeric values
        targetUserIds = user_ids.map(id => parseInt(id)).filter(id => !isNaN(id));
      }

      // 3. Insert recipients
      if (targetUserIds.length > 0) {
        // Remove duplicates
        const uniqueUserIds = [...new Set(targetUserIds)];
        const values = uniqueUserIds.map(userId => [premonitionId, userId]);
        await pool.query(
          'INSERT INTO premonition_recipients (premonition_id, user_id) VALUES ?',
          [values]
        );

        // --- UPDATED: DISCORD PREMONITION DMs ---
        const discordEnabled = await getSetting('discord_enabled', 'true') === 'true';
        const notifyPrems = await getSetting('discord_notify_prems', 'true') === 'true';

        if (discordEnabled && notifyPrems && discordClient?.isReady()) {
          try {
            const [userRows] = await pool.query(
              `SELECT discord_id, display_name FROM users WHERE id IN (?) AND discord_id IS NOT NULL AND discord_id != ''`,
              [uniqueUserIds]
            );

            // Log how many Discord accounts were found
            log.ok(`Discord Premonition: Found ${userRows.length} linked accounts for targets.`, { targets: uniqueUserIds });

            for (const row of userRows) {
              try {
                const discordUser = await discordClient.users.fetch(row.discord_id);
                if (discordUser) {
                  let dmMsg = `🧠 **A sudden vision pierces your mind...**\n\n`;
                  if (content_text) dmMsg += `_${content_text}_\n`;

                  if (content_type === 'image' || content_type === 'video') {
                    dmMsg += `\n👁️ **View Vision:** https://portal.attlarp.gr/media/${premonitionId}`;
                  } else if (content_url) {
                    dmMsg += `\n🔗 ${content_url}`;
                  }

                  await discordUser.send(dmMsg);
                  log.ok(`Premonition DM sent to ${row.display_name}`);
                }
              } catch (dmErr) {
                log.warn(`Failed to DM Discord user ${row.discord_id} (${row.display_name})`, { error: dmErr.message });
              }
            }
          } catch (dbErr) {
            log.err('Failed to fetch Discord IDs for premonitions', { error: dbErr.message });
          }
        } else {
          // This log will appear if the bot skips the DM process entirely
          log.warn('Discord DM Skipped: Feature is toggled OFF or Bot is not ready.', {
            enabled: discordEnabled,
            notify: notifyPrems,
            ready: discordClient?.isReady()
          });
        }
        // ------------------------------------
      }

      log.adm('Admin sent premonition', { id: premonitionId, by_user_id: req.user.id, targets: sendToAllMalks ? 'all_malks' : targetUserIds });
      reply.status(201).json({ ok: true, premonition_id: premonitionId, count: targetUserIds.length });


    } catch (e) {
      log.err('Failed to send premonition', { message: e.message, stack: e.stack });
      reply.status(500).json({ error: 'Failed to send premonition' });
    }
  });

  // PLAYER: Get my premonitions
  fastify.get('/api/premonitions/mine', { preHandler: [authRequired] }, async (req, reply) => {
    try {

      const [rows] = await pool.query(`
      SELECT p.id, p.sender_id, u.display_name AS sender_name,
             p.content_type, p.content_text, p.content_url, p.created_at
      FROM premonitions p
      JOIN premonition_recipients pr ON p.id = pr.premonition_id
      LEFT JOIN users u ON u.id = p.sender_id
      WHERE pr.user_id = ?
      ORDER BY p.created_at DESC
    `, [req.user.id]);

      // fire & forget mark viewed
      if (rows.length > 0) {
        const ids = rows.map(r => r.id);
        pool.query(
          `UPDATE premonition_recipients
         SET viewed_at = NOW()
         WHERE user_id = ? AND premonition_id IN (${ids.map(() => '?').join(',')})
           AND viewed_at IS NULL`,
          [req.user.id, ...ids]
        ).catch(err => log.err('Failed to mark premonitions as read', { message: err.message }));
      }

      // 👇 ΑΥΤΟ είναι το σημαντικό
      reply.header('Cache-Control', 'no-store');
      reply.status(200).json({ premonitions: rows });
    } catch (e) {
      log.err('Failed to get my premonitions', { message: e.message });
      reply.status(500).json({ error: 'Failed to load premonitions' });
    }
  });



  // MEDIA: Stream media from DB
  fastify.get('/api/premonitions/media/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const id = Number(req.params.id) || 0;

      // **FIX: Initialize hasAccess here**
      let hasAccess = req.user.role === 'admin';

      // Check if user is admin OR has access to this premonition
      if (!hasAccess) {
        // FIX: Build the LIKE pattern string first using a template literal (backticks)
        const likePattern = `%/api/premonitions/media/${id}%`;

        const [accessRows] = await pool.query(`
        SELECT 1 FROM premonitions p
        JOIN premonition_recipients pr ON p.id = pr.premonition_id
        WHERE p.content_url LIKE ? AND pr.user_id = ?
      `, [likePattern, req.user.id]); // FIX: Pass the correctly built string

        if (accessRows.length > 0) {
          hasAccess = true;
        }
      }

      if (!hasAccess) {
        return reply.status(403).json({ error: 'Forbidden' });
      }

      // User has access, fetch the media
      const [rows] = await pool.query('SELECT data_url, mime, size, data FROM premonition_media WHERE id=? LIMIT 1', [id]);
      if (!rows.length) {
        return reply.status(404).send('Not found');
      }

      const { data_url, mime, size, data } = rows[0];
      if (data_url) return reply.redirect(302, data_url);
      if (!data) return reply.status(404).send('Not found');

      if (typeof data === 'string' && data.startsWith('http')) {
        return reply.redirect(302, data);
      }
      reply.header('Content-Type', mime || 'application/octet-stream');
      reply.header('Content-Length', size);
      reply.header('Cache-Control', 'private, max-age=3600'); // 1 hour
      reply.send(data); // send raw blob
    } catch (e) {
      log.err('Failed to stream media', { message: e.message });
      reply.status(500).json({ error: 'Failed to stream media' });
    }
  });
};
