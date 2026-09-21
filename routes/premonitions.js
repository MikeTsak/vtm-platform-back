// routes/premonitions.js
//
// Malkavian premonitions: Storyteller authoring and delivery, player inbox,
// and the attached media.
const { getSetting } = require('../utils/settings');
const { sendDiscordDM } = require('../services/discord');
const { isVideoUrl, resolveMediaUrl } = require('../services/news');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, imageClient } = opts;

  function parseWarnings(raw) {
    if (!raw) return [];
    try {
      const p = JSON.parse(raw);
      return Array.isArray(p) ? p : [String(p)];
    } catch {
      return [String(raw)];
    }
  }

  /* -------------------- NEW PREMONITION ROUTES -------------------- */

  // ADMIN: List all premonitions (+ recipients)
  fastify.get('/api/admin/premonitions', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {

      // Base list
      const [prems] = await pool.query(`
      SELECT p.id, p.sender_id, u.display_name AS sender_name,
             p.content_type, p.content_text,
             COALESCE(pm.data_url, p.content_url) AS content_url,
             p.warnings,
             p.created_at
      FROM premonitions p
      LEFT JOIN users u ON u.id = p.sender_id
      LEFT JOIN premonition_media pm ON pm.id = CAST(SUBSTRING_INDEX(p.content_url, '/', -1) AS UNSIGNED)
        AND p.content_url LIKE '%/media/%'
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
          warnings: parseWarnings(p.warnings),
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
      const { content_type, content_text, content_url, user_ids = [], warnings = [] } = req.body;
      const sendToAllMalks = user_ids.includes('all_malkavians');

      if (!content_type || (!content_text && !content_url)) {
        return reply.status(400).json({ error: 'Type and content (text or URL) are required' });
      }

      let normalizedWarnings = [];
      if (Array.isArray(warnings)) {
        normalizedWarnings = warnings.map(w => String(w).trim()).filter(Boolean);
      } else if (typeof warnings === 'string' && warnings.trim()) {
        try {
          const parsed = JSON.parse(warnings);
          if (Array.isArray(parsed)) normalizedWarnings = parsed.map(w => String(w).trim()).filter(Boolean);
          else normalizedWarnings = [warnings.trim()];
        } catch {
          normalizedWarnings = [warnings.trim()];
        }
      }
      const warningsJson = normalizedWarnings.length ? JSON.stringify(normalizedWarnings) : null;

      // 1. Create the premonition content
      const [ins] = await pool.query(
        `INSERT INTO premonitions (sender_id, content_type, content_text, content_url, warnings)
       VALUES (?, ?, ?, ?, ?)`,
        [req.user.id, content_type, content_text || null, content_url || null, warningsJson]
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

        if (discordEnabled && notifyPrems && process.env.DISCORD_BOT_TOKEN) {
          try {
            const [userRows] = await pool.query(
              `SELECT discord_id, display_name FROM users WHERE id IN (?) AND discord_id IS NOT NULL AND discord_id != ''`,
              [uniqueUserIds]
            );

            // Log how many Discord accounts were found
            log.ok(`Discord Premonition: Found ${userRows.length} linked accounts for targets.`, { targets: uniqueUserIds });

            const appBase = (process.env.APP_BASE_URL || req.headers.origin || '').replace(/\/$/, '') || 'https://portal.attlarp.gr';
            const resolvedMedia = await resolveMediaUrl(content_url, appBase, pool);

            for (const row of userRows) {
              try {
                let dmMsg = `🧠 **A sudden vision pierces your mind...**\n\n`;
                if (normalizedWarnings.length) {
                  dmMsg += `⚠️ **Content Warning: ${normalizedWarnings.join(', ')}**\n\n`;
                }
                if (content_text) dmMsg += `_${content_text}_\n`;

                const payload = { content: dmMsg };

                if (content_type === 'image' && resolvedMedia) {
                  payload.embeds = [{ image: { url: resolvedMedia } }];
                  payload.content += `\n👁️ **View Vision:** https://portal.attlarp.gr/media/${premonitionId}`;
                } else if (content_type === 'video') {
                  payload.content += `\n👁️ **View Vision:** https://portal.attlarp.gr/media/${premonitionId}`;
                  if (resolvedMedia) {
                    payload.content += `\n\n🎥 **Attached Media:**\n${resolvedMedia}`;
                  }
                } else if (resolvedMedia) {
                  payload.content += `\n🔗 ${resolvedMedia}`;
                }

                await sendDiscordDM(row.discord_id, payload);
                log.ok(`Premonition DM sent to ${row.display_name}`);
              } catch (dmErr) {
                log.warn(`Failed to DM Discord user ${row.discord_id} (${row.display_name})`, { error: dmErr.message });
              }
            }
          } catch (dbErr) {
            log.err('Failed to fetch Discord IDs for premonitions', { error: dbErr.message });
          }
        } else if (!discordEnabled || !notifyPrems) {
          log.warn('Discord Premonition DM Skipped: Feature is toggled OFF.', {
            enabled: discordEnabled,
            notify: notifyPrems
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
             p.content_type, p.content_text,
             COALESCE(pm.data_url, p.content_url) AS content_url,
             p.warnings,
             p.created_at
      FROM premonitions p
      JOIN premonition_recipients pr ON p.id = pr.premonition_id
      LEFT JOIN users u ON u.id = p.sender_id
      LEFT JOIN premonition_media pm ON pm.id = CAST(SUBSTRING_INDEX(p.content_url, '/', -1) AS UNSIGNED)
        AND p.content_url LIKE '%/media/%'
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

      // Cache control
      reply.header('Cache-Control', 'no-store');
      reply.status(200).json({
        premonitions: rows.map(r => ({
          ...r,
          warnings: parseWarnings(r.warnings)
        }))
      });
    } catch (e) {
      log.err('Failed to get my premonitions', { message: e.message });
      reply.status(500).json({ error: 'Failed to load premonitions' });
    }
  });



  // MEDIA: Stream media from DB or return media info
  fastify.get('/api/premonitions/media/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const id = Number(req.params.id) || 0;

      let hasAccess = req.user.role === 'admin';

      if (!hasAccess) {
        const likePattern = `%/media/${id}%`;

        const [accessRows] = await pool.query(`
        SELECT 1 FROM premonitions p
        JOIN premonition_recipients pr ON p.id = pr.premonition_id
        WHERE (p.content_url LIKE ? OR p.id = ?) AND pr.user_id = ?
      `, [likePattern, id, req.user.id]);

        if (accessRows.length > 0) {
          hasAccess = true;
        }
      }

      if (!hasAccess) {
        return reply.status(403).json({ error: 'Forbidden' });
      }

      // Check premonition_media first
      let [rows] = await pool.query('SELECT data_url, mime, size, data FROM premonition_media WHERE id=? LIMIT 1', [id]);
      if (!rows.length) {
        // Fallback: :id might be the premonitions.id
        const [pRows] = await pool.query(`
          SELECT pm.data_url, pm.mime, pm.size, pm.data, p.content_url
          FROM premonitions p
          LEFT JOIN premonition_media pm ON pm.id = CAST(SUBSTRING_INDEX(p.content_url, '/', -1) AS UNSIGNED)
            AND p.content_url LIKE '%/media/%'
          WHERE p.id=? LIMIT 1
        `, [id]);
        if (pRows.length) {
          if (pRows[0].data_url) {
            rows = [{ data_url: pRows[0].data_url, mime: pRows[0].mime, size: pRows[0].size, data: pRows[0].data }];
          } else if (pRows[0].content_url && (pRows[0].content_url.startsWith('http://') || pRows[0].content_url.startsWith('https://'))) {
            rows = [{ data_url: pRows[0].content_url, mime: null, size: null, data: null }];
          }
        }
      }

      if (!rows.length) {
        return reply.status(404).send('Not found');
      }

      const { data_url, mime, size, data } = rows[0];

      // Provide JSON metadata info if requested via ?info=1 or Accept: application/json
      if (req.query.info === '1' || req.headers.accept?.includes('application/json')) {
        let mediaWarnings = [];
        try {
          const [wRows] = await pool.query(
            `SELECT warnings FROM premonitions WHERE id = ? OR content_url LIKE ? LIMIT 1`,
            [id, `%/media/${id}%`]
          );
          if (wRows.length && wRows[0].warnings) {
            mediaWarnings = parseWarnings(wRows[0].warnings);
          }
        } catch {}

        return reply.send({
          url: data_url || `/api/premonitions/media/${id}`,
          mime,
          warnings: mediaWarnings
        });
      }

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
