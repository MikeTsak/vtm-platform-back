// routes/avatars.js
//
// Avatar read/write for every portrait-bearing entity (users, NPCs, retainers,
// email identities). Uploads are resized and pushed to the image CDN.

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, getMimeType, imageClient, sharp } = opts;

  fastify.get('/api/npcs/:id/avatar', async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT avatar_url, avatar_url_thumb, avatar FROM npcs WHERE id = ?', [req.params.id]);
      if (rows.length === 0) return reply.status(404).send('Avatar not found');

      const targetUrl = (req.query.size === 'thumb' && rows[0].avatar_url_thumb) ? rows[0].avatar_url_thumb
        : rows[0].avatar_url ? rows[0].avatar_url
          : (typeof rows[0].avatar === 'string' && rows[0].avatar.startsWith('http')) ? rows[0].avatar
            : null;

      if (targetUrl) {
        reply.header('Cache-Control', 'public, max-age=86400');
        return reply.redirect(targetUrl);
      }

      if (!rows[0].avatar) return reply.status(404).send('Avatar not found');

      const mime = getMimeType(rows[0].avatar);
      reply.header('Content-Type', mime);
      reply.header('Cache-Control', 'public, max-age=86400'); // Cache for 1 day
      reply.send(rows[0].avatar);
    } catch (e) {
      log.err('NPC Avatar GET error', { message: e.message });
      reply.status(500).send({ error: 'Server error retrieving avatar.' });
    }
  });

  fastify.put('/api/npcs/:id/avatar', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const fileData = await req.file();
      if (!fileData) {
        return reply.status(400).send({ error: 'No image file provided.' });
      }
      const rawBuffer = await fileData.toBuffer();

      const buffer = await sharp(rawBuffer)
        .resize(500, 500, { fit: 'cover' })
        .webp({ quality: 80 })
        .toBuffer();
      const thumbBuffer = await sharp(rawBuffer)
        .resize(160, 160, { fit: 'cover' })
        .webp({ quality: 80 })
        .toBuffer();

      const filename = "npcs_" + req.params.id + ".jpg";
      const result = await imageClient.uploadImage(buffer, filename);
      if (!result || !result.success) throw new Error((result && result.error) || 'CDN upload failed');
      const avatarUrl = result.url;

      let avatarUrlThumb = null;
      try {
        const thumbResult = await imageClient.uploadImage(thumbBuffer, "npcs_" + req.params.id + "_thumb.jpg");
        if (thumbResult && thumbResult.success) avatarUrlThumb = thumbResult.url;
      } catch (imgErr) {
        log.warn('CDN thumb upload failed for NPC avatar', { error: imgErr.message });
      }

      // CDN-only — no BLOB fallback (see migrate-avatars-to-cdn.js for the
      // one-off cleanup of any avatars still stored as bytes from before).
      await pool.query('UPDATE npcs SET avatar_url = ?, avatar_url_thumb = ?, avatar = NULL WHERE id = ?', [avatarUrl, avatarUrlThumb, req.params.id]);
      reply.send({ success: true, message: 'NPC Avatar updated successfully.', url: avatarUrl });
    } catch (e) {
      log.err('NPC Avatar PUT error', { message: e.message });
      reply.status(500).send({ error: 'Server error updating npc avatar.' });
    }
  });

  // GET retainer avatar
  fastify.get('/api/retainers/:id/avatar', async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT avatar_url, avatar_url_thumb, avatar FROM retainers WHERE id = ?', [req.params.id]);
      if (rows.length === 0) return reply.status(404).send('No avatar found');
      if (req.query.size === 'thumb' && rows[0].avatar_url_thumb) {
        reply.header('Cache-Control', 'public, max-age=86400');
        return reply.redirect(rows[0].avatar_url_thumb);
      }
      if (rows[0].avatar_url) {
        reply.header('Cache-Control', 'public, max-age=86400');
        return reply.redirect(rows[0].avatar_url);
      }
      if (!rows[0].avatar) return reply.status(404).send('No avatar found');
      if (typeof rows[0].avatar === 'string' && rows[0].avatar.startsWith('http')) {
        reply.header('Cache-Control', 'public, max-age=86400');
        return reply.redirect(rows[0].avatar);
      }
      const mime = getMimeType(rows[0].avatar);
      reply.header('Content-Type', mime);
      reply.header('Cache-Control', 'public, max-age=86400');
      reply.send(rows[0].avatar);
    } catch (e) {
      log.err('Failed to get retainer avatar', { error: e.message });
      reply.status(500).send('Server Error');
    }
  });

  // PUT retainer avatar
  fastify.put('/api/retainers/:id/avatar', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const fileData = await req.file();
      if (!fileData) return reply.status(400).send({ error: 'No file uploaded' });
      const rawBuffer = await fileData.toBuffer();
      const processedBuffer = await sharp(rawBuffer)
        .resize(500, 500, { fit: 'cover' })
        .webp({ quality: 80 })
        .toBuffer();
      const thumbBuffer = await sharp(rawBuffer)
        .resize(160, 160, { fit: 'cover' })
        .webp({ quality: 80 })
        .toBuffer();

      const filename = "retainers_" + req.params.id + ".jpg";
      const result = await imageClient.uploadImage(processedBuffer, filename);
      if (!result || !result.success) throw new Error((result && result.error) || 'CDN upload failed');
      const avatarUrl = result.url;

      let avatarUrlThumb = null;
      try {
        const thumbResult = await imageClient.uploadImage(thumbBuffer, "retainers_" + req.params.id + "_thumb.jpg");
        if (thumbResult && thumbResult.success) avatarUrlThumb = thumbResult.url;
      } catch (imgErr) {
        log.warn('CDN thumb upload failed for retainer', { error: imgErr.message });
      }

      // CDN-only — no BLOB fallback (see migrate-avatars-to-cdn.js for the
      // one-off cleanup of any avatars still stored as bytes from before).
      await pool.query('UPDATE retainers SET avatar_url = ?, avatar_url_thumb = ?, avatar = NULL WHERE id = ?', [avatarUrl, avatarUrlThumb, req.params.id]);
      reply.send({ success: true, url: avatarUrl });
    } catch (e) {
      log.err('Failed to update retainer avatar', { error: e.message });
      reply.status(500).send({ error: 'Failed to update avatar' });
    }
  });

  /* -------------------- Identity Avatars -------------------- */

  fastify.get('/api/identities/:id/avatar', async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT avatar_url, avatar_url_thumb, avatar FROM email_identities WHERE id = ?', [req.params.id]);
      if (rows.length === 0) return reply.status(404).send('Avatar not found');

      const targetUrl = (req.query.size === 'thumb' && rows[0].avatar_url_thumb) ? rows[0].avatar_url_thumb
        : rows[0].avatar_url ? rows[0].avatar_url
          : (typeof rows[0].avatar === 'string' && rows[0].avatar.startsWith('http')) ? rows[0].avatar
            : null;

      if (targetUrl) {
        reply.header('Cache-Control', 'public, max-age=86400');
        return reply.redirect(targetUrl);
      }

      if (!rows[0].avatar) return reply.status(404).send('Avatar not found');

      const mime = getMimeType(rows[0].avatar);
      reply.header('Content-Type', mime);
      reply.header('Cache-Control', 'public, max-age=31536000, immutable');
      reply.send(rows[0].avatar);
    } catch (err) {
      log.err('Identity avatar fetch error', err);
      reply.status(500).send('Error fetching avatar');
    }
  });

  fastify.put('/api/identities/:id/avatar', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const fileData = await req.file();
      if (!fileData) {
        return reply.status(400).json({ error: 'No image file provided.' });
      }
      const rawBuffer = await fileData.toBuffer();

      const buffer = await sharp(rawBuffer)
        .resize(500, 500, { fit: 'cover', position: 'top' })
        .webp({ quality: 80 })
        .toBuffer();
      const thumbBuffer = await sharp(rawBuffer)
        .resize(160, 160, { fit: 'cover', position: 'top' })
        .webp({ quality: 80 })
        .toBuffer();

      // const fileBlob = new Blob([buffer]);
      const filename = "email_identities_" + req.params.id + ".jpg";
      const result = await imageClient.uploadImage(buffer, filename);

      if (!result.success) throw new Error(result.error);

      // Best-effort: the main avatar already succeeded above, so a failed
      // thumb upload shouldn't fail the whole request — GET just falls back
      // to the full-size avatar_url when avatar_url_thumb is null.
      let thumbUrl = null;
      try {
        const thumbResult = await imageClient.uploadImage(thumbBuffer, "email_identities_" + req.params.id + "_thumb.jpg");
        if (thumbResult && thumbResult.success) thumbUrl = thumbResult.url;
      } catch (thumbErr) {
        log.warn('CDN thumb upload failed for identity avatar', { error: thumbErr.message });
      }

      // No CDN-failure fallback path exists above (a failed upload throws
      // before this line), so the CDN URL is always available here — no need
      // to duplicate the image bytes into MySQL as well.
      await pool.query('UPDATE email_identities SET avatar_url = ?, avatar_url_thumb = ?, avatar = NULL WHERE id = ?', [result.url, thumbUrl, req.params.id]);
      log.adm('Identity avatar updated', { identity_id: req.params.id, admin_id: req.user.id });
      reply.send({ ok: true, message: 'Identity avatar updated successfully', url: result.url });
    } catch (err) {
      log.err('Identity avatar upload error', err);
      reply.status(500).json({ error: 'Error processing or saving avatar' });
    }
  });

  /* -------------------- Avatar Routes -------------------- */

  fastify.get('/api/users/:id/avatar', async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT avatar_url, avatar_url_thumb, avatar FROM users WHERE id = ?', [req.params.id]);
      if (rows.length === 0) return reply.status(404).send('Avatar not found');

      const targetUrl = (req.query.size === 'thumb' && rows[0].avatar_url_thumb) ? rows[0].avatar_url_thumb
        : rows[0].avatar_url ? rows[0].avatar_url
          : (typeof rows[0].avatar === 'string' && rows[0].avatar.startsWith('http')) ? rows[0].avatar
            : null;

      if (targetUrl) {
        reply.header('Cache-Control', 'public, max-age=86400');
        return reply.redirect(targetUrl);
      }

      if (!rows[0].avatar) return reply.status(404).send('Avatar not found');

      const mime = getMimeType(rows[0].avatar);
      reply.header('Content-Type', mime);
      reply.header('Cache-Control', 'public, max-age=86400'); // Cache for 1 day
      reply.send(rows[0].avatar);
    } catch (e) {
      log.err('Avatar GET error', { message: e.message });
      reply.status(500).send({ error: 'Server error retrieving avatar.' });
    }
  });

  fastify.put('/api/users/:id/avatar', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      if (req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
        return reply.status(403).send({ error: 'Forbidden. You can only update your own avatar.' });
      }
      const fileData = await req.file();
      if (!fileData) {
        return reply.status(400).send({ error: 'No image file provided.' });
      }
      const rawBuffer = await fileData.toBuffer();

      const buffer = await sharp(rawBuffer)
        .resize(500, 500, { fit: 'cover' })
        .webp({ quality: 80 })
        .toBuffer();
      // Small variant for the many small render contexts (admin rows, chat,
      // nav) that were downloading this same 500x500 file before — see
      // migrations/list/0011_avatar_thumb_urls.js.
      const thumbBuffer = await sharp(rawBuffer)
        .resize(160, 160, { fit: 'cover' })
        .webp({ quality: 80 })
        .toBuffer();

      const filename = "users_" + req.params.id + ".jpg";
      const result = await imageClient.uploadImage(buffer, filename);
      if (!result || !result.success) throw new Error((result && result.error) || 'CDN upload failed');
      const avatarUrl = result.url;

      // Best-effort: the main avatar already succeeded above, so a failed
      // thumb upload shouldn't fail the whole request.
      let avatarUrlThumb = null;
      try {
        const thumbResult = await imageClient.uploadImage(thumbBuffer, "users_" + req.params.id + "_thumb.jpg");
        if (thumbResult && thumbResult.success) avatarUrlThumb = thumbResult.url;
      } catch (imgErr) {
        log.warn('CDN thumb upload failed', { error: imgErr.message });
      }

      // CDN-only — no BLOB fallback (see migrate-avatars-to-cdn.js for the
      // one-off cleanup of any avatars still stored as bytes from before).
      await pool.query('UPDATE users SET avatar_url = ?, avatar_url_thumb = ?, avatar = NULL WHERE id = ?', [avatarUrl, avatarUrlThumb, req.params.id]);
      reply.send({ success: true, message: 'Avatar updated successfully.', url: avatarUrl });
    } catch (e) {
      log.err('Avatar PUT error', { message: e.message, stack: e.stack });
      reply.status(500).send({ error: 'Server error updating avatar.' });
    }
  });
};
