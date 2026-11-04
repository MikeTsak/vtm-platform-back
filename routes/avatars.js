// routes/avatars.js
//
// Avatar read/write for every portrait-bearing entity (users, NPCs, retainers,
// email identities). Uploads are resized and pushed to the image CDN.

const crypto = require('crypto');
const axios = require('axios');
const { isOwnerOrAdmin } = require('../services/guards');

// The GET routes normally 302 to the image CDN (img.miketsak.gr), which sends
// no CORS header. That's fine for a plain <img>, but the Domains map reads
// avatar pixels into a WebGL texture (deck.gl IconLayer) and a canvas — that
// needs the bytes served same-origin. Call the endpoint with ?raw=1 and it
// proxies the CDN image through instead of redirecting.
//
// A ?raw=1 caller opted out of the redirect specifically because it can't use
// one (its fetch() runs in 'cors' mode with no credentials, and a 302 to a
// host with no CORS header is opaque and unusable). Falling back to that same
// redirect on proxy failure — the previous behavior — silently reintroduces
// the exact failure it asked to avoid: the client gets what looks like a
// normal response but can never actually read it. On a slow/lossy mobile
// connection the round trip here (client → this server → CDN → this server)
// is far more likely to blow the 10s upstream timeout than on a fast desktop
// link, so this path fires disproportionately on mobile — that's the "avatars
// never load on my phone" bug. A real failure status lets the client's own
// retry wrapper (fetchAvatarWithRetry) try again through the same working
// channel instead of being funneled into a dead end every time.
//
// Caching: /api/<entity>/:id/avatar is a stable URL whose target changes on
// every upload (the CDN names each upload uniquely). It used to be cached for a
// day, so after a new upload the browser kept showing the old portrait, and
// only on the variants it had already cached (full vs ?size=thumb vs ?raw=1):
// the home page and the sheet disagreed, players re-uploaded, and everyone else
// saw the old face for up to 24 h. Now the browser revalidates every time and
// gets a 304 while the target is unchanged; the CDN image itself (immutable,
// unique URL) stays cached normally.
async function sendAvatar(req, reply, log, targetUrl) {
  const etag = `"${crypto.createHash('sha1').update(targetUrl).digest('base64url')}"`;
  reply.header('Cache-Control', 'no-cache');
  reply.header('ETag', etag);
  if (req.headers['if-none-match'] === etag) return reply.status(304).send();

  if (wantsRaw(req)) {
    try {
      const up = await axios.get(targetUrl, { responseType: 'arraybuffer', timeout: 10000 });
      reply.header('Content-Type', up.headers['content-type'] || 'image/webp');
      return reply.send(Buffer.from(up.data));
    } catch (err) {
      log.warn('Avatar raw proxy failed', { url: targetUrl, error: err.message });
      return reply.status(502).send('Avatar proxy failed');
    }
  }
  return reply.redirect(targetUrl);
}

// Legacy avatars still stored as bytes: same stale-cache problem, no ETag needed.
function sendAvatarBlob(reply, getMimeType, blob) {
  reply.header('Content-Type', getMimeType(blob));
  reply.header('Cache-Control', 'no-cache');
  return reply.send(blob);
}

function sendAvatarNotFound(reply) {
  reply.header('Cache-Control', 'public, max-age=120');
  return reply.status(404).send('Avatar not found');
}

// In-memory negative cache for missing avatars to prevent repetitive DB queries during rapid request bursts.
const missingAvatarCache = new Map();
const MISSING_CACHE_TTL_MS = 60000;

function isAvatarMissingCached(key) {
  const expiresAt = missingAvatarCache.get(key);
  if (!expiresAt) return false;
  if (Date.now() > expiresAt) {
    missingAvatarCache.delete(key);
    return false;
  }
  return true;
}

function setAvatarMissingCached(key) {
  if (missingAvatarCache.size > 2000) missingAvatarCache.clear();
  missingAvatarCache.set(key, Date.now() + MISSING_CACHE_TTL_MS);
}

function clearAvatarMissingCached(key) {
  missingAvatarCache.delete(key);
}

const wantsRaw = (req) => req.query.raw === '1' || req.query.raw === 'true';

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, getMimeType, imageClient, sharp } = opts;

  fastify.get('/api/npcs/:id/avatar', async (req, reply) => {
    try {
      const cacheKey = `npc:${req.params.id}`;
      if (isAvatarMissingCached(cacheKey)) return sendAvatarNotFound(reply);

      const [rows] = await pool.query('SELECT avatar_url, avatar_url_thumb, avatar FROM npcs WHERE id = ?', [req.params.id]);
      if (rows.length === 0) {
        setAvatarMissingCached(cacheKey);
        return sendAvatarNotFound(reply);
      }

      const targetUrl = (req.query.size === 'thumb' && rows[0].avatar_url_thumb) ? rows[0].avatar_url_thumb
        : rows[0].avatar_url ? rows[0].avatar_url
          : (typeof rows[0].avatar === 'string' && rows[0].avatar.startsWith('http')) ? rows[0].avatar
            : null;

      if (targetUrl) return sendAvatar(req, reply, log, targetUrl);
      if (!rows[0].avatar) {
        setAvatarMissingCached(cacheKey);
        return sendAvatarNotFound(reply);
      }
      return sendAvatarBlob(reply, getMimeType, rows[0].avatar);
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
      clearAvatarMissingCached(`npc:${req.params.id}`);
      reply.send({ success: true, message: 'NPC Avatar updated successfully.', url: avatarUrl });
    } catch (e) {
      log.err('NPC Avatar PUT error', { message: e.message });
      reply.status(500).send({ error: 'Server error updating npc avatar.' });
    }
  });

  // GET retainer avatar
  fastify.get('/api/retainers/:id/avatar', async (req, reply) => {
    try {
      const cacheKey = `retainer:${req.params.id}`;
      if (isAvatarMissingCached(cacheKey)) return sendAvatarNotFound(reply);

      const [rows] = await pool.query('SELECT avatar_url, avatar_url_thumb, avatar FROM retainers WHERE id = ?', [req.params.id]);
      if (rows.length === 0) {
        setAvatarMissingCached(cacheKey);
        return sendAvatarNotFound(reply);
      }
      const targetUrl = (req.query.size === 'thumb' && rows[0].avatar_url_thumb) ? rows[0].avatar_url_thumb
        : rows[0].avatar_url ? rows[0].avatar_url
          : (typeof rows[0].avatar === 'string' && rows[0].avatar.startsWith('http')) ? rows[0].avatar
            : null;
      if (targetUrl) return sendAvatar(req, reply, log, targetUrl);
      if (!rows[0].avatar) {
        setAvatarMissingCached(cacheKey);
        return sendAvatarNotFound(reply);
      }
      return sendAvatarBlob(reply, getMimeType, rows[0].avatar);
    } catch (e) {
      log.err('Failed to get retainer avatar', { error: e.message });
      reply.status(500).send('Server Error');
    }
  });

  // PUT retainer avatar
  fastify.put('/api/retainers/:id/avatar', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      // Personal retainer: the character's player. Coterie retainer: any member.
      const [[owner]] = await pool.query(
        `SELECT c.user_id, r.coterie_id,
                EXISTS(SELECT 1 FROM coterie_members m WHERE m.coterie_id = r.coterie_id AND m.user_id = ?) AS is_member
           FROM retainers r LEFT JOIN characters c ON c.id = r.character_id WHERE r.id = ?`,
        [req.user.id, req.params.id]
      );
      if (!owner) return reply.status(404).send({ error: 'Retainer not found' });
      if (!(owner.coterie_id ? isOwnerOrAdmin(req.user, owner.is_member ? req.user.id : null) : isOwnerOrAdmin(req.user, owner.user_id))) {
        return reply.status(403).send({ error: 'Not your retainer' });
      }

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
      clearAvatarMissingCached(`retainer:${req.params.id}`);
      reply.send({ success: true, url: avatarUrl });
    } catch (e) {
      log.err('Failed to update retainer avatar', { error: e.message });
      reply.status(500).send({ error: 'Failed to update avatar' });
    }
  });

  /* -------------------- Identity Avatars -------------------- */

  fastify.get('/api/identities/:id/avatar', async (req, reply) => {
    try {
      const cacheKey = `identity:${req.params.id}`;
      if (isAvatarMissingCached(cacheKey)) return sendAvatarNotFound(reply);

      // No `avatar` blob column here (see the PUT handler below): identity
      // avatars have only ever gone through the CDN, so there's no legacy
      // blob data to fall back to for this table the way there is for
      // users/npcs/retainers.
      const [rows] = await pool.query('SELECT avatar_url, avatar_url_thumb FROM email_identities WHERE id = ?', [req.params.id]);
      if (rows.length === 0) {
        setAvatarMissingCached(cacheKey);
        return sendAvatarNotFound(reply);
      }

      const targetUrl = (req.query.size === 'thumb' && rows[0].avatar_url_thumb) ? rows[0].avatar_url_thumb
        : rows[0].avatar_url ? rows[0].avatar_url
          : null;

      if (targetUrl) return sendAvatar(req, reply, log, targetUrl);
      setAvatarMissingCached(cacheKey);
      return sendAvatarNotFound(reply);
    } catch (err) {
      log.err('Identity avatar fetch error', err);
      reply.status(500).send('Error fetching avatar');
    }
  });

  fastify.put('/api/identities/:id/avatar', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const fileData = await req.file();
      if (!fileData) {
        return reply.status(400).send({ error: 'No image file provided.' });
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
      // to duplicate the image bytes into MySQL as well. email_identities
      // has no `avatar` blob column (see GET above) — nothing to clear.
      await pool.query('UPDATE email_identities SET avatar_url = ?, avatar_url_thumb = ? WHERE id = ?', [result.url, thumbUrl, req.params.id]);
      clearAvatarMissingCached(`identity:${req.params.id}`);
      log.adm('Identity avatar updated', { identity_id: req.params.id, admin_id: req.user.id });
      reply.send({ ok: true, message: 'Identity avatar updated successfully', url: result.url });
    } catch (err) {
      log.err('Identity avatar upload error', err);
      // This route is admin-only (requireAdmin above), so the real error is
      // safe to surface — it's what actually lets an admin tell a bad image
      // file apart from a CDN outage apart from a DB/schema problem without
      // needing to go pull server logs for every failed upload.
      reply.status(500).send({ error: `Error processing or saving avatar: ${err.message}` });
    }
  });

  /* -------------------- Avatar Routes -------------------- */

  fastify.get('/api/users/:id/avatar', async (req, reply) => {
    try {
      const cacheKey = `user:${req.params.id}`;
      if (isAvatarMissingCached(cacheKey)) return sendAvatarNotFound(reply);

      const [rows] = await pool.query('SELECT avatar_url, avatar_url_thumb, avatar FROM users WHERE id = ?', [req.params.id]);
      if (rows.length === 0) {
        setAvatarMissingCached(cacheKey);
        return sendAvatarNotFound(reply);
      }

      const targetUrl = (req.query.size === 'thumb' && rows[0].avatar_url_thumb) ? rows[0].avatar_url_thumb
        : rows[0].avatar_url ? rows[0].avatar_url
          : (typeof rows[0].avatar === 'string' && rows[0].avatar.startsWith('http')) ? rows[0].avatar
            : null;

      if (targetUrl) return sendAvatar(req, reply, log, targetUrl);
      if (!rows[0].avatar) {
        setAvatarMissingCached(cacheKey);
        return sendAvatarNotFound(reply);
      }
      return sendAvatarBlob(reply, getMimeType, rows[0].avatar);
    } catch (e) {
      log.err('Avatar GET error', { message: e.message });
      reply.status(500).send({ error: 'Server error retrieving avatar.' });
    }
  });

  fastify.put('/api/users/:id/avatar', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      if (!isOwnerOrAdmin(req.user, req.params.id)) {
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
      clearAvatarMissingCached(`user:${req.params.id}`);
      reply.send({ success: true, message: 'Avatar updated successfully.', url: avatarUrl });
    } catch (e) {
      log.err('Avatar PUT error', { message: e.message, stack: e.stack });
      reply.status(500).send({ error: 'Server error updating avatar.' });
    }
  });
};
