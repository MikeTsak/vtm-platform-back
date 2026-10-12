// routes/anonymousNotes.js
//
// Anonymous notes: one-off messages a Storyteller drops into a player's
// Comms > Anonymous Notes tab. The sender is never exposed to players and notes
// cannot be replied to. Body is rich text, sanitised before it is stored;
// images are CDN urls uploaded through /api/admin/notes/upload.
//
// Read receipts: the first time a player opens a note, every admin's open
// Notes tab refreshes (socket) and admins subscribed on ntfy get a push. A
// debug-login session (imp) never counts as the player reading it.

const { sanitizeRichText } = require('../utils/sanitize');

const MAX_IMAGES = 10;
const MAX_IMAGE_BYTES = 20 * 1024 * 1024;
const MAX_BODY_CHARS = 100000;
const MAX_RECIPIENTS = 200;
const MAX_URL_CHARS = 2048;
const DUPLICATE_WINDOW_SEC = 30;

const toId = (v) => { const n = Number(v); return Number.isInteger(n) && n > 0 ? n : null; };
const plainText = (html) => (html || '').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();

function parseImages(raw) {
  try {
    const arr = JSON.parse(raw || '[]');
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

function isHttpUrl(u) {
  if (typeof u !== 'string' || u.length > MAX_URL_CHARS) return false;
  try {
    const { protocol } = new URL(u);
    return protocol === 'http:' || protocol === 'https:';
  } catch {
    return false;
  }
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, imageClient, sharp, sendPushNotification, broadcastNtfyAlert, moderateLimiter, uploadLimiter } = opts;
  const limited = (...pre) => pre.filter(Boolean);

  // One refresh signal for both sides: the recipient's open tabs / nav badge,
  // and every admin's Notes list (admin_chat carries no note data).
  const signal = (userId) => {
    if (!fastify.io) return;
    fastify.io.to(`user_${userId}`).emit('notes:refresh');
    fastify.io.to('admin_chat').emit('notes:refresh');
  };

  async function notifyRead(noteId, userId) {
    const [[row]] = await pool.query(
      `SELECT n.body, n.images,
              COALESCE((SELECT c.name FROM characters c WHERE c.user_id = u.id ORDER BY c.id LIMIT 1), u.display_name) AS who,
              s.display_name AS sender
       FROM anonymous_notes n
       JOIN users u ON u.id = n.user_id
       LEFT JOIN users s ON s.id = n.sender_id
       WHERE n.id = ?`,
      [noteId]
    );
    if (!row) return;
    const text = plainText(row.body).slice(0, 120) || (parseImages(row.images).length ? 'Image' : '');
    let msg = `**${row.who}** has read an anonymous note`;
    if (row.sender) msg += ` sent by **${row.sender}**`;
    if (text) msg += `:\n\n> *${text}*`;
    await Promise.resolve(broadcastNtfyAlert?.(msg, {
      title: 'Anonymous Note Read',
      tags: 'eyes,vampire',
      priority: 'default',
      requiresSubscription: 'notes',
    })).catch(() => { });
  }

  // --- PLAYER ---

  fastify.get('/api/notes/mine', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(
        `SELECT id, body, images, read_at, created_at FROM anonymous_notes
         WHERE user_id = ? ORDER BY created_at DESC, id DESC`,
        [req.user.id]
      );
      reply.header('Cache-Control', 'no-store');
      reply.send({ notes: rows.map(r => ({ ...r, images: parseImages(r.images) })) });
    } catch (e) {
      log.err('Failed to load anonymous notes', { message: e.message });
      reply.status(500).send({ error: 'Failed to load notes' });
    }
  });

  // Drives the nav: the Anonymous Notes link shows once total > 0, badge = unread.
  fastify.get('/api/notes/summary', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [[row]] = await pool.query(
        'SELECT COUNT(*) AS total, COALESCE(SUM(read_at IS NULL), 0) AS unread FROM anonymous_notes WHERE user_id = ?',
        [req.user.id]
      );
      reply.header('Cache-Control', 'no-store');
      reply.send({ total: Number(row.total), unread: Number(row.unread) });
    } catch (e) {
      log.err('Failed to summarise anonymous notes', { message: e.message });
      reply.status(500).send({ error: 'Failed to load notes' });
    }
  });

  fastify.post('/api/notes/:id/read', { preHandler: [authRequired] }, async (req, reply) => {
    const id = toId(req.params.id);
    if (!id) return reply.status(400).send({ error: 'Invalid note id' });
    // An admin debugging as a player must not fire the player's read receipt.
    if (req.user.imp) return reply.send({ ok: true });
    try {
      const [res] = await pool.query(
        'UPDATE anonymous_notes SET read_at = NOW() WHERE id = ? AND user_id = ? AND read_at IS NULL',
        [id, req.user.id]
      );
      if (res.affectedRows) {
        signal(req.user.id);
        notifyRead(id, req.user.id).catch(e => log.err('Anonymous note read receipt failed', { message: e.message }));
      }
      reply.send({ ok: true });
    } catch (e) {
      log.err('Failed to mark anonymous note read', { message: e.message });
      reply.status(500).send({ error: 'Failed to mark read' });
    }
  });

  // --- ADMIN ---

  fastify.post('/api/admin/notes/upload', { preHandler: limited(authRequired, requireAdmin, uploadLimiter) }, async (req, reply) => {
    try {
      const file = await req.file();
      if (!file) return reply.status(400).send({ error: 'File is required' });
      if (!(file.mimetype || '').startsWith('image/')) return reply.status(400).send({ error: 'Only images can be attached' });

      const buffer = await file.toBuffer();
      if (file.file?.truncated || buffer.length > MAX_IMAGE_BYTES) return reply.status(400).send({ error: 'Image too large (max 20MB)' });

      // The mimetype header is client-supplied; make sure the bytes really decode as an image.
      if (sharp) {
        try { await sharp(buffer).metadata(); } catch { return reply.status(400).send({ error: 'File is not a valid image' }); }
      }

      const ext = (file.filename || '').split('.').pop().toLowerCase().replace(/[^a-z0-9]/g, '') || 'jpg';
      const result = await imageClient.uploadImage(buffer, `anonymous_notes_${Date.now()}.${ext}`);
      if (!result?.success) throw new Error(result?.error || 'CDN upload failed');

      reply.send({ url: result.url });
    } catch (e) {
      log.err('Anonymous note image upload failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to upload image' });
    }
  });

  fastify.post('/api/admin/notes', { preHandler: limited(authRequired, requireAdmin, moderateLimiter) }, async (req, reply) => {
    try {
      const { user_ids, body } = req.body || {};
      const ids = [...new Set((Array.isArray(user_ids) ? user_ids : []).map(toId).filter(Boolean))];
      const images = [...new Set(Array.isArray(req.body?.images) ? req.body.images.filter(isHttpUrl) : [])];
      const text = sanitizeRichText(typeof body === 'string' ? body : '');
      const hasText = plainText(text).length > 0 || /<img\b/i.test(text);

      if (!ids.length) return reply.status(400).send({ error: 'Pick at least one recipient' });
      if (ids.length > MAX_RECIPIENTS) return reply.status(400).send({ error: `At most ${MAX_RECIPIENTS} recipients` });
      if (!hasText && !images.length) return reply.status(400).send({ error: 'A note needs text or an image' });
      if (images.length > MAX_IMAGES) return reply.status(400).send({ error: `At most ${MAX_IMAGES} images` });
      if (text.length > MAX_BODY_CHARS) return reply.status(400).send({ error: 'Note is too long' });

      const [found] = await pool.query('SELECT id FROM users WHERE id IN (?)', [ids]);
      if (found.length !== ids.length) return reply.status(400).send({ error: 'Unknown recipient' });

      const storedBody = hasText ? text : null;
      const imagesJson = images.length ? JSON.stringify(images) : null;

      // Double-click / retry guard: don't re-send the identical note to someone who just got it.
      const [dupes] = await pool.query(
        `SELECT DISTINCT user_id FROM anonymous_notes
         WHERE sender_id = ? AND user_id IN (?) AND created_at > (NOW() - INTERVAL ${DUPLICATE_WINDOW_SEC} SECOND)
           AND body <=> ? AND images <=> ?`,
        [req.user.id, ids, storedBody, imagesJson]
      );
      const seen = new Set(dupes.map(d => d.user_id));
      const fresh = ids.filter(id => !seen.has(id));

      if (fresh.length) {
        await pool.query(
          'INSERT INTO anonymous_notes (user_id, sender_id, body, images) VALUES ?',
          [fresh.map(uid => [uid, req.user.id, storedBody, imagesJson])]
        );
      }

      for (const uid of fresh) {
        signal(uid);
        Promise.resolve(sendPushNotification?.(uid, 'Erebus Portal - Anonymous note', 'Someone left you a note.', { url: '/notes' }, 'chat')).catch(() => { });
      }

      log.adm('Admin sent anonymous note', { admin: req.user.id, recipients: fresh, skipped_duplicates: ids.length - fresh.length, images: images.length });
      reply.status(201).send({ ok: true, count: fresh.length, duplicates: ids.length - fresh.length });
    } catch (e) {
      log.err('Failed to send anonymous note', { message: e.message });
      reply.status(500).send({ error: 'Failed to send note' });
    }
  });

  fastify.get('/api/admin/notes', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
        SELECT n.id, n.user_id, n.body, n.images, n.read_at, n.created_at,
               u.display_name,
               (SELECT c.name FROM characters c WHERE c.user_id = u.id ORDER BY c.id LIMIT 1) AS char_name,
               n.sender_id, s.display_name AS sender_name
        FROM anonymous_notes n
        JOIN users u ON u.id = n.user_id
        LEFT JOIN users s ON s.id = n.sender_id
        ORDER BY n.created_at DESC, n.id DESC
        LIMIT 500
      `);
      reply.header('Cache-Control', 'no-store');
      reply.send({ notes: rows.map(r => ({ ...r, images: parseImages(r.images) })) });
    } catch (e) {
      log.err('Admin list anonymous notes failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load notes' });
    }
  });

  fastify.delete('/api/admin/notes/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const id = toId(req.params.id);
    if (!id) return reply.status(400).send({ error: 'Invalid note id' });
    try {
      const [[note]] = await pool.query('SELECT user_id FROM anonymous_notes WHERE id = ?', [id]);
      if (!note) return reply.status(404).send({ error: 'Note not found' });
      await pool.query('DELETE FROM anonymous_notes WHERE id = ?', [id]);
      signal(note.user_id);
      log.adm('Admin deleted anonymous note', { admin: req.user.id, id });
      reply.send({ ok: true });
    } catch (e) {
      log.err('Admin delete anonymous note failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to delete note' });
    }
  });
};
