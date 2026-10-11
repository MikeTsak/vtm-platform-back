// routes/anonymousNotes.js
//
// Anonymous notes: one-off messages a Storyteller drops into a player's
// Surface Web. The sender is never exposed to players and notes cannot be
// replied to. Body is rich-text HTML (sanitised client-side like emails);
// images are CDN urls uploaded through /api/admin/notes/upload.

const MAX_IMAGES = 10;
const MAX_IMAGE_BYTES = 20 * 1024 * 1024;
const MAX_BODY_CHARS = 100000;

function parseImages(raw) {
  try {
    const arr = JSON.parse(raw || '[]');
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, imageClient, sendPushNotification } = opts;

  // emails:refresh drives the nav's Surface Web badge, so notes ride it too.
  const signal = (userId) => {
    if (fastify.io) fastify.io.to(`user_${userId}`).emit('emails:refresh', { type: 'note' });
  };

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

  fastify.post('/api/notes/:id/read', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [res] = await pool.query(
        'UPDATE anonymous_notes SET read_at = NOW() WHERE id = ? AND user_id = ? AND read_at IS NULL',
        [req.params.id, req.user.id]
      );
      if (res.affectedRows) signal(req.user.id);
      reply.send({ ok: true });
    } catch (e) {
      log.err('Failed to mark anonymous note read', { message: e.message });
      reply.status(500).send({ error: 'Failed to mark read' });
    }
  });

  // --- ADMIN ---

  fastify.post('/api/admin/notes/upload', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const file = await req.file();
      if (!file) return reply.status(400).send({ error: 'File is required' });
      if (!(file.mimetype || '').startsWith('image/')) return reply.status(400).send({ error: 'Only images can be attached' });

      const buffer = await file.toBuffer();
      if (buffer.length > MAX_IMAGE_BYTES) return reply.status(400).send({ error: 'Image too large (max 20MB)' });

      const ext = (file.filename || '').split('.').pop().toLowerCase().replace(/[^a-z0-9]/g, '') || 'jpg';
      const result = await imageClient.uploadImage(buffer, `anonymous_notes_${Date.now()}.${ext}`);
      if (!result?.success) throw new Error(result?.error || 'CDN upload failed');

      reply.send({ url: result.url });
    } catch (e) {
      log.err('Anonymous note image upload failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to upload image' });
    }
  });

  fastify.post('/api/admin/notes', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { user_ids, body } = req.body || {};
      const ids = [...new Set((Array.isArray(user_ids) ? user_ids : []).map(Number).filter(n => Number.isInteger(n) && n > 0))];
      const images = (Array.isArray(req.body?.images) ? req.body.images : [])
        .filter(u => typeof u === 'string' && /^https?:\/\//i.test(u));
      const text = typeof body === 'string' ? body : '';
      const hasText = text.replace(/<[^>]*>|&nbsp;/g, '').trim().length > 0;

      if (!ids.length) return reply.status(400).send({ error: 'Pick at least one recipient' });
      if (!hasText && !images.length) return reply.status(400).send({ error: 'A note needs text or an image' });
      if (images.length > MAX_IMAGES) return reply.status(400).send({ error: `At most ${MAX_IMAGES} images` });
      if (text.length > MAX_BODY_CHARS) return reply.status(400).send({ error: 'Note is too long' });

      const [found] = await pool.query('SELECT id FROM users WHERE id IN (?)', [ids]);
      if (found.length !== ids.length) return reply.status(400).send({ error: 'Unknown recipient' });

      const imagesJson = images.length ? JSON.stringify(images) : null;
      await pool.query(
        'INSERT INTO anonymous_notes (user_id, sender_id, body, images) VALUES ?',
        [ids.map(uid => [uid, req.user.id, hasText ? text : null, imagesJson])]
      );

      for (const uid of ids) {
        signal(uid);
        sendPushNotification(uid, 'Erebus Portal - Anonymous note', 'Someone left you a note.', { url: '/surfaceweb?tab=notes' }, 'chat').catch(() => { });
      }

      log.adm('Admin sent anonymous note', { admin: req.user.id, recipients: ids, images: images.length });
      reply.status(201).send({ ok: true, count: ids.length });
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
               (SELECT c.name FROM characters c WHERE c.user_id = u.id ORDER BY c.id LIMIT 1) AS char_name
        FROM anonymous_notes n
        JOIN users u ON u.id = n.user_id
        ORDER BY n.created_at DESC, n.id DESC
        LIMIT 500
      `);
      reply.send({ notes: rows.map(r => ({ ...r, images: parseImages(r.images) })) });
    } catch (e) {
      log.err('Admin list anonymous notes failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load notes' });
    }
  });

  fastify.delete('/api/admin/notes/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [[note]] = await pool.query('SELECT user_id FROM anonymous_notes WHERE id = ?', [req.params.id]);
      if (!note) return reply.status(404).send({ error: 'Note not found' });
      await pool.query('DELETE FROM anonymous_notes WHERE id = ?', [req.params.id]);
      signal(note.user_id);
      log.adm('Admin deleted anonymous note', { admin: req.user.id, id: Number(req.params.id) });
      reply.send({ ok: true });
    } catch (e) {
      log.err('Admin delete anonymous note failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to delete note' });
    }
  });
};
