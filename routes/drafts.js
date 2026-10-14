// routes/drafts.js
//
// Comms drafts: messages a player writes while SchreckNet / Surface Web is
// closed. They sit in a drawer on top of the conversation and are never sent
// automatically: the player sends, copies or deletes each one by hand once
// comms reopen. Sending goes through the normal chat/email endpoints (the
// client deletes the draft afterwards), so drafts never bypass those checks.
// Private to their author: there is no admin view.
//
// A draft is addressed by { kind, id }:
//   user / group / npc  a SchreckNet conversation (key from convKey())
//   email               a reply in an email thread the player owns  ('e:<id>')
//   email-new           a new email, with to_address + subject       ('e:new')
//
// Every change emits drafts:refresh to the author's own room, so a draft
// written on the phone shows up on the open PC tab.

const { convKey } = require('../utils/chatConversation');
const { isAdmin: checkIsAdmin } = require('../services/guards');
const { sanitizeRichText } = require('../utils/sanitize');

const MAX_CHAT_CHARS = 10000;
const MAX_EMAIL_CHARS = 100000;
const MAX_DRAFTS_PER_USER = 300;
const MAX_FIELD_CHARS = 255;

const toId = (v) => { const n = Number(v); return Number.isInteger(n) && n > 0 ? n : null; };
const plainText = (html) => (html || '').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').trim();

// The client's { kind, id } back from a stored key, for the per-conversation
// counts shown in the contact list / inbox.
function decodeKey(key, me) {
  const [k, a, b] = String(key).split(':');
  if (k === 'u') return { kind: 'user', id: Number(a) === me ? Number(b) : Number(a) };
  if (k === 'g') return { kind: 'group', id: Number(a) };
  if (k === 'n') return { kind: 'npc', id: Number(a) };
  if (k === 'e') return a === 'new' ? { kind: 'email-new', id: null } : { kind: 'email', id: Number(a) };
  return null;
}

const shape = (row, me) => ({
  id: row.id,
  kind: decodeKey(row.conv_key, me)?.kind,
  target_id: decodeKey(row.conv_key, me)?.id,
  body: row.body,
  subject: row.subject,
  to_address: row.to_address,
  created_at: row.created_at,
  updated_at: row.updated_at,
});

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired } = opts;

  const signal = (userId) => fastify.io?.to(`user_${userId}`).emit('drafts:refresh');

  // Where a draft lives, or { error } when this player can't write there.
  async function resolveTarget(req, kind, rawId) {
    const me = Number(req.user.id);
    if (kind === 'email-new') return { key: 'e:new', email: true };
    const id = toId(rawId);
    if (!id) return { error: 400 };
    if (kind === 'user') {
      if (id === me) return { error: 400 };
      const [rows] = await pool.query('SELECT 1 FROM users WHERE id=?', [id]);
      return rows.length ? { key: convKey('user', me, id) } : { error: 404 };
    }
    if (kind === 'group') {
      const [rows] = await pool.query('SELECT 1 FROM chat_group_members WHERE group_id=? AND user_id=?', [id, me]);
      return rows.length ? { key: convKey('group', id) } : { error: 403 };
    }
    if (kind === 'npc') {
      // A Storyteller speaking as an NPC has the Send Later queue instead.
      if (checkIsAdmin(req.user)) return { error: 400 };
      const [rows] = await pool.query('SELECT 1 FROM npcs WHERE id=? AND IFNULL(is_disabled, 0) = 0', [id]);
      return rows.length ? { key: convKey('npc', id, me) } : { error: 404 };
    }
    if (kind === 'email') {
      const [rows] = await pool.query('SELECT 1 FROM email_threads WHERE id=? AND user_id=?', [id, me]);
      return rows.length ? { key: `e:${id}`, email: true } : { error: 404 };
    }
    return { error: 400 };
  }

  // Validates and normalises the editable fields. Chat drafts are plain text
  // (the chat renders text); email drafts are rich text, sanitised the same
  // way an email body is before it reaches the editor again.
  function cleanFields(input, email, isNew) {
    let body = typeof input.body === 'string' ? input.body : '';
    if (email) body = sanitizeRichText(body);
    if (body.length > (email ? MAX_EMAIL_CHARS : MAX_CHAT_CHARS)) return { error: 'Draft is too long' };
    const out = { body };
    if (isNew) {
      out.subject = String(input.subject || '').trim().slice(0, MAX_FIELD_CHARS) || null;
      out.to_address = String(input.to_address || '').trim().slice(0, MAX_FIELD_CHARS) || null;
    }
    const hasText = email ? plainText(body) : body.trim();
    if (!hasText && !out.subject) return { error: 'Draft is empty' };
    return out;
  }

  // All of the player's drafts for one conversation, oldest first (the order
  // they were written in).
  fastify.get('/api/drafts', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const target = await resolveTarget(req, req.query.kind, req.query.id);
      if (target.error) return reply.status(target.error).send({ error: 'Conversation not found' });
      const [rows] = await pool.query(
        'SELECT * FROM comms_drafts WHERE user_id=? AND conv_key=? ORDER BY created_at ASC, id ASC',
        [req.user.id, target.key]
      );
      reply.send({ drafts: rows.map(r => shape(r, Number(req.user.id))) });
    } catch (e) {
      log.err('Failed to load drafts', { message: e.message });
      reply.status(500).send({ error: 'Failed to load drafts' });
    }
  });

  // Draft counts per conversation, for the badges in the contact list / inbox.
  fastify.get('/api/drafts/summary', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const me = Number(req.user.id);
      const [rows] = await pool.query(
        'SELECT conv_key, COUNT(*) AS n, MAX(created_at) AS last_at FROM comms_drafts WHERE user_id=? GROUP BY conv_key',
        [me]
      );
      const counts = rows
        .map(r => ({ ...decodeKey(r.conv_key, me), count: Number(r.n), last_at: r.last_at }))
        .filter(r => r.kind);
      reply.send({ counts, total: counts.reduce((s, r) => s + r.count, 0) });
    } catch (e) {
      log.err('Failed to load draft summary', { message: e.message });
      reply.status(500).send({ error: 'Failed to load drafts' });
    }
  });

  // created_at is accepted only to put an undone delete back where it was.
  fastify.post('/api/drafts', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const input = req.body || {};
      const target = await resolveTarget(req, input.kind, input.id);
      if (target.error) return reply.status(target.error).send({ error: 'Conversation not found' });
      const fields = cleanFields(input, !!target.email, target.key === 'e:new');
      if (fields.error) return reply.status(400).send({ error: fields.error });

      const [[{ n }]] = await pool.query('SELECT COUNT(*) AS n FROM comms_drafts WHERE user_id=?', [req.user.id]);
      if (n >= MAX_DRAFTS_PER_USER) return reply.status(400).send({ error: `You can keep up to ${MAX_DRAFTS_PER_USER} drafts. Send or delete some first.` });

      const restoredAt = input.created_at ? new Date(input.created_at) : null;
      const createdAt = restoredAt && !Number.isNaN(restoredAt.getTime()) && restoredAt <= new Date() ? restoredAt : new Date();

      const [r] = await pool.query(
        'INSERT INTO comms_drafts (user_id, conv_key, body, subject, to_address, created_at) VALUES (?,?,?,?,?,?)',
        [req.user.id, target.key, fields.body, fields.subject || null, fields.to_address || null, createdAt]
      );
      const [[row]] = await pool.query('SELECT * FROM comms_drafts WHERE id=?', [r.insertId]);
      signal(req.user.id);
      reply.send({ draft: shape(row, Number(req.user.id)) });
    } catch (e) {
      log.err('Failed to save draft', { message: e.message });
      reply.status(500).send({ error: 'Failed to save draft' });
    }
  });

  fastify.put('/api/drafts/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const id = toId(req.params.id);
      const [[row]] = await pool.query('SELECT * FROM comms_drafts WHERE id=? AND user_id=?', [id, req.user.id]);
      if (!row) return reply.status(404).send({ error: 'Draft not found' });
      const email = row.conv_key.startsWith('e:');
      const fields = cleanFields(req.body || {}, email, row.conv_key === 'e:new');
      if (fields.error) return reply.status(400).send({ error: fields.error });

      await pool.query(
        'UPDATE comms_drafts SET body=?, subject=?, to_address=? WHERE id=?',
        [fields.body, fields.subject ?? null, fields.to_address ?? null, id]
      );
      const [[updated]] = await pool.query('SELECT * FROM comms_drafts WHERE id=?', [id]);
      signal(req.user.id);
      reply.send({ draft: shape(updated, Number(req.user.id)) });
    } catch (e) {
      log.err('Failed to update draft', { message: e.message });
      reply.status(500).send({ error: 'Failed to update draft' });
    }
  });

  fastify.delete('/api/drafts/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [r] = await pool.query('DELETE FROM comms_drafts WHERE id=? AND user_id=?', [toId(req.params.id), req.user.id]);
      if (!r.affectedRows) return reply.status(404).send({ error: 'Draft not found' });
      signal(req.user.id);
      reply.send({ ok: true });
    } catch (e) {
      log.err('Failed to delete draft', { message: e.message });
      reply.status(500).send({ error: 'Failed to delete draft' });
    }
  });
};
