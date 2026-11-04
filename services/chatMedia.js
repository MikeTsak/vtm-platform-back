// services/chatMedia.js
//
// Chat images live on the image host (img.miketsak.gr, services/media.js) since
// 2026-11-04: a chat_media row keeps who uploaded it (access checks in
// routes/chat.js) and the image's URL in data_url, and serving it is a redirect.
// Before, the bytes sat in the row's data column, which made every nightly
// backup bigger. Voice messages still do: the host takes images only.
//
// The host renames each upload (img_<uniqid with entropy>.webp) and lists no
// directory, so a chat image opens only for someone given its link.
const pool = require('../db');
const { imageClient } = require('./media');
const { isAdmin } = require('./guards');

// A chat_media row is visible to whoever uploaded it, or to a participant of a
// message (DM / group / NPC) that has it as its attachment_id, never to anyone
// who merely guesses its numeric id. Admins see everything (moderation). The
// send routes check it too (services/chatForward.js): attaching an id makes
// the attachment visible to that chat, so nobody may attach one they can't see.
async function canAccessChatMedia(mediaId, user) {
  if (!mediaId || !user) return false;
  if (isAdmin(user)) return true;
  const [rows] = await pool.query(
    `SELECT 1 FROM chat_media WHERE id = ? AND uploader_id = ?
     UNION
     SELECT 1 FROM chat_messages WHERE attachment_id = ? AND (sender_id = ? OR recipient_id = ?)
     UNION
     SELECT 1 FROM npc_messages WHERE attachment_id = ? AND user_id = ?
     UNION
     SELECT 1 FROM chat_group_messages gm
       JOIN chat_group_members mem ON mem.group_id = gm.group_id AND mem.user_id = ?
     WHERE gm.attachment_id = ?
     LIMIT 1`,
    [mediaId, user.id, mediaId, user.id, user.id, mediaId, user.id, user.id, mediaId]
  );
  return rows.length > 0;
}

const EXT = { jpeg: 'jpg', 'svg+xml': 'svg' };
const extFor = (mime) => { const t = String(mime || '').split('/')[1] || 'webp'; return EXT[t] || t; };

// Uploads one image; returns its URL or throws.
async function uploadChatImage(buffer, filename) {
  const r = await imageClient.uploadImage(buffer, filename);
  if (!r?.success || !r.url) throw new Error(r?.error || 'the image host refused the upload');
  return r.url;
}

// The row's image URL: data_url, or (some old rows) a URL saved in data itself.
function storedUrl(row) {
  if (row.data_url) return row.data_url;
  const d = row.data;
  const head = Buffer.isBuffer(d) ? d.subarray(0, 8).toString('utf8') : typeof d === 'string' ? d.slice(0, 8) : '';
  return /^https?:\/\//.test(head) ? String(d) : null;
}

// Moves up to `limit` images still stored in the database to the image host
// (jobs/index.js 'chat-media-offload', a batch per run, so a big backlog never
// loads the server at once). A failed upload leaves its row as it was, to be
// tried again next run. Returns { moved, failed, left, error }.
async function offloadChatImages(limit = 25) {
  const pending = "data_url IS NULL AND data IS NOT NULL AND mime LIKE 'image/%'";
  const [rows] = await pool.query(`SELECT id, mime, data FROM chat_media WHERE ${pending} ORDER BY id LIMIT ?`, [limit]);
  let moved = 0, failed = 0, error = null;
  for (const row of rows) {
    try {
      const url = storedUrl(row) || await uploadChatImage(row.data, `chat_${row.id}.${extFor(row.mime)}`);
      await pool.query('UPDATE chat_media SET data_url = ?, data = NULL WHERE id = ? AND data_url IS NULL', [url, row.id]);
      moved += 1;
    } catch (e) {
      failed += 1;
      error = error || `#${row.id}: ${e.message}`;
    }
  }
  const [[{ n }]] = await pool.query(`SELECT COUNT(*) AS n FROM chat_media WHERE ${pending}`);
  return { moved, failed, left: Number(n), error };
}

module.exports = { uploadChatImage, storedUrl, offloadChatImages, canAccessChatMedia };
