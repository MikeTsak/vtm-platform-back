// services/liveSession.js
//
// Live sessions are addressed by an 8-character DDMMYY## code in URLs, but
// joined on an INT id in the database. Shared by the HTTP routes and the
// socket.io join_session handler.

const pool = require('../db');

async function getSessionRow(codeOrId) {
  if (!codeOrId) return null;
  const [rows] = await pool.query(
    'SELECT id, session_code, status, created_at, duration_seconds FROM live_sessions WHERE session_code=? OR id=? LIMIT 1',
    [codeOrId, codeOrId]
  );
  return rows[0] || null;
}

async function getSessionInternalId(codeOrId) {
  const row = await getSessionRow(codeOrId);
  return row?.id;
}

async function emitSessionRefresh(io, codeOrId) {
  if (!io || !codeOrId) return;
  try {
    const session = await getSessionRow(codeOrId);
    if (session) {
      io.to(`session_${session.id}`).emit('refresh_session');
      if (session.session_code && String(session.session_code) !== String(session.id)) {
        io.to(`session_${session.session_code}`).emit('refresh_session');
      }
    } else {
      io.to(`session_${codeOrId}`).emit('refresh_session');
    }
  } catch (err) {
    // silent fallback
  }
}

// A session nobody ended (the ST forgot) is closed after this long.
// unless the Storyteller flagged it keepOpen in its metadata.
const STALE_SESSION_HOURS = 24;

const parseMeta = (m) => {
  try { return (typeof m === 'string' ? JSON.parse(m) : m) || {}; } catch { return {}; }
};

// Who has the session open right now: users with a socket in its room. The id
// is stashed on socket.data at connect (RemoteSocket has no other user field).
async function onlineUserIds(io, sessionId) {
  if (!io) return new Set();
  const sockets = await io.in(`session_${sessionId}`).fetchSockets();
  return new Set(sockets.map((s) => Number(s.data?.userId)).filter(Boolean));
}

// Light nudge: someone joined/left, reload the roster only.
function emitSessionPresence(io, rooms) {
  if (io && rooms.length) io.to(rooms).emit('session_presence');
}

// Drops one user's sockets out of a session's rooms (kick).
async function removeUserSockets(io, session, userId) {
  if (!io) return;
  const keys = [...new Set([session.id, session.session_code].filter(Boolean))].map((k) => `session_${k}`);
  for (const s of await io.in(keys).fetchSockets()) {
    if (Number(s.data?.userId) === Number(userId)) keys.forEach((k) => s.leave(k));
  }
}

/**
 * Ends an active session: stamps its duration, tells everyone in it to
 * refresh (their screen sees `ended` and leaves), then drops their sockets out
 * of the room so nothing more is delivered. Returns the duration in seconds,
 * or null when the row was already ended.
 */
async function closeSession(io, row, endedBy = null) {
  const duration = Math.max(0, Math.floor((Date.now() - new Date(row.created_at).getTime()) / 1000));
  const [res] = await pool.query(
    "UPDATE live_sessions SET status='ended', ended_at=NOW(), duration_seconds=?, ended_by=? WHERE id=? AND status='active'",
    [duration, endedBy, row.id]
  );
  if (!res.affectedRows) return null;
  await emitSessionRefresh(io, row.id);
  for (const key of new Set([row.id, row.session_code].filter(Boolean))) io?.in(`session_${key}`).socketsLeave(`session_${key}`);
  return duration;
}

async function closeStaleSessions(io) {
  const [rows] = await pool.query(
    "SELECT id, session_code, created_at, metadata FROM live_sessions WHERE status='active' AND created_at < NOW() - INTERVAL ? HOUR",
    [STALE_SESSION_HOURS]
  );
  const stale = rows.filter((row) => !parseMeta(row.metadata).keepOpen);
  for (const row of stale) await closeSession(io, row);
  return stale.length;
}

module.exports = { getSessionInternalId, getSessionRow, emitSessionRefresh, closeSession, closeStaleSessions, onlineUserIds, emitSessionPresence, removeUserSockets };
