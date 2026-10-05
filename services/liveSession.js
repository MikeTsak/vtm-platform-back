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

module.exports = { getSessionInternalId, getSessionRow, emitSessionRefresh };
