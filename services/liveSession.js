// services/liveSession.js
//
// Live sessions are addressed by an 8-character DDMMYY## code in URLs, but
// joined on an INT id in the database. Shared by the HTTP routes and the
// socket.io join_session handler.

const pool = require('../db');

async function getSessionInternalId(codeOrId) {
  const [rows] = await pool.query('SELECT id FROM live_sessions WHERE session_code=? OR id=?', [codeOrId, codeOrId]);
  return rows[0]?.id;
}

module.exports = { getSessionInternalId };
