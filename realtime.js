// realtime.js
//
// socket.io: authentication, room membership, and the chat relay.
//
// Must be called before fastify.listen() — it decorates the instance with
// `io`, and route modules reach realtime through `fastify.io` / `req.server.io`.

const { Server } = require('socket.io');
const { parse: parseCookieHeader } = require('cookie');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const { log } = require('./logger');
const { corsOrigin } = require('./config/cors');
const { COOKIE_NAME } = require('./utils/authCookie');
const { getTokenVersion } = require('./utils/tokenVersion');
const { getSessionInternalId } = require('./services/liveSession');

function attachRealtime(fastify) {
  const io = new Server(fastify.server, {
    // Matches the HTTP CORS policy: an explicit origin allowlist + credentials,
    // never '*' — the handshake now carries the httpOnly session cookie.
    cors: { origin: corsOrigin, credentials: true },
  });

  // Reject socket connections without a valid, non-revoked session (mirrors authRequired for HTTP routes).
  // The client no longer hands us a token explicitly (it's httpOnly, so page JS
  // can't read it) — we read it straight off the handshake's Cookie header,
  // exactly like a normal HTTP request would. `auth.token` is kept as a fallback
  // for non-browser clients that authenticate via Bearer token instead of cookies.
  io.use(async (socket, next) => {
    try {
      const cookies = parseCookieHeader(socket.handshake.headers?.cookie || '');
      const token = cookies[COOKIE_NAME] || socket.handshake.auth?.token;
      if (!token) return next(new Error('Authentication required'));

      const payload = jwt.verify(token, process.env.JWT_SECRET);
      const currentVersion = await getTokenVersion(payload.id);
      if (currentVersion === null || (payload.tv ?? 0) !== currentVersion) {
        return next(new Error('Session revoked'));
      }

      socket.user = payload;
      next();
    } catch (e) {
      next(new Error('Authentication failed'));
    }
  });

  io.on('connection', (socket) => {
    // Real-time chat: automatically join authenticated user's private room
    if (socket.user?.id) {
      socket.join(`user_${socket.user.id}`);
      if (socket.user.role === 'admin' || socket.user.role === 'courtuser') {
        socket.join('admin_chat');
      }
    }

    // Real-time group chat rooms
    socket.on('join_group', async (groupId) => {
      try {
        if (!groupId || !socket.user?.id) return;
        const [rows] = await pool.query(
          'SELECT 1 FROM chat_group_members WHERE group_id = ? AND user_id = ? LIMIT 1',
          [groupId, socket.user.id]
        );
        if (rows.length > 0) {
          socket.join(`group_${groupId}`);
        }
      } catch (e) {
        log.err('Socket join_group failed', { error: e.message });
      }
    });

    socket.on('leave_group', (groupId) => {
      if (groupId) socket.leave(`group_${groupId}`);
    });

    socket.on('join_session', async (sessionId) => {
      try {
        if (!sessionId) return;

        // STs (admin/courtuser) may join any session; everyone else must be a registered participant
        if (socket.user.role === 'admin' || socket.user.role === 'courtuser') {
          socket.join(`session_${sessionId}`);
          return;
        }

        const internalId = await getSessionInternalId(sessionId);
        if (!internalId) return;

        const [rows] = await pool.query(
          'SELECT 1 FROM live_session_participants WHERE session_id = ? AND user_id = ? LIMIT 1',
          [internalId, socket.user.id]
        );
        if (rows.length > 0) {
          socket.join(`session_${sessionId}`);
        }
      } catch (e) {
        log.err('Socket join_session failed', { error: e.message });
      }
    });

    socket.on('chat_message', (payload) => {
      if (!payload || !payload.sessionId) return;
      const room = `session_${payload.sessionId}`;
      // socket.rooms is server-maintained state — the only way into a room is
      // the membership-checked join_session handler above, so this is an
      // authoritative check that this socket was actually let into this
      // session, not something a client can fake by just sending a sessionId.
      if (!socket.rooms.has(room)) return;

      // Overwrite (not merge-if-missing) sender identity from the verified
      // socket.user, discarding whatever the client put in the payload —
      // otherwise any authenticated socket could put an arbitrary sender in
      // the payload and impersonate someone else in a session it may not even
      // belong to.
      io.to(room).emit('chat_message', {
        ...payload,
        senderId: socket.user.id,
        senderName: socket.user.display_name,
      });
    });
  });

  fastify.decorate('io', io);
  return io;
}

module.exports = { attachRealtime };
