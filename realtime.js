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
const { getSessionRow, emitSessionPresence } = require('./services/liveSession');

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

  // Presence for SchreckNet's online dots: userId -> { count, admin }, where
  // count is open sockets (tabs/devices). "Online" = has the site open.
  // ponytail: in-memory and per-process, like the socket rooms themselves;
  // needs a shared adapter (e.g. Redis) if the server ever runs >1 process.
  const presence = new Map();
  const presenceSnapshot = () => {
    const online = [];
    const admins = [];
    for (const [id, p] of presence) {
      online.push(id);
      if (p.admin) admins.push(id);
    }
    return { online, admins };
  };

  io.on('connection', (socket) => {
    // Real-time chat: automatically join authenticated user's private room
    const uid = socket.user?.id ? Number(socket.user.id) : null;
    if (uid) {
      socket.data.userId = uid; // readable on RemoteSocket (fetchSockets), unlike socket.user
      socket.join(`user_${uid}`);
      if (socket.user.role === 'admin' || socket.user.role === 'courtuser') {
        socket.join('admin_chat');
      }

      // A debug session (routes/debugLogin.js) must not show the player online.
      if (!socket.user.imp) {
        // Admins are who answer as NPCs, so clients use them for NPC presence.
        const entry = presence.get(uid) || { count: 0, admin: socket.user.role === 'admin' };
        entry.count += 1;
        presence.set(uid, entry);
        if (entry.count === 1) io.emit('presence:update', { userId: uid, online: true, admin: entry.admin });

        socket.on('disconnect', () => {
          const e = presence.get(uid);
          if (!e) return;
          e.count -= 1;
          if (e.count <= 0) {
            presence.delete(uid);
            io.emit('presence:update', { userId: uid, online: false, admin: e.admin });
          }
        });
      }
    }

    socket.on('presence:get', (ack) => {
      if (typeof ack === 'function') ack(presenceSnapshot());
    });

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

        const session = await getSessionRow(sessionId);
        if (!session || session.status === 'ended') return;

        // STs (admin/courtuser) may join any session; everyone else must be a registered participant
        const isStaff = socket.user.role === 'admin' || socket.user.role === 'courtuser';
        if (!isStaff) {
          const [rows] = await pool.query(
            'SELECT 1 FROM live_session_participants WHERE session_id = ? AND user_id = ? LIMIT 1',
            [session.id, socket.user.id]
          );
          if (rows.length === 0) return;
        }

        socket.join(`session_${session.id}`);
        if (session.session_code && String(session.session_code) !== String(session.id)) {
          socket.join(`session_${session.session_code}`);
        }
        socket.join(`session_${sessionId}`);
        emitSessionPresence(io, [`session_${session.id}`]);
      } catch (e) {
        log.err('Socket join_session failed', { error: e.message });
      }
    });

    // Tell a session's roster someone dropped, after a grace period so a flaky
    // connection that bounces straight back doesn't flicker.
    socket.on('disconnecting', () => {
      const rooms = [...socket.rooms].filter((r) => /^session_\d+$/.test(r));
      if (rooms.length) setTimeout(() => emitSessionPresence(io, rooms), 3000);
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
