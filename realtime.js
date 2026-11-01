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
const { getAuthState } = require('./utils/tokenVersion');
const { isAdmin, isCourt } = require('./services/guards');
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
      const state = await getAuthState(payload.id);
      if (!state || (payload.tv ?? 0) !== state.version) {
        return next(new Error('Session revoked'));
      }

      socket.user = { ...payload, role: state.role };
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
      if (isCourt(socket.user)) {
        socket.join('admin_chat');
      }

      // A debug session (routes/debugLogin.js) must not show the player online.
      if (!socket.user.imp) {
        // Admins are who answer as NPCs, so clients use them for NPC presence.
        const entry = presence.get(uid) || { count: 0, admin: isAdmin(socket.user) };
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

    // The handshake is the only auth check a socket gets, so without this a
    // revoked session (password reset, "log out everywhere"), an expired JWT or
    // a demoted courtuser kept its live feed and the admin_chat room for as long
    // as the tab stayed open. Re-validated against the DB (getAuthState is the
    // same 15 s-cached read authRequired uses) rather than disconnected from the
    // revoking route, because that route may run in another Passenger process.
    if (uid) {
      const recheck = setInterval(async () => {
        let state;
        try { state = await getAuthState(uid); } catch { return; } // DB hiccup: keep the socket
        const expired = socket.user.exp && Date.now() >= socket.user.exp * 1000;
        if (!state || state.version !== (socket.user.tv ?? 0) || expired) {
          socket.disconnect(true);
          return;
        }
        if (state.role !== socket.user.role) {
          socket.user = { ...socket.user, role: state.role };
          if (isCourt(socket.user)) socket.join('admin_chat');
          else socket.leave('admin_chat');
        }
      }, 60_000);
      socket.on('disconnect', () => clearInterval(recheck));
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
        const isStaff = isCourt(socket.user);
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
  });

  fastify.decorate('io', io);
  return io;
}

module.exports = { attachRealtime };
