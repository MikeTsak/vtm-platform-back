// config/cors.js
//
// The single source of truth for which origins may talk to this API. Shared by
// the HTTP CORS plugin, the socket.io handshake, and the hand-rolled SSE
// headers — those three used to be configured independently, which is how an
// origin ends up allowed on one transport and blocked on another.
//
// Auth travels as an httpOnly cookie (credentials: true), so — unlike a
// Bearer-token API — reflecting *any* calling origin would let an arbitrary
// website ride a logged-in visitor's session cookie. Never fall back to
// "allow all"; fall back to the known app origins instead.

const DEFAULT_CORS_ORIGINS = [
  'https://portal.attlarp.gr',
  'http://localhost:3002',
  'http://127.0.0.1:3002',
  'https://h.attlarp.gr',
  'http://localhost:5173',
];

// In production, set CORS_ORIGIN to your frontend URL (comma-separated for
// more than one).
const corsOrigin = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map((o) => o.trim())
  : DEFAULT_CORS_ORIGINS;

module.exports = { DEFAULT_CORS_ORIGINS, corsOrigin };
