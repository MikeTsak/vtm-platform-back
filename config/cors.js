// config/cors.js
//
// The single source of truth for which origins may talk to this API. Shared by
// the HTTP CORS plugin, the socket.io handshake, and the hand rolled SSE
// headers: those three used to be configured independently, which is how an
// origin ends up allowed on one transport and blocked on another.
//
// Auth travels as an httpOnly cookie (credentials: true), so: unlike a
// Bearer token API: reflecting *any* calling origin would let an arbitrary
// website ride a logged in visitor's session cookie. Never fall back to
// "allow all"; fall back to the known app origins instead.

const PRODUCTION_ORIGINS = [
  'https://portal.attlarp.gr',
  'https://wiki.attlarp.gr',
  'https://h.attlarp.gr',
];

const LOCAL_ORIGINS = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:3001',
  'http://127.0.0.1:3001',
  'http://localhost:3002',
  'http://127.0.0.1:3002',
  'http://localhost:3003',
  'http://127.0.0.1:3003',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
];

function isLocalOrigin(origin) {
  return /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(origin);
}

function resolveAllowedOrigins() {
  const rawEnv = (process.env.NODE_ENV || '').toLowerCase().trim();
  const isExplicitDev = rawEnv === 'development' || rawEnv === 'dev' || rawEnv === 'test' || rawEnv === 'staging';
  const explicitAllow = process.env.ALLOW_LOCALHOST !== undefined
    ? process.env.ALLOW_LOCALHOST === 'true'
    : (process.env.CORS_ALLOW_LOCALHOST !== undefined ? process.env.CORS_ALLOW_LOCALHOST === 'true' : undefined);

  // Secure by default: allow localhost ONLY in development or when explicitly enabled.
  // Deployed production environments (production, stable, or unset on server) automatically block localhost.
  const shouldAllowLocalhost = explicitAllow !== undefined ? explicitAllow : isExplicitDev;

  let origins;
  if (process.env.CORS_ORIGIN) {
    origins = process.env.CORS_ORIGIN.split(',').map((o) => o.trim()).filter(Boolean);
  } else {
    origins = shouldAllowLocalhost
      ? [...PRODUCTION_ORIGINS, ...LOCAL_ORIGINS]
      : [...PRODUCTION_ORIGINS];
  }

  if (!shouldAllowLocalhost) {
    origins = origins.filter((origin) => !isLocalOrigin(origin));
  } else {
    for (const localOrigin of LOCAL_ORIGINS) {
      if (!origins.includes(localOrigin)) {
        origins.push(localOrigin);
      }
    }
  }

  return origins;
}

const corsOrigin = resolveAllowedOrigins();
const DEFAULT_CORS_ORIGINS = corsOrigin;

module.exports = {
  PRODUCTION_ORIGINS,
  LOCAL_ORIGINS,
  DEFAULT_CORS_ORIGINS,
  corsOrigin,
  isLocalOrigin,
  resolveAllowedOrigins,
};
