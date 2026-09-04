// utils/authCookie.js
//
// Centralizes how the session JWT is stored in the browser: an httpOnly
// cookie instead of a value the frontend keeps in localStorage and
// re-attaches itself. httpOnly means client-side JS (including an
// attacker's injected script) cannot read the token at all, which is the
// whole point — see the stored-XSS fix in features/news, /rumors, etc.

const COOKIE_NAME = 'token';
const MAX_AGE_SECONDS = 7 * 24 * 60 * 60; // mirrors the JWT's own 7d expiresIn

// The frontend (portal.attlarp.gr) and API (vtm.back.miketsak.gr) are on
// different registrable domains in production — a genuinely CROSS-SITE
// relationship, not just cross-origin. SameSite=Lax cookies are never sent
// on cross-site XHR/fetch (only same-site requests and top-level
// navigations), so a Lax cookie there would be set by /login but silently
// never attached to the very next /auth/me call — SameSite=None is required
// for the cookie to work across those two domains at all.
//
// But SameSite=None is only legal paired with Secure — browsers reject it
// outright otherwise — and local dev runs over plain http://127.0.0.1 (Vite
// proxies the frontend's /api calls to the backend same-origin, so it's
// genuinely same-site there; changeOrigin: true in vite.config.js rewrites
// the Host header the backend sees to 127.0.0.1). So Secure and SameSite are
// decided together, from the same signal, rather than independently:
// cross-site production gets None+Secure, same-site local dev gets Lax
// (no Secure requirement, and it's the correct choice for genuinely
// same-site traffic anyway).
//
// This app runs behind a reverse proxy in production (Apache) that
// terminates TLS and forwards plain HTTP to Fastify, so req.protocol alone
// isn't trustworthy there — only X-Forwarded-Proto is, and only if the proxy
// actually sets it (unverified for this deployment). So: trust a
// direct/forwarded https signal when present; otherwise, treat a request
// arriving for localhost/127.0.0.1 as local dev (unambiguous — production
// traffic is never addressed to those hosts) and default to the
// cross-site/secure production behavior for everything else, since silently
// falling back to a cookie that doesn't work cross-site is exactly what
// broke login in production. COOKIE_SECURE=true/false overrides this
// explicitly, for when you *do* know the answer for a given deployment.
function isCrossSiteHttps(req) {
  if (process.env.COOKIE_SECURE !== undefined) return process.env.COOKIE_SECURE === 'true';
  if (req.protocol === 'https') return true;
  const forwarded = req.headers['x-forwarded-proto'];
  if (forwarded && String(forwarded).split(',')[0].trim().toLowerCase() === 'https') return true;
  if (/^(localhost|127\.0\.0\.1|\[::1\])$/i.test(req.hostname || '')) return false;
  return true;
}

function cookieOptions(req) {
  const secure = isCrossSiteHttps(req);
  return {
    httpOnly: true,
    secure,
    sameSite: secure ? 'none' : 'lax',
    path: '/',
  };
}

function setAuthCookie(req, reply, token) {
  reply.setCookie(COOKIE_NAME, token, { ...cookieOptions(req), maxAge: MAX_AGE_SECONDS });
}

function clearAuthCookie(req, reply) {
  reply.clearCookie(COOKIE_NAME, cookieOptions(req));
}

module.exports = { COOKIE_NAME, setAuthCookie, clearAuthCookie };
