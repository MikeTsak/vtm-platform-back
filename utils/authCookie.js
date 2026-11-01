// utils/authCookie.js
//
// Centralizes how the session JWT is stored in the browser: an httpOnly
// cookie instead of a value the frontend keeps in localStorage and
// re-attaches itself. httpOnly means client-side JS (including an
// attacker's injected script) cannot read the token at all, which is the
// whole point — see the stored-XSS fix in features/news, /rumors, etc.

const COOKIE_NAME = 'token';
const MAX_AGE_SECONDS = 7 * 24 * 60 * 60; // mirrors the JWT's own 7d expiresIn

// The frontend (portal.attlarp.gr) and API (api.attlarp.gr) are same-site in
// production (same registrable domain, attlarp.gr) — this used to be a
// genuinely cross-site relationship when the API lived on a different
// domain (miketsak.gr), which is precisely what broke login on Safari,
// every iOS browser (all forced onto WebKit, so subject to the same ITP
// third-party-cookie blocking as Safari), and Chrome Incognito: those
// browsers block third-party cookies outright regardless of SameSite, and
// no client-side fix works around that — only same-site fixes it for real.
//
// SameSite=Lax, now that it's same-site. It used to be None+Secure "to stay
// correct if the API ever moved domains again", but None is exactly what lets
// any other website ride the session: CORS only stops a foreign page READING
// responses, not SENDING a form-encoded/multipart/text-plain POST — so an
// auto-submitting form could ratify a Blood Hunt or leave a coterie as whoever
// visited it. Lax keeps the cookie on every same-site request (portal, wiki,
// h., attlarp.gr itself) and drops it on cross-site POSTs. Native clients
// (Android app, erebus-mobile) use Bearer tokens and are unaffected.
// If the API is ever split onto a different registrable domain again, this
// has to go back to None AND every mutation needs a CSRF token or custom header.
//
// Secure is decided below: local dev runs over plain http://127.0.0.1 (Vite
// proxies /api same-origin; changeOrigin: true rewrites the Host header the
// backend sees to 127.0.0.1), every real host gets Secure.
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
  return {
    httpOnly: true,
    secure: isCrossSiteHttps(req),
    sameSite: 'lax',
    path: '/',
  };
}

function setAuthCookie(req, reply, token, maxAge = MAX_AGE_SECONDS) {
  reply.setCookie(COOKIE_NAME, token, { ...cookieOptions(req), maxAge });
}

function clearAuthCookie(req, reply) {
  reply.clearCookie(COOKIE_NAME, cookieOptions(req));
}

module.exports = { COOKIE_NAME, setAuthCookie, clearAuthCookie };
