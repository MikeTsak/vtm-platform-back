// utils/authCookie.js
//
// Centralizes how the session JWT is stored in the browser: an httpOnly,
// SameSite=Lax cookie instead of a value the frontend keeps in localStorage
// and re-attaches itself. httpOnly means client-side JS (including an
// attacker's injected script) cannot read the token at all, which is the
// whole point — see the stored-XSS fix in features/news, /rumors, etc.

const COOKIE_NAME = 'token';
const MAX_AGE_SECONDS = 7 * 24 * 60 * 60; // mirrors the JWT's own 7d expiresIn

// The site is always served over HTTPS in production, but local dev runs
// over plain http://localhost — a `Secure` cookie would silently never be
// set (and never sent back) there. Rather than hardcode an environment
// assumption, look at how *this* request actually arrived: directly over
// TLS, or forwarded as HTTPS by the reverse proxy in front of the API.
function isHttpsRequest(req) {
  if (req.protocol === 'https') return true;
  const forwarded = req.headers['x-forwarded-proto'];
  if (forwarded && String(forwarded).split(',')[0].trim().toLowerCase() === 'https') return true;
  return false;
}

function setAuthCookie(req, reply, token) {
  reply.setCookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: isHttpsRequest(req),
    sameSite: 'lax', // same-site XHR + top-level nav only; blocks classic cross-site form CSRF
    path: '/',
    maxAge: MAX_AGE_SECONDS,
  });
}

function clearAuthCookie(reply) {
  reply.clearCookie(COOKIE_NAME, { path: '/' });
}

module.exports = { COOKIE_NAME, setAuthCookie, clearAuthCookie };
