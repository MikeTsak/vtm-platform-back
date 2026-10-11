// utils/loginThrottle.js
//
// Per-account guard against password guessing. The IP limiter (services/guards.js
// authLimiter) cannot stop an attacker who spreads guesses over many IPs at one
// player's account; this counts failed logins per email regardless of IP.
// Unknown emails are counted too, so the 429 never reveals whether an account exists.
//
// Trade-off: someone can also lock a victim out for the window by failing on purpose.
// The victim can still reset their password by email, which is not throttled here.
// ponytail: in-memory and per-process like the IP limiter; share via DB/Redis if >1 process.

const MAX_FAILS = 10;
const WINDOW_MS = 15 * 60_000;
const fails = new Map(); // email -> { count, resetAt }

const key = (email) => String(email || '').trim().toLowerCase();

function live(k) {
  const h = fails.get(k);
  if (h && h.resetAt <= Date.now()) { fails.delete(k); return null; }
  return h || null;
}

/** Seconds until the account may try again, or 0 if it may try now. */
function retryAfter(email) {
  const h = live(key(email));
  return h && h.count >= MAX_FAILS ? Math.ceil((h.resetAt - Date.now()) / 1000) : 0;
}

function recordFailure(email) {
  const k = key(email);
  if (fails.size > 5000) for (const x of fails.keys()) live(x);
  const h = live(k) || { count: 0, resetAt: Date.now() + WINDOW_MS };
  h.count += 1;
  fails.set(k, h);
}

function clear(email) {
  fails.delete(key(email));
}

module.exports = { MAX_FAILS, retryAfter, recordFailure, clear };
