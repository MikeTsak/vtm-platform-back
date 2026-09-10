// utils/compression.js
//
// A response-compression onSend hook — gzip / brotli for text responses.
//
// Why this is hand-rolled instead of `@fastify/compress` in global mode:
// almost every handler in this codebase ends with a bare `reply.send(x)`
// (or `reply.status(n).json(x)`) rather than `return reply.send(x)` — ~490
// call sites. `@fastify/compress`'s global hook makes `reply.send()` resolve
// asynchronously, so those handlers' promises settle as `undefined` while the
// reply is still in flight and Fastify ships a second, empty response — the
// client gets `Content-Encoding: gzip`, `Content-Length: 0`, no body. That is
// exactly why compression has been dead in this app (see the history in
// plugins/security.js).
//
// A *synchronous* onSend hook doesn't have that problem: the whole onSend
// chain runs in the same tick, before the handler's promise resolution is
// processed, so `reply.send(x)` still behaves synchronously from Fastify's
// point of view. zlib's sync deflate is cheap at these payload sizes —
// measured ~1ms (gzip) / ~3ms (brotli q5) for a 290 KB response, the largest
// this API produces — so blocking the event loop for it is a non-issue here
// and buys a 70–90% smaller body on every list endpoint.
//
// SSE endpoints (banner.js, maintenance.js) and the log file stream
// (adminLogs.js) write to `reply.raw` directly and never reach this hook.

const zlib = require('zlib');

// Bodies below this aren't worth a content-encoding round trip.
const MIN_BYTES = 1024;
// Above this, skip rather than risk a long synchronous stall. Nothing this
// API returns as JSON is anywhere near this; it's a guard, not a normal path.
const MAX_BYTES = 5 * 1024 * 1024;

// Only text-shaped payloads compress usefully. Images, video, PDFs, fonts and
// anything already-compressed are skipped (and several are served straight
// from the DB as BLOBs — re-deflating them would just burn CPU).
const COMPRESSIBLE_TYPE =
  /^\s*(?:text\/|application\/(?:json|ld\+json|manifest\+json|javascript|xml)\b|image\/svg\+xml)/i;

const GZIP_OPTS = { level: 6 };
const BROTLI_OPTS = { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } };

// Returns 'br', 'gzip', or null. Honours an explicit `;q=0` opt-out and
// prefers brotli (roughly half the bytes of gzip on this API's JSON).
function pickEncoding(header) {
  if (!header) return null;
  const h = String(header).toLowerCase();
  if (/(?:^|,)\s*br\b/.test(h) && !/\bbr\s*;\s*q=0(?:\.0+)?\b/.test(h)) return 'br';
  if (/(?:^|,)\s*gzip\b/.test(h) && !/\bgzip\s*;\s*q=0(?:\.0+)?\b/.test(h)) return 'gzip';
  return null;
}

function compressionHook(request, reply, payload, done) {
  try {
    if (payload == null) return done(null, payload);
    // Streams (static files, log tails) — leave them alone.
    if (typeof payload.pipe === 'function') return done(null, payload);
    if (typeof payload !== 'string' && !Buffer.isBuffer(payload)) return done(null, payload);
    // Already encoded upstream (e.g. a pre-gzipped BLOB) — don't double-wrap.
    if (reply.hasHeader('content-encoding')) return done(null, payload);
    if (!COMPRESSIBLE_TYPE.test(String(reply.getHeader('content-type') || ''))) {
      return done(null, payload);
    }

    // This resource's bytes depend on Accept-Encoding — tell shared caches so,
    // whether or not this particular response ends up compressed.
    reply.header('vary', 'accept-encoding');

    const buf = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
    if (buf.length < MIN_BYTES || buf.length > MAX_BYTES) return done(null, payload);

    const encoding = pickEncoding(request.headers['accept-encoding']);
    if (!encoding) return done(null, payload);

    const compressed =
      encoding === 'br'
        ? zlib.brotliCompressSync(buf, BROTLI_OPTS)
        : zlib.gzipSync(buf, GZIP_OPTS);

    reply.header('content-encoding', encoding);
    // Let Fastify recompute Content-Length from the compressed buffer; several
    // handlers set it by hand off the uncompressed payload.
    reply.removeHeader('content-length');
    return done(null, compressed);
  } catch {
    // Never let a compression failure sink an otherwise-good response.
    return done(null, payload);
  }
}

module.exports = { compressionHook, pickEncoding, COMPRESSIBLE_TYPE, MIN_BYTES };
