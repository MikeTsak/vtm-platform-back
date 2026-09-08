// services/sse.js
//
// Server-Sent Events streams are written straight to the raw socket, which
// bypasses @fastify/cors entirely — so the CORS headers have to be echoed by
// hand. Same allowlist as every other transport (see config/cors.js).

const { corsOrigin } = require('../config/cors');

function sseCorsHeaders(req) {
  const origin = req.headers.origin;
  if (origin && corsOrigin.includes(origin)) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
      Vary: 'Origin',
    };
  }
  return {};
}

module.exports = { sseCorsHeaders };
