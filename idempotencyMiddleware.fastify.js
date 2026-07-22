const fp = require('fastify-plugin');
const pool = require('./db');
const { log } = require('./logger');

async function idempotencyPlugin(fastify, options) {
  // PreHandler: check if idempotency key exists
  fastify.addHook('preHandler', async (request, reply) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return;

    const idempotencyKey = request.headers['idempotency-key'];
    if (!idempotencyKey) return;

    try {
      const [rows] = await pool.query(
        'SELECT response_code, response_body FROM idempotency_keys WHERE idempotency_key = ?',
        [idempotencyKey]
      );

      if (rows.length > 0) {
        log.info(`Idempotency cache hit for key: ${idempotencyKey}`, { path: request.url });
        const cached = rows[0];
        let bodyData = cached.response_body;
        try {
          bodyData = JSON.parse(cached.response_body);
        } catch (e) {
          // not json
        }
        reply.status(cached.response_code).send(bodyData);
        return reply; // return reply to short-circuit in Fastify
      }
    } catch (error) {
      log.error('Error checking idempotency key', { error: error.message });
    }
  });

  // onSend: save the response
  fastify.addHook('onSend', async (request, reply, payload) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return payload;

    const idempotencyKey = request.headers['idempotency-key'];
    if (!idempotencyKey) return payload;

    const statusCode = reply.statusCode;
    if (statusCode < 500) {
      const userId = request.user ? request.user.id : null;
      pool.query(
        'INSERT INTO idempotency_keys (idempotency_key, user_id, request_path, request_method, response_code, response_body) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE response_code = VALUES(response_code), response_body = VALUES(response_body)',
        [idempotencyKey, userId, request.url, request.method, statusCode, typeof payload === 'string' ? payload : JSON.stringify(payload)]
      ).catch(err => {
        log.error('Failed to save idempotency response', { error: err.message });
      });
    }

    return payload;
  });
}

module.exports = fp(idempotencyPlugin);
