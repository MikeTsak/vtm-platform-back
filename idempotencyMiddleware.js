const pool = require('./db');
const { log } = require('./logger');

async function idempotencyMiddleware(req, res, next) {
  // Only apply to state-modifying requests
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const idempotencyKey = req.headers['idempotency-key'];
  if (!idempotencyKey) {
    return next();
  }

  try {
    const [rows] = await pool.query(
      'SELECT response_code, response_body FROM idempotency_keys WHERE idempotency_key = ?',
      [idempotencyKey]
    );

    if (rows.length > 0) {
      log.info(`Idempotency cache hit for key: ${idempotencyKey}`, { path: req.originalUrl });
      const cached = rows[0];
      
      let bodyData = cached.response_body;
      try {
        // If it's stored as a JSON string, try parsing it so we can use res.json correctly.
        bodyData = JSON.parse(cached.response_body);
        return res.status(cached.response_code).json(bodyData);
      } catch (e) {
        // If not JSON, just send it as text/html or whatever it was
        return res.status(cached.response_code).send(bodyData);
      }
    }
  } catch (error) {
    log.error('Error checking idempotency key', { error: error.message });
    return next();
  }

  // Intercept the response
  const originalSend = res.send;
  res.send = function(body) {
    // Restore the original send method
    res.send = originalSend;

    const statusCode = res.statusCode;

    // Only cache successful or client-error responses.
    // Do not cache server crashes (500s) so they can be retried if fixed.
    if (statusCode < 500) {
      const bodyStr = typeof body === 'object' ? JSON.stringify(body) : String(body);
      
      // Determine user_id if authMiddleware has already run
      const userId = req.user ? req.user.id : null;

      pool.query(
        'INSERT INTO idempotency_keys (idempotency_key, user_id, request_path, request_method, response_code, response_body) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE response_code = VALUES(response_code), response_body = VALUES(response_body)',
        [idempotencyKey, userId, req.originalUrl, req.method, statusCode, bodyStr]
      ).catch(err => {
        log.error('Failed to save idempotency response', { error: err.message });
      });
    }

    // Call the original send
    return res.send(body);
  };

  next();
}

module.exports = idempotencyMiddleware;
