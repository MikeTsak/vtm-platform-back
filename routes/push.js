// routes/push.js
//
// Web-push and Expo subscription management, per-category preferences, and a
// test send.
const { VAPID_PUBLIC_KEY } = require('../services/push');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, sendPushNotification } = opts;

  // --- NEW ROUTE to save a subscription ---
  // --- PUSH: UPSERT SUB, TEST SEND, UNSUBSCRIBE ---

  // Save/Upsert subscription (auth required)
  fastify.post('/api/push/subscribe', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { subscription } = req.body || {};

      // Validate that we actually received a proper subscription object
      if (!subscription || !subscription.endpoint) {
        return reply.status(400).json({ error: 'Valid subscription with endpoint is required' });
      }

      const endpoint = subscription.endpoint;
      const json = JSON.stringify(subscription);

      // Upsert by endpoint, so repeated toggles don't duplicate
      await pool.query(
        `INSERT INTO push_subscriptions (user_id, endpoint, subscription_json)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), subscription_json=VALUES(subscription_json)`,
        [req.user.id, endpoint, json]
      );

      log.ok('Push subscription upserted', { user_id: req.user.id });
      reply.status(201).json({ ok: true });
    } catch (e) {
      log.err('Push subscribe failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to save subscription' });
    }
  });

  // Unsubscribe: delete by endpoint (auth required)
  fastify.post('/api/push/unsubscribe', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { endpoint } = req.body || {};
      if (!endpoint) return reply.status(400).json({ error: 'endpoint is required' });

      await pool.query('DELETE FROM push_subscriptions WHERE user_id=? AND endpoint=?', [req.user.id, endpoint]);
      log.ok('Push subscription removed', { user_id: req.user.id });
      reply.send({ ok: true });
    } catch (e) {
      log.err('Push unsubscribe failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to remove subscription' });
    }
  });



  // Fire a test push to current user (auth required)
  fastify.post('/api/push/test', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { category } = req.body || {};
      const notifCategory = category === 'chat' ? 'chat' : 'system';
      await sendPushNotification(req.user.id, `🔔 Test: ${notifCategory.toUpperCase()}`, `If you can read this, background ${notifCategory} push works!`, { url: '/comms', tag: 'push-test' }, notifCategory);
      reply.send({ ok: true });
    } catch (e) {
      log.err('Push test failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to send test push' });
    }
  });

  // GET /api/push/vapidPublicKey
  fastify.get('/api/push/vapidPublicKey', (req, reply) => {
    reply.send({ publicKey: VAPID_PUBLIC_KEY });
  });

  // GET /api/push/settings
  fastify.get('/api/push/settings', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT push_settings FROM users WHERE id=?', [req.user.id]);
      let settings = { chat: false, system: false };
      if (rows[0] && rows[0].push_settings) {
        try {
          settings = typeof rows[0].push_settings === 'string'
            ? JSON.parse(rows[0].push_settings)
            : rows[0].push_settings;
          // Clean up corrupted numeric keys
          for (const key of Object.keys(settings)) {
            if (!isNaN(key)) delete settings[key];
          }
        } catch (e) { }
      }
      reply.send(settings);
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch settings' });
    }
  });

  // PUT /api/push/settings
  fastify.put('/api/push/settings', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { settings } = req.body;

      // Fetch existing settings
      const [rows] = await pool.query('SELECT push_settings FROM users WHERE id=?', [req.user.id]);
      const currentSettings = rows[0].push_settings || { chat: false, system: false };

      // Merge new settings
      const newSettings = { ...currentSettings, ...settings };

      await pool.query('UPDATE users SET push_settings=? WHERE id=?', [JSON.stringify(newSettings), req.user.id]);
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to save settings' });
    }
  });

  // PWA Web Push Subscription (auth required)
  fastify.post('/api/push/web-subscribe', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { subscription } = req.body || {};
      if (!subscription || !subscription.endpoint) {
        return reply.status(400).json({ error: 'Valid subscription required' });
      }

      await pool.query(
        `INSERT INTO user_push_subscriptions (user_id, endpoint, p256dh, auth)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE user_id=VALUES(user_id)`,
        [req.user.id, subscription.endpoint, subscription.keys.p256dh, subscription.keys.auth]
      );

      reply.status(201).json({ ok: true });
    } catch (e) {
      log.err('Web Push subscribe failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to save subscription' });
    }
  });
};
