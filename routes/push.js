// routes/push.js
//
// Web-push and Expo subscription management, per-category preferences, and a
// test send.
const { VAPID_PUBLIC_KEY, PUSH_CATEGORIES, parseSettings, effectiveSettings } = require('../services/push');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, sendPushNotification } = opts;

  // --- NEW ROUTE to save a subscription ---
  // --- PUSH: UPSERT SUB, TEST SEND, UNSUBSCRIBE ---

  // Save/Upsert subscription (auth required)
  fastify.post('/api/push/subscribe', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      // Upserting by endpoint would move the admin's own device onto this player.
      if (req.user.imp) return reply.status(403).send({ error: 'Push subscriptions are disabled in a debug session' });
      const { subscription } = req.body || {};

      // Validate that we actually received a proper subscription object
      if (!subscription || !subscription.endpoint) {
        return reply.status(400).send({ error: 'Valid subscription with endpoint is required' });
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
      reply.status(201).send({ ok: true });
    } catch (e) {
      log.err('Push subscribe failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to save subscription' });
    }
  });

  // Unsubscribe: delete by endpoint (auth required)
  fastify.post('/api/push/unsubscribe', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { endpoint } = req.body || {};
      if (!endpoint) return reply.status(400).send({ error: 'endpoint is required' });

      await pool.query('DELETE FROM push_subscriptions WHERE user_id=? AND endpoint=?', [req.user.id, endpoint]);
      log.ok('Push subscription removed', { user_id: req.user.id });
      reply.send({ ok: true });
    } catch (e) {
      log.err('Push unsubscribe failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to remove subscription' });
    }
  });



  // Fire a test push to current user (auth required)
  fastify.post('/api/push/test', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { category } = req.body || {};
      // A known category tests that category's switch; anything else ('test')
      // is a plain "does this device receive pushes" check, sent regardless.
      const notifCategory = Object.prototype.hasOwnProperty.call(PUSH_CATEGORIES, category) ? category : 'test';
      // Uses your own avatar as the icon so this doubles as a live check that
      // notification icons actually render, not just that push delivery works.
      await sendPushNotification(req.user.id, `Test: ${notifCategory}`, `If you can read this, ${notifCategory === 'test' ? 'notifications reach this device' : `${notifCategory} notifications work`}.`, { url: '/', tag: 'push-test', icon: `/api/users/${req.user.id}/avatar` }, notifCategory);
      reply.send({ ok: true });
    } catch (e) {
      log.err('Push test failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to send test push' });
    }
  });

  // GET /api/push/vapidPublicKey
  fastify.get('/api/push/vapidPublicKey', (req, reply) => {
    reply.send({ publicKey: VAPID_PUBLIC_KEY });
  });

  // GET /api/push/settings: every category's effective on/off (an unset
  // category follows its parent, see PUSH_CATEGORIES in services/push.js).
  fastify.get('/api/push/settings', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [[row]] = await pool.query('SELECT push_settings FROM users WHERE id=?', [req.user.id]);
      reply.send(effectiveSettings(row?.push_settings));
    } catch (e) {
      reply.status(500).send({ error: 'Failed to fetch settings' });
    }
  });

  // PUT /api/push/settings { settings: { category: boolean, ... } }: partial update.
  // Only known categories with real booleans are stored, so the column can't
  // fill up with junk again (a string spread here once grew rows to 75 MB).
  fastify.put('/api/push/settings', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const incoming = req.body?.settings;
      if (!incoming || typeof incoming !== 'object') return reply.status(400).send({ error: 'settings object required' });
      const updates = Object.entries(incoming).filter(([k, v]) => Object.prototype.hasOwnProperty.call(PUSH_CATEGORIES, k) && typeof v === 'boolean');
      if (!updates.length) return reply.status(400).send({ error: 'No known notification categories in request' });

      const [[row]] = await pool.query('SELECT push_settings FROM users WHERE id=?', [req.user.id]);
      const current = parseSettings(row?.push_settings);
      const next = {};
      for (const k of Object.keys(PUSH_CATEGORIES)) if (typeof current[k] === 'boolean') next[k] = current[k];
      for (const [k, v] of updates) next[k] = v;

      await pool.query('UPDATE users SET push_settings=? WHERE id=?', [JSON.stringify(next), req.user.id]);
      reply.send({ ok: true, settings: effectiveSettings(next) });
    } catch (e) {
      reply.status(500).send({ error: 'Failed to save settings' });
    }
  });

  // PWA Web Push Subscription (auth required)
  fastify.post('/api/push/web-subscribe', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      if (req.user.imp) return reply.status(403).send({ error: 'Push subscriptions are disabled in a debug session' });
      const { subscription } = req.body || {};
      if (!subscription?.endpoint || !subscription.keys?.p256dh || !subscription.keys?.auth) {
        return reply.status(400).send({ error: 'Valid subscription required' });
      }

      // Keys are refreshed too: a browser can re-key an endpoint, and pushes
      // encrypted with the old keys are undecryptable on the device.
      await pool.query(
        `INSERT INTO user_push_subscriptions (user_id, endpoint, p256dh, auth)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), p256dh=VALUES(p256dh), auth=VALUES(auth)`,
        [req.user.id, subscription.endpoint, subscription.keys.p256dh, subscription.keys.auth]
      );

      reply.status(201).send({ ok: true });
    } catch (e) {
      log.err('Web Push subscribe failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to save subscription' });
    }
  });
};
