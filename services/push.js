// services/push.js
//
// One entry point for notifying a user, whatever device they are on: Web Push
// for browsers (gated per category by the user's push_settings) and Expo for
// the mobile app. Callers should treat this as fire-and-forget — it never
// throws, because a failed notification must not fail the request that
// triggered it.

const webpush = require('web-push');
const axios = require('axios');
const pool = require('../db');
const { log } = require('../logger');

// Keys come from the environment only (validated at boot by
// utils/envValidator.js). Never hardcode a VAPID private key in source.
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:admin@attlarp.gr';
webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

async function sendPushNotification(userId, title, body, data = {}, category = 'system') {
  try {
    // Check user push settings
    const [userRows] = await pool.query('SELECT push_settings FROM users WHERE id=?', [userId]);
    if (!userRows.length) return;

    const settings = userRows[0].push_settings || {};
    // If settings are false for this category, do not send web push (off by default)
    const isEnabled = !!settings[category];

    const origin = process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',')[0] : '';
    const clickUrl = data.url ? data.url : '/comms';
    const clickFullUrl = origin ? (origin + clickUrl) : clickUrl;
    // data.icon is a relative avatar/crest path (e.g. `/api/users/5/avatar`)
    // set by the caller — resolved to an absolute URL the same way clickUrl
    // is, since the service worker's showNotification() needs it to survive
    // being read back out of the push payload with no other context. Not
    // every caller passes one (system-level notifications, the test push):
    // those fall back to the service worker's own generic app icon.
    const iconFullUrl = data.icon ? (origin ? (origin + data.icon) : data.icon) : null;

    if (isEnabled) {
      // Send Web Push
      const [webSubs] = await pool.query('SELECT endpoint, p256dh, auth FROM user_push_subscriptions WHERE user_id=?', [userId]);
      const payload = JSON.stringify({
        title,
        body,
        icon: iconFullUrl,
        data: { url: clickFullUrl }
      });

      for (const row of webSubs) {
        const pushSubscription = {
          endpoint: row.endpoint,
          keys: { p256dh: row.p256dh, auth: row.auth }
        };
        try {
          await webpush.sendNotification(pushSubscription, payload);
        } catch (err) {
          if (err.statusCode === 404 || err.statusCode === 410) {
            await pool.query('DELETE FROM user_push_subscriptions WHERE endpoint=?', [row.endpoint]);
          } else {
            log.err('Web push failed', { err: err.message });
          }
        }
      }
    }

    // 2. Retain Mobile Devices (Expo)
    const [subs] = await pool.query('SELECT id, subscription_json FROM push_subscriptions WHERE user_id=?', [userId]);
    if (!subs.length) return;

    const expoTokens = [];
    for (const row of subs) {
      try {
        const sub = JSON.parse(row.subscription_json);
        if (sub.expoPushToken) expoTokens.push(sub.expoPushToken);
      } catch (e) { }
    }

    if (expoTokens.length > 0) {
      // Expo's push API has no first-class "notification icon" field — this
      // just passes the resolved avatar URL through in `data` for the native
      // app to use if/when it's built to read it. Not a working image today.
      const expoMessages = expoTokens.map(token => ({
        to: token, sound: 'default', title: title, body: body, data: { ...data, icon: iconFullUrl },
      }));
      await axios.post('https://exp.host/--/api/v2/push/send', expoMessages, {
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' }
      }).catch(err => log.err('Expo push failed', { err: err.message }));
    }
  } catch (e) {
    log.err('Failed to execute push notification', { error: e.message });
  }
}

module.exports = { sendPushNotification, VAPID_PUBLIC_KEY };
