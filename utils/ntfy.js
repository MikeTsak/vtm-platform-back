const axios = require('axios');
const pool = require('../db');
const { log } = require('../logger');

/**
 * Broadcasts an alert via Ntfy to all admins who have configured a topic.
 * @param {string} message - The body of the push notification
 * @param {object} options - Options for the notification
 * @param {string} [options.title] - The title of the notification
 * @param {string|string[]} [options.tags] - E.g. 'warning,skull' or ['warning', 'skull']
 * @param {string} [options.priority] - 'max', 'high', 'default', 'low', 'min'
 * @param {string} [options.click] - URL to open when notification is clicked
 */
async function broadcastNtfyAlert(message, options = {}) {
  try {
    // 1. Get all admins who have an ntfy_topic
    const [admins] = await pool.query(
      "SELECT ntfy_topic FROM users WHERE role = 'admin' AND ntfy_topic IS NOT NULL AND ntfy_topic != ''"
    );

    if (admins.length === 0) return;

    const tagsArray = Array.isArray(options.tags) ? options.tags : (options.tags ? options.tags.split(',') : ['warning']);

    // 2. Prepare headers (using Markdown for prettier formatting)
    const headers = {
      'Title': options.title || '🦇 Erebus System Alert',
      'Tags': tagsArray.join(','),
      'Markdown': 'yes',
      'Priority': options.priority || 'default',
      'Icon': options.icon || 'https://portal.attlarp.gr/img/ATT-logo(1).png'
    };

    if (options.click) {
      headers['Click'] = options.click;
    }

    // Convert object messages to string just in case
    const body = typeof message === 'object' ? JSON.stringify(message, null, 2) : message;

    // 3. Send requests in parallel
    const promises = admins.map(admin => {
      const topicUrl = `https://ntfy.sh/${admin.ntfy_topic}`;
      return axios.post(topicUrl, body, { headers })
        .catch(err => {
          log.err('Failed to send ntfy push to topic', { topic: admin.ntfy_topic, error: err.message });
        });
    });

    await Promise.allSettled(promises);
    log.info('Ntfy alerts dispatched successfully.', { count: admins.length });
  } catch (error) {
    log.err('Fatal error in broadcastNtfyAlert', { error: error.message });
  }
}

module.exports = { broadcastNtfyAlert };
