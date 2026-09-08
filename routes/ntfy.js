// routes/ntfy.js
//
// Admin plumbing for ntfy.sh push topics: issue a topic, set per-admin
// subscription prefs, fire a test alert.
const crypto = require('crypto');
const axios = require('axios');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  // Admin: Get current Ntfy Topic
  fastify.get('/api/admin/ntfy', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT ntfy_topic, ntfy_subscribed_npcs, ntfy_subscribe_errors, ntfy_subscribe_downtimes FROM users WHERE id = ?', [req.user.id]);
      if (!rows.length) return reply.send({ topic: '', subscribed_npcs: [], subscribe_errors: false, subscribe_downtimes: false });
      let npcPrefs = [];
      try { if (rows[0].ntfy_subscribed_npcs) npcPrefs = typeof rows[0].ntfy_subscribed_npcs === 'string' ? JSON.parse(rows[0].ntfy_subscribed_npcs) : rows[0].ntfy_subscribed_npcs; } catch (e) { }
      reply.send({ topic: rows[0].ntfy_topic, subscribed_npcs: npcPrefs, subscribe_errors: !!rows[0].ntfy_subscribe_errors, subscribe_downtimes: !!rows[0].ntfy_subscribe_downtimes });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch Ntfy topic' });
    }
  });

  // Admin: Generate new Ntfy Topic
  fastify.post('/api/admin/ntfy/generate', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const newTopic = `erebus_admin_${crypto.randomBytes(8).toString('hex')}`;
      await pool.query('UPDATE users SET ntfy_topic = ? WHERE id = ?', [newTopic, req.user.id]);

      // Also send a welcome push
      axios.post(`https://ntfy.sh/${newTopic}`, `Your Ntfy integration is now active!`, {
        headers: { 'Title': '🦇 Erebus Ntfy Linked', 'Tags': 'vampire,white_check_mark' }
      }).catch(() => { });

      log.adm('Ntfy key generated', { admin_id: req.user.id, topic: newTopic });
      reply.send({ topic: newTopic });
    } catch (e) {
      reply.status(500).send({ error: 'Failed to generate Ntfy topic' });
    }
  });

  // Admin: Save Ntfy NPC Preferences
  fastify.post('/api/admin/ntfy/prefs', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { npc_ids, subscribe_errors, subscribe_downtimes } = req.body;
      const cleanIds = Array.isArray(npc_ids) ? npc_ids.map(Number).filter(n => !isNaN(n)) : [];

      const [oldRows] = await pool.query('SELECT ntfy_topic, ntfy_subscribe_errors, ntfy_subscribe_downtimes FROM users WHERE id = ?', [req.user.id]);
      await pool.query('UPDATE users SET ntfy_subscribed_npcs = ?, ntfy_subscribe_errors = ?, ntfy_subscribe_downtimes = ? WHERE id = ?', [JSON.stringify(cleanIds), subscribe_errors ? 1 : 0, subscribe_downtimes ? 1 : 0, req.user.id]);

      if (subscribe_errors && oldRows.length > 0 && !oldRows[0].ntfy_subscribe_errors && oldRows[0].ntfy_topic) {
        const axios = require('axios');
        axios.post(`https://ntfy.sh/${oldRows[0].ntfy_topic}`, `You are now subscribed to receive system errors.`, {
          headers: { 'Title': '🦇 System Errors Subscribed', 'Tags': 'vampire,white_check_mark' }
        }).catch(() => { });
      }

      if (subscribe_downtimes && oldRows.length > 0 && !oldRows[0].ntfy_subscribe_downtimes && oldRows[0].ntfy_topic) {
        const axios = require('axios');
        axios.post(`https://ntfy.sh/${oldRows[0].ntfy_topic}`, `You are now subscribed to receive push notifications when players read their Downtime resolutions.`, {
          headers: { 'Title': '🦇 Downtimes Subscribed', 'Tags': 'vampire,white_check_mark' }
        }).catch(() => { });
      }

      reply.send({ success: true, subscribed_npcs: cleanIds, subscribe_errors: !!subscribe_errors, subscribe_downtimes: !!subscribe_downtimes });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to save Ntfy preferences' });
    }
  });

  // Admin: Test Ntfy Notification
  fastify.post('/api/admin/ntfy/test', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT ntfy_topic FROM users WHERE id = ?', [req.user.id]);
      if (!rows.length || !rows[0].ntfy_topic) return reply.status(400).send({ error: 'No Ntfy topic configured' });

      await axios.post(`https://ntfy.sh/${rows[0].ntfy_topic}`, 'This is a test notification from Erebus Portal backend.', {
        headers: {
          'Title': '🦇 Ntfy Test',
          'Tags': 'bell',
          'Markdown': 'yes',
          'Priority': 'default',
          'Icon': 'https://portal.attlarp.gr/img/ATT-logo(1).png'
        }
      });

      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).send({ error: 'Failed to send test notification' });
    }
  });
};
