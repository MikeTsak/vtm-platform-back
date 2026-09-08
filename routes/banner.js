// routes/banner.js
//
// The site-wide announcement banner: public read, SSE live updates, admin write.
const { getSetting, setSetting } = require('../utils/settings');
const { sanitizeRichText } = require('../utils/sanitize');
const { bannerEmitter } = require('../services/banner');

module.exports = async function (fastify, opts) {
  const { log, authRequired, requireAdmin } = opts;

  // ==========================================
  // --- GLOBAL BANNER ROUTES ---
  // ==========================================

  // Public: Get global banner settings (No auth required so it loads for everyone)
  fastify.get('/api/system/banner', async (req, reply) => {
    try {
      reply.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      const enabled = await getSetting('banner_enabled', 'false');
      const message = await getSetting('banner_message', '');
      const countdown = await getSetting('banner_countdown', '');
      const threat = await getSetting('masquerade_threat_level', '1');

      reply.send({
        banner_enabled: enabled === 'true',
        banner_message: message,
        banner_countdown: countdown,
        masquerade_threat_level: parseInt(threat, 10)
      });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch banner config' });
    }
  });

  // Public: Stream banner updates (SSE)
  fastify.get('/api/system/banner/stream', (req, reply) => {
    reply.hijack();
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      // No credentials on this one (public route), so a wildcard is valid —
      // kept as '*' rather than echoing origin, on purpose, so it still works
      // for any caller. X-Accel-Buffering guards against a reverse proxy
      // (e.g. nginx in front of Apache/Node on Plesk) buffering the whole
      // response instead of streaming it chunk by chunk, which can otherwise
      // present as the stream hanging or erroring out.
      'Access-Control-Allow-Origin': '*',
      'X-Accel-Buffering': 'no'
    });
    reply.raw.flushHeaders();

    // Send an initial ping to establish connection
    reply.raw.write('data: ping\n\n');

    const onUpdate = async () => {
      try {
        const enabled = await getSetting('banner_enabled', 'false');
        const message = await getSetting('banner_message', '');
        const countdown = await getSetting('banner_countdown', '');
        const threat = await getSetting('masquerade_threat_level', '1');

        reply.raw.write(`data: ${JSON.stringify({
        banner_enabled: enabled === 'true',
        banner_message: message,
        banner_countdown: countdown,
        masquerade_threat_level: parseInt(threat, 10)
      })}\n\n`);
      } catch (e) {
        log.err('SSE banner update fetch failed', { error: e.message });
      }
    };

    bannerEmitter.on('update', onUpdate);

    req.raw.on('close', () => {
      bannerEmitter.off('update', onUpdate);
      reply.raw.end();
    });
  });

  // Admin: Save global banner settings
  fastify.post('/api/admin/system/banner', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { banner_enabled, banner_message, banner_countdown } = req.body;

      await setSetting('banner_enabled', String(banner_enabled));
      await setSetting('banner_message', sanitizeRichText(banner_message || ''));
      await setSetting('banner_countdown', banner_countdown || '');

      log.adm('Global banner updated', { admin_id: req.user.id });

      // Broadcast change
      bannerEmitter.emit('update');

      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to update banner config' });
    }
  });
};
