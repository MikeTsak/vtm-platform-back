// routes/adminLogs.js
//
// Server log tail, download, and clear — admin only.
const fs = require('fs');
const path = require('path');
const { tailFile } = require('../services/logTail');

module.exports = async function (fastify, opts) {
  const { log, authRequired, requireAdmin } = opts;

  // Admin: fetch last N lines
  fastify.get('/api/admin/logs', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const file = process.env.LOG_FILE;
    if (!file) return reply.status(404).json({ error: 'Log file not configured' });

    const lines = Number(req.query.lines || 200);
    try {
      const last = await tailFile(file, Math.min(1000, Math.max(10, lines)));
      // If LOG_JSON=1, return parsed JSON objects (best-effort)
      if (process.env.LOG_JSON === '1') {
        const parsed = last.map(l => {
          try { return JSON.parse(l); } catch { return { raw: l }; }
        });
        return reply.send({ ok: true, lines: parsed });
      } else {
        return reply.send({ ok: true, lines: last });
      }
    } catch (e) {
      log.err('Admin logs read failed', { message: e.message });
      return reply.status(500).json({ error: 'Failed to read log file' });
    }
  });

  // Admin: download full log (stream)
  fastify.get('/api/admin/logs/download', { preHandler: [authRequired, requireAdmin] }, (req, reply) => {
    const file = process.env.LOG_FILE;
    if (!file) return reply.status(404).json({ error: 'Log file not configured' });
    const fp = path.resolve(file);
    if (!fs.existsSync(fp)) return reply.status(404).json({ error: 'Log file missing' });

    reply.header('Content-Disposition', `attachment; filename="${path.basename(fp)}"`);
    reply.header('Content-Type', 'text/plain; charset=utf-8');
    const stream = fs.createReadStream(fp);
    stream.pipe(reply.raw);
    stream.on('error', (err) => {
      log.err('Admin logs download failed', { message: err.message });
      reply.send();
    });
  });

  // Admin: clear log file (truncate) — use with care
  fastify.post('/api/admin/logs/clear', { preHandler: [authRequired, requireAdmin] }, (req, reply) => {
    const file = process.env.LOG_FILE;
    if (!file) return reply.status(440).json({ error: 'Log file not configured' });
    const fp = path.resolve(file);
    try {
      fs.truncateSync(fp, 0);
      log.adm('Log file truncated by admin', { admin_id: req.user.id });
      return reply.send({ ok: true });
    } catch (e) {
      log.err('Admin clear logs failed', { message: e.message });
      return reply.status(500).json({ error: 'Failed to clear log file' });
    }
  });
};
