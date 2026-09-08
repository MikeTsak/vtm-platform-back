// routes/maintenance.js
//
// Admin-only maintenance runners (migrations, avatar backfills) streamed to the
// browser over SSE so long jobs report progress instead of timing out.
const { spawn } = require('child_process');
const path = require('path');
const { sseCorsHeaders } = require('../services/sse');

// The migration scripts live at the application root, not in routes/.
const APP_ROOT = path.join(__dirname, '..');

module.exports = async function (fastify, opts) {
  const { authRequired, requireAdmin } = opts;

  // Admin: Run Migrations Stream (SSE)

  // Admin: Run Media Migration Stream (SSE)
  fastify.get('/api/admin/migrate-media/stream', { preHandler: [authRequired, requireAdmin] }, (req, reply) => {
    reply.hijack();
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
      ...sseCorsHeaders(req)
    });
    reply.raw.flushHeaders();

    const scripts = ['migrate_media.js'];
    const total = scripts.length;
    let current = 0;

    const sendEvent = (event, data) => {
      reply.raw.write(`event: ${event}\n`);
      reply.raw.write(`data: ${JSON.stringify(data)}\n\n`);
      if (reply.raw.flush) reply.raw.flush();
    };

    sendEvent('start', { total });

    const runNext = () => {
      if (current >= total) {
        sendEvent('done', { message: 'Media migration complete!' });
        return setTimeout(() => {
          reply.raw.end();
        }, 500);
      }

      const script = scripts[current];
      sendEvent('progress', { script, current: current + 1, total });
      sendEvent('log', `\n--- Running ${script} ---`);

      const child = spawn(process.execPath, [script], { cwd: APP_ROOT });

      child.stdout.on('data', (data) => {
        sendEvent('log', data.toString());
      });

      child.stderr.on('data', (data) => {
        sendEvent('log', `[ERROR] ${data.toString()}`);
      });

      child.on('close', (code) => {
        sendEvent('log', `--- ${script} finished with code ${code} ---`);
        current++;
        runNext();
      });

      child.on('error', (err) => {
        sendEvent('log', `[FATAL] Failed to start ${script}: ${err.message}`);
        current++;
        runNext();
      });
    };

    runNext();

    req.raw.on('close', () => {
      reply.raw.end();
    });
  });

  fastify.get('/api/admin/run-migrations/stream', { preHandler: [authRequired, requireAdmin] }, (req, reply) => {
    reply.hijack();
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
      ...sseCorsHeaders(req)
    });
    reply.raw.flushHeaders();

    const scripts = [
      'migrate-avatars.js',
      'migrate-npc-avatars.js',
      'migrate-retainers.js',
      'migrations/split_rumors.js'
    ];

    const total = scripts.length;
    let current = 0;

    const sendEvent = (event, data) => {
      reply.raw.write(`event: ${event}\n`);
      reply.raw.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    sendEvent('start', { total });

    const runNext = () => {
      if (current >= total) {
        sendEvent('done', { message: 'All migrations complete!' });
        return reply.raw.end();
      }

      const script = scripts[current];
      sendEvent('progress', { script, current: current + 1, total });
      sendEvent('log', `\n--- Running ${script} ---`);

      const child = spawn(process.execPath, [script], { cwd: APP_ROOT });

      child.stdout.on('data', (data) => {
        sendEvent('log', data.toString());
      });

      child.stderr.on('data', (data) => {
        sendEvent('log', `[ERROR] ${data.toString()}`);
      });

      child.on('close', (code) => {
        sendEvent('log', `--- ${script} finished with code ${code} ---`);
        current++;
        runNext();
      });

      child.on('error', (err) => {
        sendEvent('log', `[FATAL] Failed to start ${script}: ${err.message}`);
        current++;
        runNext();
      });
    };

    runNext();

    req.raw.on('close', () => {
      // Client disconnected, though child processes might still run if we don't kill them.
      reply.raw.end();
    });
  });

  // Admin: Backfill avatar thumbnails (SSE) — same one-script-at-a-time
  // spawn/stream pattern as migrate-media/stream above, for
  // migrate-avatar-thumbs.js (see migrations/list/0011_avatar_thumb_urls.js).
  fastify.get('/api/admin/backfill-avatar-thumbs/stream', { preHandler: [authRequired, requireAdmin] }, (req, reply) => {
    reply.hijack();
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
      ...sseCorsHeaders(req)
    });
    reply.raw.flushHeaders();

    const scripts = ['migrate-avatar-thumbs.js'];
    const total = scripts.length;
    let current = 0;

    const sendEvent = (event, data) => {
      reply.raw.write(`event: ${event}\n`);
      reply.raw.write(`data: ${JSON.stringify(data)}\n\n`);
      if (reply.raw.flush) reply.raw.flush();
    };

    sendEvent('start', { total });

    const runNext = () => {
      if (current >= total) {
        sendEvent('done', { message: 'Avatar thumbnail backfill complete!' });
        return setTimeout(() => {
          reply.raw.end();
        }, 500);
      }

      const script = scripts[current];
      sendEvent('progress', { script, current: current + 1, total });
      sendEvent('log', `\n--- Running ${script} ---`);

      const child = spawn(process.execPath, [script], { cwd: APP_ROOT });

      child.stdout.on('data', (data) => {
        sendEvent('log', data.toString());
      });

      child.stderr.on('data', (data) => {
        sendEvent('log', `[ERROR] ${data.toString()}`);
      });

      child.on('close', (code) => {
        sendEvent('log', `--- ${script} finished with code ${code} ---`);
        current++;
        runNext();
      });

      child.on('error', (err) => {
        sendEvent('log', `[FATAL] Failed to start ${script}: ${err.message}`);
        current++;
        runNext();
      });
    };

    runNext();

    req.raw.on('close', () => {
      reply.raw.end();
    });
  });

  // Admin: Migrate any leftover avatar BLOBs to the CDN, then clear them
  // (SSE) — same spawn/stream pattern as the routes above, for
  // migrate-avatars-to-cdn.js.
  fastify.get('/api/admin/migrate-avatars-to-cdn/stream', { preHandler: [authRequired, requireAdmin] }, (req, reply) => {
    reply.hijack();
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
      ...sseCorsHeaders(req)
    });
    reply.raw.flushHeaders();

    const scripts = ['migrate-avatars-to-cdn.js'];
    const total = scripts.length;
    let current = 0;

    const sendEvent = (event, data) => {
      reply.raw.write(`event: ${event}\n`);
      reply.raw.write(`data: ${JSON.stringify(data)}\n\n`);
      if (reply.raw.flush) reply.raw.flush();
    };

    sendEvent('start', { total });

    const runNext = () => {
      if (current >= total) {
        sendEvent('done', { message: 'Avatar BLOB cleanup complete!' });
        return setTimeout(() => {
          reply.raw.end();
        }, 500);
      }

      const script = scripts[current];
      sendEvent('progress', { script, current: current + 1, total });
      sendEvent('log', `\n--- Running ${script} ---`);

      const child = spawn(process.execPath, [script], { cwd: APP_ROOT });

      child.stdout.on('data', (data) => {
        sendEvent('log', data.toString());
      });

      child.stderr.on('data', (data) => {
        sendEvent('log', `[ERROR] ${data.toString()}`);
      });

      child.on('close', (code) => {
        sendEvent('log', `--- ${script} finished with code ${code} ---`);
        current++;
        runNext();
      });

      child.on('error', (err) => {
        sendEvent('log', `[FATAL] Failed to start ${script}: ${err.message}`);
        current++;
        runNext();
      });
    };

    runNext();

    req.raw.on('close', () => {
      reply.raw.end();
    });
  });
};
