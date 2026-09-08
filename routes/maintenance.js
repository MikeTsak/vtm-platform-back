// routes/maintenance.js
//
// Admin-only maintenance runners (migrations, avatar backfills) streamed to the
// browser over SSE so long jobs report progress instead of timing out.
const fs = require('fs');
const { spawn } = require('child_process');
const path = require('path');
const { sseCorsHeaders } = require('../services/sse');
const { backup, listBackups, backupDir } = require('../scripts/backup-db');

// The migration scripts live at the application root, not in routes/.
const APP_ROOT = path.join(__dirname, '..');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

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
  /* ------------------------------------------------------------------ *
   * Database backups
   * ------------------------------------------------------------------ */

  // Streams a backup as it runs. `?full=true` includes the media BLOB tables
  // (~400 MB); the default omits them (~2.4 MB) — see scripts/backup-db.js.
  fastify.get('/api/admin/backup/stream', { preHandler: [authRequired, requireAdmin] }, (req, reply) => {
    const full = String(req.query.full) === 'true';

    reply.hijack();
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
      ...sseCorsHeaders(req),
    });
    reply.raw.flushHeaders();

    let closed = false;
    req.raw.on('close', () => { closed = true; });

    const sendEvent = (event, data) => {
      if (closed) return;
      reply.raw.write(`event: ${event}\n`);
      reply.raw.write(`data: ${JSON.stringify(data)}\n\n`);
      if (reply.raw.flush) reply.raw.flush();
    };

    sendEvent('log', `--- Starting ${full ? 'FULL' : 'game-data-only'} backup ---`);
    if (!full) sendEvent('log', 'Media tables (images) are omitted. Use "Full backup" to include them.');

    backup({
      quiet: true,
      skipMedia: !full,
      onProgress: (p) => {
        if (p.phase === 'start') {
          sendEvent('start', { total: p.total });
          return;
        }
        sendEvent('progress', { current: p.index, total: p.total });
        sendEvent('log', p.skipped
          ? `${p.table}: structure only (${p.rows} rows omitted)`
          : `${p.table}: ${p.rows} rows`);
      },
    })
      .then((res) => {
        const mb = (res.size / 1024 / 1024).toFixed(1);
        sendEvent('log', `--- Wrote ${require('path').basename(res.file)} (${mb} MB) ---`);
        if (res.pruned) sendEvent('log', `Pruned ${res.pruned} backup(s) past the retention window.`);
        sendEvent('done', {
          message: `Backup complete: ${mb} MB, ${res.rows} rows.`,
          file: require('path').basename(res.file),
          full,
        });
        setTimeout(() => reply.raw.end(), 500);
      })
      .catch((e) => {
        log.err('Admin backup failed', { error: e.message });
        sendEvent('log', `[FATAL] ${e.message}`);
        sendEvent('done', { message: `Backup FAILED: ${e.message}`, failed: true });
        setTimeout(() => reply.raw.end(), 500);
      });
  });

  // Lists what's on disk, newest first.
  fastify.get('/api/admin/backups', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const rows = await listBackups();
      reply.send({
        dir: backupDir(),
        backups: rows.map((r) => ({
          file: r.file,
          size: r.size,
          created_at: r.mtime,
          partial: r.file.includes('-nomedia'),
        })),
      });
    } catch (e) {
      log.err('Failed to list backups', { error: e.message });
      reply.status(500).send({ error: 'Failed to list backups' });
    }
  });

  // Downloads one backup file.
  //
  // The filename comes from the client, so it is matched against a strict
  // pattern AND the resolved path is required to sit directly inside the
  // backup directory — without both checks this is a path-traversal hole that
  // would hand out any file on the server (.env included).
  fastify.get('/api/admin/backups/:file', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const name = String(req.params.file || '');
    if (!/^[A-Za-z0-9._-]+\.sql\.gz$/.test(name)) {
      return reply.status(400).send({ error: 'Invalid backup filename' });
    }

    const dir = backupDir();
    const full = path.resolve(dir, name);
    if (path.dirname(full) !== path.resolve(dir)) {
      return reply.status(400).send({ error: 'Invalid backup path' });
    }
    if (!fs.existsSync(full)) return reply.status(404).send({ error: 'Backup not found' });

    log.adm('Backup downloaded', { admin_id: req.user.id, file: name });
    reply
      .header('Content-Type', 'application/gzip')
      .header('Content-Disposition', `attachment; filename="${name}"`)
      .header('Content-Length', fs.statSync(full).size);
    return reply.send(fs.createReadStream(full));
  });

  /* ------------------------------------------------------------------
   * Schema versions
   *
   * The equivalent of phpMyAdmin's Tracking tab for this application.
   * phpMyAdmin's own tracking only records statements it executes itself,
   * so it never sees our schema changes — those are applied by
   * migrations/runner.js at boot. schema_migrations is the real record.
   * ------------------------------------------------------------------ */
  fastify.get('/api/admin/schema-versions', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const LIST_DIR = path.join(APP_ROOT, 'migrations', 'list');

    let applied = new Map();
    try {
      const [rows] = await pool.query('SELECT name, applied_at FROM schema_migrations ORDER BY name');
      applied = new Map(rows.map((r) => [r.name, r.applied_at]));
    } catch (e) {
      // Before the first run the table does not exist yet; that is not an error.
      if (e.code !== 'ER_NO_SUCH_TABLE') {
        log.err('Failed to read schema_migrations', { error: e.message });
        return reply.status(500).send({ error: 'Failed to read schema versions' });
      }
    }

    const files = fs.existsSync(LIST_DIR)
      ? fs.readdirSync(LIST_DIR).filter((f) => f.endsWith('.js')).sort()
      : [];

    const nameOf = (file) => {
      try {
        const mod = require(path.join(LIST_DIR, file));
        return (mod && mod.name) || file.replace(/\.js$/, '');
      } catch (e) {
        return file.replace(/\.js$/, '');
      }
    };

    const versions = files.map((file) => {
      const name = nameOf(file);
      const at = applied.get(name);
      return { name, file, applied: Boolean(at), applied_at: at || null };
    });

    // Recorded in the database but with no file on disk — a deleted or
    // renamed migration. Harmless, but worth surfacing rather than hiding.
    const known = new Set(versions.map((v) => v.name));
    const orphaned = [...applied.keys()]
      .filter((n) => !known.has(n))
      .map((n) => ({ name: n, applied_at: applied.get(n) }));

    return reply.send({
      database: process.env.DB_NAME,
      versions,
      orphaned,
      pending: versions.filter((v) => !v.applied).length,
    });
  });
};
