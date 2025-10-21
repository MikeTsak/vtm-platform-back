// logger.js
// Lightweight structured logger for Node/Express with:
// - JSON lines via LOG_JSON=1 (great for Plesk/centralized logs)
// - Emoji categories (toggle with LOG_EMOJI=0)
// - Level gating via LOG_LEVEL=debug|info|warn|error
// - Optional file sink via LOG_FILE=/abs/path/app.log
// - Request logger with silentPaths or LOG_SILENCE_PATHS
// - Express error handler and process signal handlers

const fs = require('fs');
const path = require('path');

/* =========================
 * Config (via env)
 * ========================= */
const USE_JSON  = process.env.LOG_JSON === '1';
const USE_EMOJI = process.env.LOG_EMOJI !== '0';
const LEVEL     = (process.env.LOG_LEVEL || 'info').toLowerCase();
const LOG_FILE  = process.env.LOG_FILE || '';

const LEVEL_RANK = { debug: 10, info: 20, warn: 30, error: 40 };
const allow = (lvl) => LEVEL_RANK[lvl] >= LEVEL_RANK[LEVEL];

/* =========================
 * Category emojis
 * ========================= */
const EMO = {
  start: '🚀', auth: '🔐', char: '🧛', xp: '✨', dt: '🕰️', dom: '🏰', adm: '🛡️',
  ok: '✅', warn: '⚠️', err: '💥', req: '➡️', res: '⬅️', mail: '✉️', db: '🗄️',
  info: 'ℹ️', http: '🌐', dbg: '🐛'
};

const levelBadge = (lvl) => {
  switch (lvl) {
    case 'debug': return 'DEBUG';
    case 'info' : return 'INFO';
    case 'warn' : return 'WARN';
    case 'error': return 'ERROR';
    default     : return String(lvl || '').toUpperCase();
  }
};

/* =========================
 * File sink (optional)
 * ========================= */
let fileStream = null;
if (LOG_FILE) {
  try {
    // Ensure directory exists
    const dir = path.dirname(LOG_FILE);
    fs.mkdirSync(dir, { recursive: true });
    fileStream = fs.createWriteStream(LOG_FILE, { flags: 'a', encoding: 'utf8' });
  } catch (e) {
    console.error('[LOGGER] Failed to open LOG_FILE:', LOG_FILE, e);
  }
}

function writeLine(line) {
  // Console
  try { process.stdout.write(line + '\n'); } catch (_) {}
  // File
  if (fileStream) {
    try { fileStream.write(line + '\n'); } catch (_) {}
  }
}

/* =========================
 * Safe stringify (handles circular)
 * ========================= */
function safeStringify(obj) {
  try {
    const seen = new WeakSet();
    return JSON.stringify(obj, function (k, v) {
      if (typeof v === 'object' && v !== null) {
        if (seen.has(v)) return '[Circular]';
        seen.add(v);
      }
      // Hide huge buffers
      if (Buffer.isBuffer(v)) return `Buffer(${v.length})`;
      return v;
    });
  } catch {
    try { return String(obj); } catch { return '[Unstringifiable]'; }
  }
}

/* =========================
 * Core write
 * ========================= */
function nowISO() { return new Date().toISOString(); }

function formatText({ time, level, cat, msg, ctx }) {
  const badge = levelBadge(level);
  const emo = (USE_EMOJI && EMO[cat]) ? `${EMO[cat]} ` : '';
  const header = `${time} [${badge}] ${emo}${cat}: ${msg}`;
  if (ctx && Object.keys(ctx).length) {
    return `${header} | ${safeStringify(ctx)}`;
  }
  return header;
}

function formatJSON({ time, level, cat, msg, ctx }) {
  const base = { time, level, cat, msg };
  return safeStringify(ctx ? { ...base, ...ctx } : base);
}

function emit(level, cat, msg, ctx) {
  if (!allow(level)) return;
  const time = nowISO();
  const payload = { time, level, cat, msg, ctx };
  const line = USE_JSON ? formatJSON(payload) : formatText(payload);
  writeLine(line);
}

/* =========================
 * Public logger API
 * ========================= */
const log = {
  // level-first
  debug(msg, ctx = {}, cat = 'dbg') { emit('debug', cat, msg, ctx); },
  info (msg, ctx = {}, cat = 'info') { emit('info',  cat, msg, ctx); },
  warn (msg, ctx = {}, cat = 'warn') { emit('warn',  cat, msg, ctx); },
  error(msg, ctx = {}, cat = 'err')  { emit('error', cat, msg, ctx); },

  // category-first helpers — all are INFO unless noted
  start(msg, ctx = {}) { emit('info',  'start', msg, ctx); },
  auth (msg, ctx = {}) { emit('info',  'auth',  msg, ctx); },
  char (msg, ctx = {}) { emit('info',  'char',  msg, ctx); },
  xp   (msg, ctx = {}) { emit('info',  'xp',    msg, ctx); },
  dt   (msg, ctx = {}) { emit('info',  'dt',    msg, ctx); },
  dom  (msg, ctx = {}) { emit('info',  'dom',   msg, ctx); },
  adm  (msg, ctx = {}) { emit('info',  'adm',   msg, ctx); },
  ok   (msg, ctx = {}) { emit('info',  'ok',    msg, ctx); },
  req  (msg, ctx = {}) { emit('info',  'req',   msg, ctx); },
  res  (msg, ctx = {}) { emit('info',  'res',   msg, ctx); },
  mail (msg, ctx = {}) { emit('info',  'mail',  msg, ctx); },
  db   (msg, ctx = {}) { emit('info',  'db',    msg, ctx); },
  http (msg, ctx = {}) { emit('info',  'http',  msg, ctx); },
  dbg  (msg, ctx = {}) { emit('debug', 'dbg',   msg, ctx); },
  err  (msg, ctx = {}) { emit('error', 'err',   msg, ctx); }, // alias

  // create a category-bound child
  with(cat) {
    return {
      debug(msg, ctx = {}) { emit('debug', cat, msg, ctx); },
      info (msg, ctx = {}) { emit('info',  cat, msg, ctx); },
      warn (msg, ctx = {}) { emit('warn',  cat, msg, ctx); },
      error(msg, ctx = {}) { emit('error', cat, msg, ctx); },
    };
  },
};

/* =========================
 * Express request logger
 * ========================= */
// LOG_SILENCE_PATHS="/api/admin/logs,/api/admin/logs/download"
function attachRequestLogger(options = {}) {
  const envList = (process.env.LOG_SILENCE_PATHS || '')
    .split(/[;,]/)
    .map(s => s.trim())
    .filter(Boolean);

  const rawList = Array.isArray(options.silentPaths) && options.silentPaths.length
    ? options.silentPaths
    : envList;

  const testers = rawList.map(p =>
    p instanceof RegExp ? (u) => p.test(u) : (u) => (u || '').split('?')[0].startsWith(p)
  );

  const isSilent = (u) => testers.some(fn => fn(String(u || '')));

  return (req, res, next) => {
    if (isSilent(req.originalUrl)) return next();

    const t0 = Date.now();
    const reqCtx = {
      ip: req.ip,
      method: req.method,
      url: req.originalUrl,
      ua: req.get('user-agent'),
      // Body can be noisy; include if small / useful in your app
      body: req.body && Object.keys(req.body).length ? req.body : undefined,
    };
    log.req(`${req.method} ${req.originalUrl}`, reqCtx);

    res.on('finish', () => {
      const ms = Date.now() - t0;
      const code = res.statusCode || 0;
      const base = { status: code, bytes: res.getHeader('content-length'), ms };
      if (code >= 500)        log.err(`${code} ${req.method} ${req.originalUrl} (${ms}ms)`, base);
      else if (code >= 400)   log.warn(`${code} ${req.method} ${req.originalUrl} (${ms}ms)`, base, 'warn');
      else                    log.ok(`${code} ${req.method} ${req.originalUrl} (${ms}ms)`, base);
    });

    next();
  };
}

/* =========================
 * Express error handler
 * ========================= */
function expressErrorHandler(err, req, res, next) {
  try {
    log.error('Unhandled error', {
      url: req.originalUrl,
      method: req.method,
      ip: req.ip,
      err: {
        message: err && err.message,
        stack: err && err.stack,
        name:  err && err.name,
        code:  err && err.code,
      },
    }, 'err');
  } catch (_) {}

  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ ok: false, error: 'Internal Server Error' });
}

/* =========================
 * Process signal handlers
 * ========================= */
function installProcessHandlers() {
  process.on('uncaughtException', (e) => {
    log.error('uncaughtException', { message: e.message, stack: e.stack }, 'err');
    // give streams a moment to flush
    setTimeout(() => process.exit(1), 50);
  });

  process.on('unhandledRejection', (reason) => {
    const msg = reason && reason.message ? reason.message : String(reason);
    const stack = reason && reason.stack ? reason.stack : undefined;
    log.error('unhandledRejection', { message: msg, stack }, 'err');
  });

  const graceful = (sig) => () => {
    log.adm(`Received ${sig}, shutting down…`);
    try { fileStream && fileStream.end(); } catch (_) {}
    setTimeout(() => process.exit(0), 50);
  };
  process.on('SIGTERM', graceful('SIGTERM'));
  process.on('SIGINT',  graceful('SIGINT'));
}

/* =========================
 * Exports
 * ========================= */
module.exports = {
  log,
  attachRequestLogger,
  expressErrorHandler,
  installProcessHandlers,
  EMO, // exported for UI parity if needed
};
