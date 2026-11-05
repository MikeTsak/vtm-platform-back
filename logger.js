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
 * File sink (optional): JSON lines, the shape the admin Logs page reads
 * ========================= */
// Until 2026-11 production wrote only to stdout (pino), which Passenger drops:
// the file got nothing from 2026-07-21 on and could not explain the outages.
// Every Passenger process appends to the same file. Writes are synchronous so
// the lines just before a crash or exit reach the disk.
// ponytail: sync appends, fine at a few lines a second; async stream if volume grows.
const LOG_MAX_BYTES = 20 * 1024 * 1024; // past this LOG_FILE becomes LOG_FILE.1 (one old file kept)
let logFd = null;

function openLog() {
  try {
    fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true });
    logFd = fs.openSync(LOG_FILE, 'a');
  } catch (e) {
    logFd = null;
    console.error('[LOGGER] Failed to open LOG_FILE:', LOG_FILE, e.message);
  }
}

// Rotates a full file, and follows a rotation another process did (our fd
// would otherwise keep writing into the renamed file).
function checkLogFile() {
  if (!LOG_FILE) return;
  try {
    const st = fs.statSync(LOG_FILE);
    if (st.size > LOG_MAX_BYTES) fs.renameSync(LOG_FILE, `${LOG_FILE}.1`);
    else if (logFd !== null && fs.fstatSync(logFd).ino === st.ino) return;
  } catch (_) { /* missing: reopening creates it */ }
  if (logFd !== null) { try { fs.closeSync(logFd); } catch (_) {} }
  openLog();
}
checkLogFile();

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
function formatJSON({ level, cat, msg, ctx }) {
  const base = { time: new Date().toISOString(), level, pid: process.pid, cat, msg };
  return safeStringify(ctx ? { ...base, ...ctx, ...base } : base); // base first, and wins over ctx keys
}

const pino = require('pino');
const colors = require('colors/safe');

// Pino is only used in production or when JSON logging is forced
const pinoLogger = pino();

// Call sites throughout the codebase do both `log.err('X failed', err)` (the
// raw Error as ctx) and `log.err('X failed', { message: err.message })`. The
// latter was always fine; the former silently dropped the useful part in
// production. Error.message/.stack/.name live on the prototype chain, not as
// own enumerable properties, so `{ ...err }` (used below for the pino/JSON
// path) serializes a plain Error to `{}` — and even a driver error (mysql2
// attaches code/errno/sqlMessage as real own properties) still loses message
// and stack the same way. That's meant every production error this route
// logged as `log.err('...', err)` came out with no usable detail at all.
function normalizeCtx(ctx) {
  if (ctx instanceof Error) {
    return { message: ctx.message, stack: ctx.stack, name: ctx.name, ...ctx };
  }
  if (ctx != null && typeof ctx !== 'object') return { detail: ctx }; // a string would spread into characters
  return ctx;
}

function emit(level, cat, msg, ctx) {
  if (!allow(level)) return;
  ctx = normalizeCtx(ctx);

  if (logFd !== null) {
    try { fs.writeSync(logFd, formatJSON({ level, cat, msg, ctx }) + '\n'); } catch (_) {}
  }

  if (process.env.NODE_ENV !== 'production' && !USE_JSON) {
    const d = new Date();
    const time = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}.${String(d.getMilliseconds()).padStart(3, '0')}`;
    
    let badge = levelBadge(level);
    if (level === 'error') badge = colors.red(badge);
    else if (level === 'warn') badge = colors.yellow(badge);
    else if (level === 'debug') badge = colors.gray(badge);
    else badge = colors.green(badge);

    const emo = (USE_EMOJI && EMO[cat]) ? `${EMO[cat]} ` : '';
    const catLabel = cat ? colors.cyan(`[${cat}] `) : '';
    
    let ctxStr = '';
    if (ctx && Object.keys(ctx).length > 0) {
      ctxStr = ' ' + colors.gray(safeStringify(ctx));
    }
    
    const line = `[${time}] ${badge}: ${emo}${catLabel}${msg}${ctxStr}`;

    if (level === 'error') console.error(line);
    else if (level === 'warn') console.warn(line);
    else if (level === 'debug') console.debug(line);
    else console.log(line);
    
    return;
  }

  const payload = { cat, ...ctx };
  let pLevel = 'info';
  if (level === 'error') pLevel = 'error';
  else if (level === 'warn') pLevel = 'warn';
  else if (level === 'debug') pLevel = 'debug';

  const emo = (USE_EMOJI && EMO[cat]) ? `${EMO[cat]} ` : '';
  const catLabel = cat ? `[${cat}] ` : '';
  pinoLogger[pLevel](payload, `${emo}${catLabel}${msg}`);
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
    
    let safeBody = undefined;
    if (req.body && Object.keys(req.body).length) {
      safeBody = { ...req.body };
      const sensitiveKeys = ['password', 'passwordConfirm', 'token', 'recaptchaToken', 'secret'];
      for (const key of sensitiveKeys) {
        if (safeBody[key] !== undefined) {
          safeBody[key] = '[REDACTED]';
        }
      }
    }

    const reqCtx = {
      ip: req.ip,
      method: req.method,
      url: req.originalUrl,
      ua: req.get('user-agent'),
      // Body can be noisy; include if small / useful in your app
      body: safeBody,
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
const mb = (n) => Math.round(n / 1048576);
function vitals() {
  const m = process.memoryUsage();
  return `rss=${mb(m.rss)}MB heap=${mb(m.heapUsed)}/${mb(m.heapTotal)}MB ext=${mb(m.external)}MB buf=${mb(m.arrayBuffers)}MB up=${Math.round(process.uptime() / 60)}m`;
}

function installProcessHandlers() {
  // Restart forensics. A silent death (no "exit"/"SIGTERM" line from that pid
  // before the next boot) means the host's resource limiter SIGKILLed us; rss
  // in its last `health` line (plugins/observability.js) then shows how close
  // to the package's memory cap we were.
  setInterval(checkLogFile, 60 * 1000).unref();
  process.on('exit', (code) => { try { log.adm(`exit code=${code} ${vitals()}`); } catch (_) {} });

  // A stray error (dropped DB socket, Discord hiccup, one bad request) should
  // not take the whole API down and drop every connected socket. Only bail out
  // if it is happening in a tight loop.
  // ponytail: crude loop guard; replace with real supervision if it ever matters.
  let recent = [];
  process.on('uncaughtException', (e) => {
    log.error('uncaughtException', { message: e.message, stack: e.stack, vitals: vitals() }, 'err');
    const now = Date.now();
    recent = recent.filter((t) => now - t < 60_000).concat(now);
    if (recent.length >= 5) setTimeout(() => process.exit(1), 50);
  });

  process.on('unhandledRejection', (reason) => {
    const msg = reason && reason.message ? reason.message : String(reason);
    const stack = reason && reason.stack ? reason.stack : undefined;
    log.error('unhandledRejection', { message: msg, stack }, 'err');
  });

  const graceful = (sig) => () => {
    log.adm(`Received ${sig}, shutting down… ${vitals()}`);
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
  vitals,
  EMO, // exported for UI parity if needed
};
