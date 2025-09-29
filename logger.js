// logger.js
const crypto = require('crypto');
const fs = require('fs');

// --- Configuration via Environment Variables ---

// Set LOG_JSON=1 to output logs as JSON lines (ideal for log aggregators like Plesk Log Viewer)
const USE_JSON  = process.env.LOG_JSON === '1';

// Set LOG_EMOJI=0 to disable emojis in console-friendly (non-JSON) mode
const USE_EMOJI = process.env.LOG_EMOJI !== '0';

// Set LOG_LEVEL to control verbosity: debug | info | warn | error
const LEVEL     = (process.env.LOG_LEVEL || 'info').toLowerCase();

// Set LOG_FILE to an absolute path to enable file logging
// e.g., /var/www/vhosts/yourdomain.com/logs/app.log
const LOG_FILE  = process.env.LOG_FILE || '';

// --- Logger Internals ---

const LEVEL_RANK = { debug: 10, info: 20, warn: 30, error: 40 };
const allow = (lvl) => LEVEL_RANK[lvl] >= LEVEL_RANK[LEVEL];

const EMO = {
  start: '🚀', auth: '🔐', char: '🧛', xp: '✨', dt: '🕰️', dom: '🏰', adm: '🛡️',
  ok: '✅', warn: '⚠️', err: '💥', req: '➡️', res: '⬅️', mail: '✉️', db: '🗄️', info: 'ℹ️'
};

const SENSITIVE_KEYS = ['password', 'pass', 'pwd', 'authorization', 'cookie', 'token', 'secret', 'key'];

/**
 * Recursively redacts sensitive keys from an object.
 * @param {*} value The value to process.
 * @param {number} depth The current recursion depth.
 * @returns {*} The redacted value.
 */
function redact(value, depth = 0) {
  if (value == null || depth > 5) return value;
  if (Array.isArray(value)) return value.map(v => redact(v, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) {
      const low = k.toLowerCase();
      out[k] = SENSITIVE_KEYS.some(s => low.includes(s)) ? '[redacted]' : redact(value[k], depth + 1);
    }
    return out;
  }
  if (typeof value === 'string' && value.length > 2000) return value.slice(0, 2000) + '…';
  return value;
}

function nowISO() { return new Date().toISOString(); }

function writeFileLine(line) {
  if (!LOG_FILE) return;
  // Asynchronously append to the file, ignoring errors for now.
  fs.appendFile(LOG_FILE, line + '\n', (err) => {
    if (err) console.error(`Failed to write to log file ${LOG_FILE}:`, err);
  });
}

/**
 * The core log emission function.
 * @param {string} level The log level ('info', 'warn', etc.).
 * @param {string} cat The log category (for emoji).
 * @param {string} msg The log message.
 * @param {object} [ctx] Additional context object.
 */
function emit(level, cat, msg, ctx) {
  if (!allow(level)) return;
  const payload = { t: nowISO(), lvl: level, cat, msg, ...(ctx ? redact(ctx) : {}) };

  if (USE_JSON) {
    const line = JSON.stringify(payload);
    if (level === 'error') console.error(line);
    else if (level === 'warn') console.warn(line);
    else console.log(line);
    writeFileLine(line);
  } else {
    const head = `${USE_EMOJI && EMO[cat] ? EMO[cat] + ' ' : ''}${msg}`;
    const line = ctx ? `${head} ${JSON.stringify(redact(ctx))}` : head;
    if (level === 'error') console.error(line);
    else if (level === 'warn') console.warn(line);
    else console.log(line);
    // Also write the non-JSON line to the file if specified
    writeFileLine(`${payload.t} [${level.toUpperCase()}] ${line}`);
  }
}

// Public log object with different categories
const log = {
  start: (m, c) => emit('info',  'start', m, c),
  auth:  (m, c) => emit('info',  'auth',  m, c),
  char:  (m, c) => emit('info',  'char',  m, c),
  xp:    (m, c) => emit('info',  'xp',    m, c),
  dt:    (m, c) => emit('info',  'dt',    m, c),
  dom:   (m, c) => emit('info',  'dom',   m, c),
  adm:   (m, c) => emit('info',  'adm',   m, c),
  ok:    (m, c) => emit('info',  'ok',    m, c),
  info:  (m, c) => emit('info',  'info',  m, c),
  warn:  (m, c) => emit('warn',  'warn',  m, c),
  err:   (m, c) => emit('error', 'err',   m, c),
  mail:  (m, c) => emit('info',  'mail',  m, c),
  db:    (m, c) => emit('info',  'db',    m, c),
  req:   (m, c) => emit('info',  'req',   m, c),
  res:   (m, c) => emit('info',  'res',   m, c),
};

/**
 * Express middleware to log all incoming requests and their responses.
 */
function attachRequestLogger() {
  return (req, res, next) => {
    req.id = req.headers['x-request-id'] || crypto.randomUUID().slice(0, 8);
    const t0 = process.hrtime.bigint();

    log.req(`→ ${req.method} ${req.originalUrl}`, {
      id: req.id,
      ip: req.ip,
      ua: req.get('user-agent'),
      query: req.query,
      body: req.body
    });

    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      const lvl = res.statusCode >= 500 ? 'err' : res.statusCode >= 400 ? 'warn' : 'ok';
      const msg = `← ${res.statusCode} ${req.method} ${req.originalUrl} ${ms.toFixed(1)}ms`;
      log[lvl](msg, {
        id: req.id,
        user_id: req.user?.id,
        role: req.user?.role,
        bytes: res.getHeader('content-length') || undefined,
      });
    });

    next();
  };
}

/**
 * Express error handler to catch and log unhandled route errors.
 */
function expressErrorHandler() {
  // eslint-disable-next-line no-unused-vars
  return (err, req, res, _next) => {
    log.err('Unhandled API error', { id: req?.id, message: err?.message, stack: err?.stack });
    res.status(500).json({ error: 'Internal server error', req_id: req?.id });
  };
}

/**
 * Installs global process handlers to catch crashes.
 */
function installProcessHandlers() {
  process.on('unhandledRejection', (reason) => {
    log.err('Unhandled Promise Rejection', { reason: reason?.stack || String(reason) });
  });
  process.on('uncaughtException', (err) => {
    log.err('Uncaught Exception', { message: err?.message, stack: err?.stack });
    // Give the logger a moment to write the file, then exit to allow for a clean restart.
    setTimeout(() => process.exit(1), 100);
  });
}

module.exports = { log, attachRequestLogger, expressErrorHandler, installProcessHandlers };