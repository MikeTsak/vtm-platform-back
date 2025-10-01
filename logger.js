// logger.js
const crypto = require('crypto');
const fs = require('fs');

// --- Configuration via Environment Variables ---

// JSON lines output (good for aggregators)
const USE_JSON  = process.env.LOG_JSON === '1';

// Emojis in pretty mode
const USE_EMOJI = process.env.LOG_EMOJI !== '0';

// Verbosity: debug | info | warn | error
const LEVEL     = (process.env.LOG_LEVEL || 'debug').toLowerCase(); // default: debug (log everything)

// Optional file logging
const LOG_FILE  = process.env.LOG_FILE || '';

// Include headers/bodies (safe redaction + truncation)
const LOG_HEADERS = process.env.LOG_HEADERS !== '0'; // default ON
const LOG_BODIES  = process.env.LOG_BODIES  !== '0'; // default ON

// Tap console.* into the logger
const TAP_CONSOLE = process.env.LOG_TAP_CONSOLE === '1';

// --- Logger Internals ---

const LEVEL_RANK = { debug: 10, info: 20, warn: 30, error: 40 };
const allow = (lvl) => LEVEL_RANK[lvl] >= LEVEL_RANK[LEVEL];

const EMO = {
  start: '🚀', auth: '🔐', char: '🧛', xp: '✨', dt: '🕰️', dom: '🏰', adm: '🛡️',
  ok: '✅', warn: '⚠️', err: '💥', req: '➡️', res: '⬅️', mail: '✉️', db: '🗄️', info: 'ℹ️',
  http: '🌐', dbg: '🐛'
};

const SENSITIVE_KEYS = [
  'password','pass','pwd','authorization','cookie','token',
  'secret','key','x-api-key','set-cookie'
];

const MAX_STR = 2000;      // Trim long strings
const MAX_BUF = 64 * 1024; // Cap collected response body to 64KB

function redact(value, depth = 0) {
  if (value == null || depth > 5) return value;
  if (Array.isArray(value)) return value.map(v => redact(v, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) {
      const low = k.toLowerCase();
      out[k] = SENSITIVE_KEYS.some(s => low.includes(s))
        ? '[redacted]'
        : redact(value[k], depth + 1);
    }
    return out;
  }
  if (Buffer.isBuffer(value)) {
    return value.length > MAX_BUF
      ? value.subarray(0, MAX_BUF).toString('utf8') + '…[truncated]'
      : value.toString('utf8');
  }
  if (typeof value === 'string' && value.length > MAX_STR) {
    return value.slice(0, MAX_STR) + '…';
  }
  return value;
}

function nowISO() { return new Date().toISOString(); }

function writeFileLine(line) {
  if (!LOG_FILE) return;
  fs.appendFile(LOG_FILE, line + '\n', (err) => {
    if (err) console.error(`Failed to write to log file ${LOG_FILE}:`, err);
  });
}

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
    writeFileLine(`${payload.t} [${level.toUpperCase()}] ${line}`);
  }
}

// Public log object with different categories
const log = {
  debug: (m, c) => emit('debug', 'dbg',   m, c),
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
  http:  (m, c) => emit('info',  'http',  m, c),
};

// Express middleware to log all incoming requests and their responses.
function attachRequestLogger() {
  return (req, res, next) => {
    req.id = req.headers['x-request-id'] || crypto.randomUUID().slice(0, 8);
    const t0 = process.hrtime.bigint();

    // Capture response body by monkey patching res.write/end
    let bodyChunks = [];
    if (LOG_BODIES) {
      const origWrite = res.write.bind(res);
      const origEnd = res.end.bind(res);

      res.write = (chunk, enc, cb) => {
        try {
          if (chunk) {
            if (typeof chunk === 'string') chunk = Buffer.from(chunk, enc || 'utf8');
            if (Buffer.isBuffer(chunk)) {
              const remaining = Math.max(0, MAX_BUF - Buffer.concat(bodyChunks).length);
              if (remaining > 0) bodyChunks.push(chunk.subarray(0, remaining));
            }
          }
        } catch (_) { /* ignore */ }
        return origWrite(chunk, enc, cb);
      };

      res.end = (chunk, enc, cb) => {
        try {
          if (chunk) {
            if (typeof chunk === 'string') chunk = Buffer.from(chunk, enc || 'utf8');
            if (Buffer.isBuffer(chunk)) {
              const remaining = Math.max(0, MAX_BUF - Buffer.concat(bodyChunks).length);
              if (remaining > 0) bodyChunks.push(chunk.subarray(0, remaining));
            }
          }
        } catch (_) { /* ignore */ }
        return origEnd(chunk, enc, cb);
      };
    }

    const reqCtx = {
      id: req.id,
      ip: req.ip,
      ua: req.get('user-agent'),
      method: req.method,
      url: req.originalUrl,
      ...(LOG_HEADERS ? { headers: req.headers } : {}),
      ...(LOG_BODIES ? { query: req.query, body: req.body } : { query: req.query }),
    };

    log.req(`→ ${req.method} ${req.originalUrl}`, reqCtx);

    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      const lvl = res.statusCode >= 500 ? 'err'
                : res.statusCode >= 400 ? 'warn'
                : 'ok';
      const msg = `← ${res.statusCode} ${req.method} ${req.originalUrl} ${ms.toFixed(1)}ms`;

      let resBody;
      if (LOG_BODIES && bodyChunks.length) {
        try {
          const buf = Buffer.concat(bodyChunks);
          resBody = buf.length > MAX_BUF ? buf.subarray(0, MAX_BUF) : buf;
        } catch (_) { /* ignore */ }
      }

      const resCtx = {
        id: req.id,
        user_id: req.user?.id,
        role: req.user?.role,
        bytes: res.getHeader('content-length') || undefined,
        ...(LOG_HEADERS ? { headers: headersToObject(res.getHeaders && res.getHeaders()) } : {}),
        ...(LOG_BODIES && resBody ? { body: resBody } : {}),
      };

      log[lvl](msg, resCtx);
    });

    next();
  };
}

function headersToObject(h) {
  if (!h) return undefined;
  try { return JSON.parse(JSON.stringify(h)); } catch { return h; }
}

// Express error handler to catch and log unhandled route errors.
function expressErrorHandler() {
  // eslint-disable-next-line no-unused-vars
  return (err, req, res, _next) => {
    log.err('Unhandled API error', {
      id: req?.id,
      message: err?.message,
      stack: err?.stack
    });
    res.status(500).json({ error: 'Internal server error', req_id: req?.id });
  };
}

// Installs global process handlers to catch crashes.
function installProcessHandlers() {
  process.on('unhandledRejection', (reason) => {
    log.err('Unhandled Promise Rejection', { reason: reason?.stack || String(reason) });
  });
  process.on('uncaughtException', (err) => {
    log.err('Uncaught Exception', { message: err?.message, stack: err?.stack });
    setTimeout(() => process.exit(1), 100);
  });
}

// Optionally route console.* through our logger for complete visibility
function tapConsole() {
  if (!TAP_CONSOLE) return;
  const _log = console.log.bind(console);
  const _warn = console.warn.bind(console);
  const _err = console.error.bind(console);

  console.log = (...args) => {
    try { log.debug(args.map(a => serializeArg(a)).join(' ')); } catch (_) { /* ignore */ }
    _log(...args);
  };
  console.warn = (...args) => {
    try { log.warn(args.map(a => serializeArg(a)).join(' ')); } catch (_) { /* ignore */ }
    _warn(...args);
  };
  console.error = (...args) => {
    try { log.err(args.map(a => serializeArg(a)).join(' ')); } catch (_) { /* ignore */ }
    _err(...args);
  };
}

function serializeArg(a) {
  if (a instanceof Error) return `${a.message}\n${a.stack}`;
  if (typeof a === 'object') {
    try { return JSON.stringify(redact(a)); } catch { return String(a); }
  }
  return String(a);
}

// Initialize console tap if requested
tapConsole();

module.exports = {
  log,
  attachRequestLogger,
  expressErrorHandler,
  installProcessHandlers
};
