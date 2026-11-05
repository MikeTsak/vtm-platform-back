// db.js
const mysql = require('mysql2/promise');
require('dotenv').config();
const { log } = require('./logger');

const options = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  charset: 'utf8mb4',
  waitForConnections: true,
  // The DB user has a server-side max_user_connections cap shared by EVERY
  // Passenger process (each has its own pool), so total = processes x this.
  // Requests beyond the limit queue here instead of failing with
  // ER_TOO_MANY_USER_CONNECTIONS.
  connectionLimit: Number(process.env.DB_POOL_SIZE) || 4,
  // Close idle connections so quiet or stale processes (e.g. old ones still
  // draining after a restart) don't sit on the user's quota. mysql2 defaults
  // maxIdle to connectionLimit, i.e. never closes them.
  maxIdle: 1,
  idleTimeout: 60000,
  enableKeepAlive: true,
  queueLimit: 0,
};
const pool = mysql.createPool(options);

// A background job holds its GET_LOCK connection for the whole run while its
// work queries `pool` (jobs/index.js). With the lock taken from `pool` too,
// enough jobs on one cron tick (5-6 at every :x0 minute) held every connection
// and waited forever for one more: every request then hung until the process
// was restarted (prod, 2026-11-02/03, once the pool went from 10 to 4-5). Locks
// get their own pool so a lock holder never sits on what its work waits for.
const lockPool = mysql.createPool({ ...options, connectionLimit: 2 });

for (const p of [pool, lockPool]) require('./utils/unrefIdleSweeper')(p);

// Backstop: mysql2 waits for a free connection forever. If code ever holds a
// connection while waiting on the pool for another, enough such requests at once
// hold all of them and the process stops answering until it is restarted (prod,
// 2026-11-04 17:24). Every pool.query/execute/getConnection goes through the core
// pool's getConnection(cb), so a timeout there fails that one request instead; a
// connection that turns up after the timeout goes straight back to the pool and
// the abandoned query never runs. Not on lockPool: jobs wait there on purpose.
// DB_ACQUIRE_TIMEOUT_MS (read per call) is for tests.
const corePool = pool.pool;
const coreGetConnection = corePool.getConnection.bind(corePool);
corePool.getConnection = (cb) => {
  let settled = false;
  const timer = setTimeout(() => {
    settled = true;
    pool.acquireTimeouts = (pool.acquireTimeouts || 0) + 1;
    log.err('Timed out waiting for a database connection', poolStats());
    cb(Object.assign(new Error('Timed out waiting for a database connection'), { code: 'POOL_ACQUIRE_TIMEOUT' }));
  }, Number(process.env.DB_ACQUIRE_TIMEOUT_MS) || 20000);
  coreGetConnection((err, conn) => {
    if (settled) { if (conn) conn.release(); return; }
    settled = true;
    clearTimeout(timer);
    cb(err, conn);
  });
};

// all = open connections, free = idle ones, queued = callers waiting for one,
// timeouts = acquire timeouts since boot.
function poolStats(p = pool) {
  const c = p.pool;
  return { all: c._allConnections.length, free: c._freeConnections.length, queued: c._connectionQueue.length, limit: c.config.connectionLimit, timeouts: p.acquireTimeouts || 0 };
}

// When MySQL refuses a NEW connection (the user's max_user_connections, or the
// server's max_connections), wait and try again instead of failing the request.
// This happens around restarts, while old Passenger processes still hold their
// connections. The refusal comes at connect time, before any SQL runs, so a retry
// never runs a statement twice. ~4 s worst case, then the error goes through.
const REFUSED = new Set(['ER_TOO_MANY_USER_CONNECTIONS', 'ER_CON_COUNT_ERROR']);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
for (const [p, method] of [pool, lockPool].flatMap((p) => ['query', 'execute', 'getConnection'].map((m) => [p, m]))) {
  const original = p[method].bind(p);
  p[method] = async (...args) => {
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await original(...args);
      } catch (err) {
        if (!REFUSED.has(err.code) || attempt >= 4) throw err;
        if (attempt === 0) log.warn('MySQL refused a connection, retrying', { code: err.code });
        await sleep(250 * 2 ** attempt);
      }
    }
  };
}

// Per-query acquire/release debug lines were dropped (2026-11): they flood the
// log file once LOG_LEVEL=debug, and the minute `health` line shows pool state.
pool.on('connection', (connection) => {
  connection.on('error', (err) => {
    if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code === 'ECONNRESET') {
       log.warn('⚠️ Database socket reset. Pool will handle reconnection.', { error: err.message });
    } else {
       log.error('❌ Database connection error:', { error: err.message });
    }
  });
});

module.exports = pool;
module.exports.lockPool = lockPool;
module.exports.poolStats = poolStats;