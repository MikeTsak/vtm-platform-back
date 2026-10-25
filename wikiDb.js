// wikiDb.js
// Dedicated connection pool for the Wiki Database (wiki.larp)
const mysql = require('mysql2/promise');
require('dotenv').config();
const { log } = require('./logger');

const getEnv = (key, fallback = '') => {
  if (process.env[key] !== undefined) return process.env[key];
  const found = Object.entries(process.env).find(([k]) => k.trim() === key);
  return found ? found[1] : fallback;
};

const wikiPool = mysql.createPool({
  host: getEnv('WIKI_DB_HOST', process.env.DB_HOST || '127.0.0.1'),
  port: Number(getEnv('WIKI_DB_PORT', process.env.DB_PORT || 3306)),
  user: getEnv('WIKI_DB_USER', 'wiki'),
  password: getEnv('WIKI_DB_PASS', ''),
  database: getEnv('WIKI_DB_NAME', 'wiki.larp'),
  charset: 'utf8mb4',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

wikiPool.on('connection', (connection) => {
  connection.on('acquire', () => {
    log.debug('Wiki DB connection acquired from pool');
  });

  connection.on('release', () => {
    log.debug('Wiki DB connection released to pool');
  });

  connection.on('error', (err) => {
    if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code === 'ECONNRESET') {
      log.warn('⚠️ Wiki Database socket reset. Pool will handle reconnection.', { error: err.message });
    } else {
      log.error('❌ Wiki Database connection error:', { error: err.message });
    }
  });
});

module.exports = wikiPool;
