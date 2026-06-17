// db.js
const mysql = require('mysql2/promise');
require('dotenv').config();
const { log } = require('./logger');

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  charset: 'utf8mb4',
  waitForConnections: true,
  connectionLimit: 10,

  // --- CRITICAL FIXES FOR ECONNRESET ---

  // 1. Keep the connection alive by sending a "ping" every 10 seconds
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,

  // 2. Automatically drop connections that have been idle too long
  // (Prevents using a connection the server already closed)
  idleTimeout: 60000,

  // 3. Max lifetime of a connection (Refreshes connections every 30 mins)
  maxIdle: 10,
  maxLifetimeBeforeRecycle: 1800000,

  // 4. Queue limit (0 = infinite)
  queueLimit: 0,
});

// Improved Error Handling
pool.on('connection', (connection) => {
  // Log connection acquire/release for debugging
  connection.on('acquire', () => {
    log.db('Connection acquired from pool');
  });

  connection.on('release', () => {
    log.db('Connection released to pool');
  });

  // Check for errors on individual connections
  connection.on('error', (err) => {
    if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code === 'ECONNRESET') {
       log.warn('⚠️ Database socket reset. Pool will handle reconnection.', { error: err.message });
    } else {
       log.error('❌ Database connection error:', { error: err.message });
    }
  });
});

// Log pool events
pool.on('acquire', (connection) => {
  log.db('Pool connection acquired');
});

pool.on('release', (connection) => {
  log.db('Pool connection released');
});

module.exports = pool;