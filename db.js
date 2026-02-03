// db.js
const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  // Add connection quality improvements
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
});

// Handle pool errors gracefully
// Note: Using console.error here to avoid circular dependency with logger module
pool.on('connection', (connection) => {
  connection.on('error', (err) => {
    console.error('Database connection error:', err.message);
  });
});

module.exports = pool;
