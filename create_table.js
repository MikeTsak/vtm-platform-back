const mysql = require('mysql2/promise');
require('dotenv').config();

async function run() {
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'vampire',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  try {
    try {
      await pool.query(`ALTER TABLE users ADD COLUMN push_settings JSON`);
      await pool.query(`UPDATE users SET push_settings = '{"chat": false, "system": false}' WHERE push_settings IS NULL`);
      console.log("Added push_settings column");
    } catch (e) {
      if (!e.message.includes('Duplicate column name')) console.error("Error adding column:", e.message);
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_push_subscriptions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT UNSIGNED NOT NULL,
        endpoint VARCHAR(512) NOT NULL UNIQUE,
        p256dh VARCHAR(255) NOT NULL,
        auth VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    console.log("Table created successfully!");
  } catch (err) {
    console.error("Error showing table:", err);
  } finally {
    pool.end();
  }
}

run();
