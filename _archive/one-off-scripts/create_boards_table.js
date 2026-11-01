const db = require('./db');

async function createTable() {
  try {
    await db.execute(`
      CREATE TABLE IF NOT EXISTS wiki_elysium_boards (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        data JSON,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    console.log('Table wiki_elysium_boards created or already exists.');
    process.exit(0);
  } catch (error) {
    console.error('Failed to create table:', error);
    process.exit(1);
  }
}

createTable();
