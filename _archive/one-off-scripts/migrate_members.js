const db = require('./db');

async function migrateTable() {
  try {
    await db.execute(`
      CREATE TABLE IF NOT EXISTS wiki_elysium_board_members (
        board_id INT NOT NULL,
        user_id INT NOT NULL,
        added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (board_id, user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    console.log('Successfully created wiki_elysium_board_members table.');
    process.exit(0);
  } catch (error) {
    console.error('Failed to create table:', error);
    process.exit(1);
  }
}

migrateTable();
