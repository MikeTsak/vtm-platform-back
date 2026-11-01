const db = require('./db');

async function migrateTable() {
  try {
    await db.execute(`
      ALTER TABLE wiki_elysium_boards
      ADD COLUMN visibility VARCHAR(50) DEFAULT 'public',
      ADD COLUMN owner_id INT DEFAULT NULL;
    `);
    console.log('Successfully altered wiki_elysium_boards.');
    process.exit(0);
  } catch (error) {
    if (error.code === 'ER_DUP_FIELDNAME') {
      console.log('Columns already exist. Skipping.');
      process.exit(0);
    }
    console.error('Failed to alter table:', error);
    process.exit(1);
  }
}

migrateTable();
