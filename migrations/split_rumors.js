const { pool } = require('../db');

async function migrateRumors() {
  try {
    console.log('--- Starting Rumors Migration ---');
    
    // 1. Create the new rumors table
    console.log('Creating rumors table...');
    await pool.promise().query(`
      CREATE TABLE IF NOT EXISTS rumors (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        author_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        body TEXT NOT NULL,
        media_url VARCHAR(2048),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 2. Count rumors to migrate
    const [rows] = await pool.promise().query(`SELECT COUNT(*) as count FROM news_entries WHERE theme = 'RUMOR'`);
    const count = rows[0].count;
    
    if (count > 0) {
      console.log(`Found ${count} rumors to migrate. Inserting into rumors table...`);
      
      // 3. Insert into rumors
      await pool.promise().query(`
        INSERT INTO rumors (id, author_id, title, body, media_url, created_at)
        SELECT id, author_id, title, body, media_url, created_at 
        FROM news_entries 
        WHERE theme = 'RUMOR'
      `);

      // 4. Delete from news_entries
      console.log('Deleting migrated rumors from news_entries...');
      await pool.promise().query(`DELETE FROM news_entries WHERE theme = 'RUMOR'`);
      console.log('Migration completed successfully.');
    } else {
      console.log('No rumors found in news_entries. Nothing to migrate.');
    }
  } catch (error) {
    console.error('Migration failed:', error);
  } finally {
    process.exit(0);
  }
}

migrateRumors();
