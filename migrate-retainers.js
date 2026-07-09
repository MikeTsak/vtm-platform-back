const mysql = require('mysql2/promise');
require('dotenv').config();

async function runMigration() {
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'vampire',
  });

  try {
    const [characters] = await pool.query('SELECT id, sheet FROM characters');
    let migratedCount = 0;

    for (const char of characters) {
      if (!char.sheet) continue;
      
      let sheet;
      try {
        sheet = typeof char.sheet === 'string' ? JSON.parse(char.sheet) : char.sheet;
      } catch (e) {
        continue;
      }

      const merits = sheet?.advantages?.merits || [];
      let migrated = false;
      
      let retainerMeritIndex = merits.findIndex(m => m.id === 'backgrounds_retainers__retainers');

      while (retainerMeritIndex !== -1) {
        const rating = merits[retainerMeritIndex].rating || 1;
        
        // Create the retainer
        await pool.query(
          'INSERT INTO retainers (character_id, name, tier, sheet, xp) VALUES (?, ?, ?, ?, ?)',
          [char.id, 'Migrated Retainer', rating, JSON.stringify({ attributes: {}, skills: {}, disciplines: {} }), 0]
        );

        // Remove the merit
        merits.splice(retainerMeritIndex, 1);
        
        console.log(`Migrated Retainer for Character ID ${char.id} (Tier ${rating})`);
        migratedCount++;
        migrated = true;
        
        retainerMeritIndex = merits.findIndex(m => m.id === 'backgrounds_retainers__retainers');
      }

      if (migrated) {
        sheet.advantages.merits = merits;

        // Save the updated sheet
        await pool.query(
          'UPDATE characters SET sheet = ? WHERE id = ?',
          [JSON.stringify(sheet), char.id]
        );
      }
    }

    console.log(`Migration complete! Successfully migrated ${migratedCount} retainers.`);
  } catch (err) {
    console.error('Migration failed:', err);
  } finally {
    await pool.end();
  }
}

runMigration();
