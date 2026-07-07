require('dotenv').config();
const axios = require('axios');
const pool = require('./db');

async function runMigration() {
  console.log('Starting avatar migration...');
  
  try {
    const [npcs] = await pool.query('SELECT id, name, image_url FROM npcs WHERE image_url IS NOT NULL AND image_url != ""');
    
    let migratedCount = 0;
    
    for (const ch of npcs) {
      if (!ch.image_url) continue;
      
      const trimmed = ch.image_url.trim();
      let url = trimmed;
      if (!trimmed.startsWith('http')) {
        const cleanName = trimmed.replace(/\.jpg$/i, '');
        url = `https://portal.attlarp.gr/images.court/${encodeURIComponent(cleanName)}.jpg`;
      }
      
      console.log(`Migrating avatar for character: ${ch.name}, URL: ${url}`);
      
      try {
        const response = await axios.get(url, { responseType: 'arraybuffer' });
        const buffer = Buffer.from(response.data, 'binary');
        
        await pool.query('UPDATE npcs SET avatar = ? WHERE id = ?', [buffer, ch.id]);
        console.log(`Successfully updated avatar for user_id: ${ch.id}`);
        migratedCount++;
      } catch (err) {
        console.error(`Failed to fetch or save image for character ${ch.name} (user_id: ${ch.id}): ${err.message}`);
      }
    }
    
    console.log(`Migration complete. Migrated ${migratedCount} avatars.`);
  } catch (error) {
    console.error('Migration failed:', error);
  } finally {
    process.exit(0);
  }
}

runMigration();
