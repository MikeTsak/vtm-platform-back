require('dotenv').config({ path: require('path').resolve(__dirname, '.env') });
const axios = require('axios');
const pool = require('./db');
const fs = require('fs');
const path = require('path');

const logFile = path.resolve(__dirname, 'migration.log');

function logProgress(msg) {
  console.log(msg);
  fs.appendFileSync(logFile, `[${new Date().toISOString()}] ${msg}\n`);
}

async function runMigration() {
  fs.appendFileSync(logFile, `=== NPC Avatar Migration Started ===\n`);
  logProgress('Starting NPC avatar migration...');
  
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
      
      logProgress(`Migrating avatar for NPC: ${ch.name}, URL: ${url}`);
      
      try {
        const response = await axios.get(url, { responseType: 'arraybuffer', timeout: 10000 });
        const buffer = Buffer.from(response.data, 'binary');
        
        await pool.query('UPDATE npcs SET avatar = ? WHERE id = ?', [buffer, ch.id]);
        
        logProgress(`Successfully migrated avatar for NPC ID: ${ch.id}`);
        migratedCount++;
      } catch (err) {
        logProgress(`Failed to fetch or save image for NPC ${ch.name} (id: ${ch.id}): ${err.message}`);
      }
    }
    
    logProgress(`Migration complete. Migrated ${migratedCount} NPC avatars.`);
  } catch (error) {
    logProgress(`Migration failed: ${error.message}`);
  } finally {
    process.exit(0);
  }
}

runMigration();
