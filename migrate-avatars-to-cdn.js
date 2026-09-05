require('dotenv').config();
const pool = require('./db');
const sharp = require('sharp');
const { VampireImageClient } = require('./utils/mikes-php-image-handler');

// One-off cleanup: the PUT .../avatar routes no longer ever write a BLOB
// fallback (CDN-only now, same as email_identities always was). This
// migrates any row still holding raw bytes in the `avatar` column to the
// CDN, then clears that column everywhere it's no longer needed —
// reclaiming the space and finishing the move to "mikesphp only, no blobs".
const apiKey = process.env.IMAGE_API_KEY;
if (!apiKey) {
  console.error('ERROR: Missing IMAGE_API_KEY in .env file!');
  process.exit(1);
}
const imageClient = new VampireImageClient({ baseUrl: 'https://img.miketsak.gr', apiKey });

const TABLES = ['users', 'npcs', 'retainers']; // email_identities never had a blob column

async function migrateOne(table, row) {
  // avatar_url already set means this blob is just orphaned leftover bytes
  // from before CDN uploads existed for this row — nothing to upload.
  if (row.avatar_url) return { uploaded: false };

  const buffer = await sharp(row.avatar)
    .resize(500, 500, { fit: 'cover' })
    .webp({ quality: 80 })
    .toBuffer();
  const thumbBuffer = await sharp(row.avatar)
    .resize(160, 160, { fit: 'cover' })
    .webp({ quality: 80 })
    .toBuffer();

  const result = await imageClient.uploadImage(buffer, `${table}_${row.id}.jpg`);
  if (!result || !result.success) throw new Error((result && result.error) || 'CDN upload failed');

  let thumbUrl = null;
  try {
    const thumbResult = await imageClient.uploadImage(thumbBuffer, `${table}_${row.id}_thumb.jpg`);
    if (thumbResult && thumbResult.success) thumbUrl = thumbResult.url;
  } catch (e) {
    console.warn(`  [!] Thumb upload failed for ${table}#${row.id}: ${e.message}`);
  }

  await pool.query(`UPDATE ${table} SET avatar_url = ?, avatar_url_thumb = ? WHERE id = ?`, [result.url, thumbUrl, row.id]);
  return { uploaded: true, url: result.url };
}

async function migrate() {
  console.log('🚀 [START] Migrating avatar BLOBs to CDN, then clearing them...');
  let totalUploaded = 0;
  let totalCleared = 0;
  let totalFailed = 0;

  for (const table of TABLES) {
    const [rows] = await pool.query(`SELECT id, avatar_url, avatar FROM ${table} WHERE avatar IS NOT NULL`);
    console.log(`\n📂 [TABLE] ${table}: ${rows.length} row(s) with leftover blob data`);

    for (const row of rows) {
      try {
        const res = await migrateOne(table, row);
        if (res.uploaded) {
          console.log(`  ⬆️  ${table}#${row.id} uploaded to CDN -> ${res.url}`);
          totalUploaded++;
        }
        // Only clear after avatar_url is confirmed set (just now, or already).
        await pool.query(`UPDATE ${table} SET avatar = NULL WHERE id = ?`, [row.id]);
        console.log(`  🧹 ${table}#${row.id} blob cleared`);
        totalCleared++;
      } catch (e) {
        console.error(`  ❌ ${table}#${row.id}: ${e.message} (blob left untouched)`);
        totalFailed++;
      }
    }
  }

  console.log(`\n🎉 [DONE] ${totalUploaded} uploaded to CDN, ${totalCleared} blob(s) cleared, ${totalFailed} failed.`);
  process.exit(0);
}

migrate().catch((e) => {
  console.error(e);
  process.exit(1);
});
