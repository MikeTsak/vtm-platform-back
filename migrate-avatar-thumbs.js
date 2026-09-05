require('dotenv').config();
const pool = require('./db');
const sharp = require('sharp');
const { VampireImageClient } = require('./utils/mikes-php-image-handler');

// One-off backfill for migrations/list/0011_avatar_thumb_urls.js: avatars
// uploaded before the thumb feature shipped have avatar_url_thumb = NULL and
// won't get one until someone re-uploads. This generates it now for every
// existing avatar instead of waiting.
//
// Doesn't need the original upload — resizing the already-processed 500x500
// (avatar_url, fetched over HTTP) or the raw BLOB fallback (avatar column)
// down to 160x160 is fine quality-wise, since the "full" was already a
// lossy resize/crop itself.
const apiKey = process.env.IMAGE_API_KEY;
if (!apiKey) {
  console.error('ERROR: Missing IMAGE_API_KEY in .env file!');
  process.exit(1);
}
const imageClient = new VampireImageClient({ baseUrl: 'https://img.miketsak.gr', apiKey });

const TABLES = [
  { table: 'users', prefix: 'users' },
  { table: 'npcs', prefix: 'npcs' },
  { table: 'retainers', prefix: 'retainers' },
  { table: 'email_identities', prefix: 'email_identities' },
];

async function fetchSourceBuffer(row) {
  if (row.avatar_url) {
    const res = await fetch(row.avatar_url);
    if (!res.ok) throw new Error(`Failed to fetch ${row.avatar_url}: HTTP ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  }
  if (row.avatar) return row.avatar; // BLOB fallback rows
  return null;
}

async function backfillOne(table, prefix, row) {
  const rawBuffer = await fetchSourceBuffer(row);
  if (!rawBuffer) return { skipped: true };

  const thumbBuffer = await sharp(rawBuffer)
    .resize(160, 160, { fit: 'cover' })
    .webp({ quality: 80 })
    .toBuffer();

  const result = await imageClient.uploadImage(thumbBuffer, `${prefix}_${row.id}_thumb.jpg`);
  if (!result || !result.success) throw new Error((result && result.error) || 'CDN upload failed');

  await pool.query(`UPDATE ${table} SET avatar_url_thumb = ? WHERE id = ?`, [result.url, row.id]);
  return { url: result.url };
}

async function migrate() {
  console.log('🚀 [START] Backfilling avatar thumbnails...');
  let totalDone = 0;
  let totalFailed = 0;

  for (const { table, prefix } of TABLES) {
    const [rows] = await pool.query(
      `SELECT id, avatar_url, avatar FROM ${table}
       WHERE avatar_url_thumb IS NULL AND (avatar_url IS NOT NULL OR avatar IS NOT NULL)`
    );
    console.log(`\n📂 [TABLE] ${table}: ${rows.length} avatar(s) need a thumb`);

    for (const row of rows) {
      try {
        const res = await backfillOne(table, prefix, row);
        if (res.skipped) continue;
        console.log(`  ✅ ${table}#${row.id} -> ${res.url}`);
        totalDone++;
      } catch (e) {
        console.error(`  ❌ ${table}#${row.id}: ${e.message}`);
        totalFailed++;
      }
    }
  }

  console.log(`\n🎉 [DONE] ${totalDone} thumbnail(s) generated, ${totalFailed} failed.`);
  process.exit(0);
}

migrate().catch((e) => {
  console.error(e);
  process.exit(1);
});
