require('dotenv').config();
const pool = require('./db');
const { VampireImageClient } = require('./utils/mikes-php-image-handler');
const { extFromMimeOrBuffer, isCdnUrlReachable } = require('./utils/cdnMedia');

const REPAIR_MODE = process.argv.includes('--repair');

// Ensure API Key exists
const apiKey = process.env.IMAGE_API_KEY;
if (!apiKey) {
    console.error('ERROR: Missing IMAGE_API_KEY in .env file!');
    process.exit(1);
}

const client = new VampireImageClient({
    baseUrl: 'https://img.miketsak.gr',
    apiKey: apiKey
});

// The tables and their blob columns to migrate
const migrations = [
    { table: 'users', column: 'avatar', urlCol: 'avatar_url', hasMime: false },
    { table: 'npcs', column: 'avatar', urlCol: 'avatar_url', hasMime: false },
    { table: 'retainers', column: 'avatar', urlCol: 'avatar_url', hasMime: false },
    { table: 'chat_groups', column: 'avatar', urlCol: 'avatar_url', hasMime: false },
    { table: 'chat_media', column: 'data', urlCol: 'data_url', hasMime: true },
    { table: 'news_media', column: 'data', urlCol: 'data_url', hasMime: true },
    { table: 'premonition_media', column: 'data', urlCol: 'data_url', hasMime: true }
];

async function migrate() {
    console.log(`🚀 [START] Starting Safe Media Migration${REPAIR_MODE ? ' (--repair)' : ''}...`);
    let totalUploaded = 0;

    for (const { table, column, urlCol, hasMime } of migrations) {
        console.log(`\n----------------------------------------`);
        console.log(`📂 [TABLE] Migrating ${table}.${column} -> ${urlCol}`);

        // 1. Ensure the URL column exists (schema.js should handle this, but just in case)
        try {
            await pool.query(`ALTER TABLE ${table} ADD COLUMN ${urlCol} VARCHAR(2048) DEFAULT NULL`);
            console.log(`  Added column ${urlCol} to ${table}`);
        } catch (e) {
            // Ignore if column already exists
        }

        // 2. Fetch rows needing migration (or broken/mismatched URLs in --repair mode)
        const selectCols = hasMime ? `id, ${column}, ${urlCol}, mime` : `id, ${column}, ${urlCol}`;
        const whereClause = REPAIR_MODE
            ? `${column} IS NOT NULL AND OCTET_LENGTH(${column}) >= 100`
            : `${column} IS NOT NULL AND ${urlCol} IS NULL`;
        const [rows] = await pool.query(`SELECT ${selectCols} FROM ${table} WHERE ${whereClause}`);

        console.log(`📊 [INFO] Found ${rows.length} candidate rows in ${table}.`);

        // 3. Upload and Update
        for (const row of rows) {
            const blob = row[column];
            if (!Buffer.isBuffer(blob)) continue;

            // Check if it's exceptionally small or broken
            if (blob.length < 100) {
                console.log(`  Skipping ${table}_${row.id} (Blob too small: ${blob.length} bytes)`);
                continue;
            }

            if (REPAIR_MODE && row[urlCol]) {
                const ok = await isCdnUrlReachable(row[urlCol], row.mime || null);
                if (ok) continue;
                console.log(`  🔧 [REPAIR] ${table}_${row.id}: ${row[urlCol]} is unreachable or mismatched, re-uploading...`);
            }

            const ext = extFromMimeOrBuffer(blob, row.mime || '');
            const filename = `${table}_${row.id}.${ext}`;

            console.log(`  ⏳ [UPLOAD] Row ID ${row.id}: Uploading ${filename} (${Math.round(blob.length / 1024)} KB)...`);
            const result = await client.uploadImage(blob, filename);

            if (result.success) {
                await pool.query(`UPDATE ${table} SET ${urlCol} = ? WHERE id = ?`, [result.url, row.id]);
                totalUploaded++;
            } else {
                console.error(`  [!] Failed to upload ${filename}: ${result.error}`);
            }
        }

        console.log(`✅ [DONE] Finished processing table: ${table}.`);
    }

    console.log(`\n========================================`);
    console.log(`🎉 [SUCCESS] Migration Complete! Total files migrated: ${totalUploaded}`);
    console.log(`🛡️  [SAFE] Original BLOBs were safely preserved in the database.`);
    process.exit(0);
}

migrate().catch(console.error);
