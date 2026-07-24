require('dotenv').config();
const pool = require('./db');

async function fixMediaUrls() {
    try {
        console.log('Fetching news_entries...');
        const [newsRows] = await pool.query("SELECT id, media_url FROM news_entries WHERE media_url LIKE '/api/news/media/%' OR media_url LIKE '%/api/news/media/%'");
        console.log(`Found ${newsRows.length} news_entries with blob URLs.`);

        for (const row of newsRows) {
            const match = row.media_url.match(/\/api\/news\/media\/(\d+)/);
            if (match && match[1]) {
                const mediaId = match[1];
                const [mediaRows] = await pool.query('SELECT data_url FROM news_media WHERE id = ?', [mediaId]);
                
                if (mediaRows.length > 0 && mediaRows[0].data_url) {
                    await pool.query('UPDATE news_entries SET media_url = ? WHERE id = ?', [mediaRows[0].data_url, row.id]);
                    console.log(`✅ Updated news_entries ID ${row.id} to use data_url: ${mediaRows[0].data_url}`);
                } else {
                    console.log(`⚠️  No data_url found in news_media for media ID ${mediaId} (news_entries ID ${row.id})`);
                }
            }
        }

        console.log('\nFetching rumors...');
        const [rumorRows] = await pool.query("SELECT id, media_url FROM rumors WHERE media_url LIKE '/api/news/media/%' OR media_url LIKE '%/api/news/media/%'");
        console.log(`Found ${rumorRows.length} rumors with blob URLs.`);

        for (const row of rumorRows) {
            const match = row.media_url.match(/\/api\/news\/media\/(\d+)/);
            if (match && match[1]) {
                const mediaId = match[1];
                const [mediaRows] = await pool.query('SELECT data_url FROM news_media WHERE id = ?', [mediaId]);
                
                if (mediaRows.length > 0 && mediaRows[0].data_url) {
                    await pool.query('UPDATE rumors SET media_url = ? WHERE id = ?', [mediaRows[0].data_url, row.id]);
                    console.log(`✅ Updated rumors ID ${row.id} to use data_url: ${mediaRows[0].data_url}`);
                } else {
                    console.log(`⚠️  No data_url found in news_media for media ID ${mediaId} (rumors ID ${row.id})`);
                }
            }
        }

        console.log('\nDone updating media URLs.');
    } catch (err) {
        console.error('Database error:', err);
    } finally {
        process.exit(0);
    }
}

fixMediaUrls();
