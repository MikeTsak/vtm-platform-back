require('dotenv').config();
const pool = require('./db');
async function run() {
    const [rows] = await pool.query('SELECT id, data_url, size, filename FROM news_media');
    console.log(rows);
    process.exit(0);
}
run();
