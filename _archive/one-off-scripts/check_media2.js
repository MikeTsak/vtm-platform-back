require('dotenv').config();
const pool = require('./db');
async function run() {
    const [rows] = await pool.query('SELECT id, data_url, data IS NULL as data_is_null FROM news_media WHERE id >= 15');
    console.log(rows);
    process.exit(0);
}
run();
