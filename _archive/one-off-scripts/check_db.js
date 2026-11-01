require('dotenv').config();
const pool = require('./db'); // uses DB_* credentials from the environment
async function run() {
  try {
    const [tables] = await pool.query('SHOW TABLES LIKE "%wiki%"');
    console.log('TABLES:', tables);
    try { const [cols1] = await pool.query('SHOW COLUMNS FROM wiki_categories'); console.log('wiki_categories:', cols1); } catch (e) { console.log('No wiki_categories'); }
    try { const [cols2] = await pool.query('SHOW COLUMNS FROM wiki_tags'); console.log('wiki_tags:', cols2); } catch (e) { console.log('No wiki_tags'); }
    try { const [cols3] = await pool.query('SHOW COLUMNS FROM wiki_article_versions'); console.log('wiki_article_versions:', cols3); } catch (e) { console.log('No versions'); }
  } catch (e) {
    console.log(e);
  } finally {
    pool.end();
  }
}
run();
