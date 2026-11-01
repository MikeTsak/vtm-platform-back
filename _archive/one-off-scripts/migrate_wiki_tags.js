const pool = require('./db');

async function run() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS wiki_tags (
      id INT AUTO_INCREMENT PRIMARY KEY, 
      name VARCHAR(255) NOT NULL, 
      slug VARCHAR(255) NOT NULL UNIQUE, 
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS wiki_article_tags (
      article_id INT NOT NULL, 
      tag_id INT NOT NULL, 
      PRIMARY KEY (article_id, tag_id), 
      FOREIGN KEY (article_id) REFERENCES wiki_articles(id) ON DELETE CASCADE, 
      FOREIGN KEY (tag_id) REFERENCES wiki_tags(id) ON DELETE CASCADE
    )`);
    console.log('Tables created successfully');
  } catch(e) {
    console.error('Error creating tables:', e);
  }
  process.exit(0);
}

run();
