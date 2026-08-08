const mysql = require('mysql2/promise');
require('dotenv').config();

(async () => {
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'vampire_platform'
  });

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wiki_timeline_events (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      date_label VARCHAR(200) NOT NULL,
      description TEXT,
      article_slug VARCHAR(255),
      category VARCHAR(100) DEFAULT 'General',
      sort_order INT DEFAULT 0,
      created_by INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `);
  console.log('Created wiki_timeline_events');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wiki_journal_entries (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      title VARCHAR(255) NOT NULL DEFAULT 'Untitled Entry',
      content LONGTEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  console.log('Created wiki_journal_entries');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wiki_admin_notes (
      id INT AUTO_INCREMENT PRIMARY KEY,
      article_id INT NOT NULL,
      author_id INT NOT NULL,
      content LONGTEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (article_id) REFERENCES wiki_articles(id) ON DELETE CASCADE,
      FOREIGN KEY (author_id) REFERENCES users(id)
    )
  `);
  console.log('Created wiki_admin_notes');

  console.log('All tables created successfully');
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
