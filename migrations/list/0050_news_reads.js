// back/migrations/list/0050_news_reads.js
// Migration 0050: who (logged in) has opened which news article.
// One row per (article, user); repeat visits bump open_count / last_read_at.
// Anonymous visitors are never recorded.
module.exports = {
  name: '0050_news_reads',
  async up(pool) {
    await pool.query(`
CREATE TABLE IF NOT EXISTS \`news_reads\` (
  \`news_id\` INT UNSIGNED NOT NULL,
  \`user_id\` INT UNSIGNED NOT NULL,
  \`first_read_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  \`last_read_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  \`open_count\` INT NOT NULL DEFAULT 1,
  PRIMARY KEY (\`news_id\`, \`user_id\`),
  KEY \`idx_news_reads_user\` (\`user_id\`),
  CONSTRAINT \`fk_news_reads_entry\` FOREIGN KEY (\`news_id\`) REFERENCES \`news_entries\` (\`id\`) ON DELETE CASCADE,
  CONSTRAINT \`fk_news_reads_user\` FOREIGN KEY (\`user_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`);
  },
};
