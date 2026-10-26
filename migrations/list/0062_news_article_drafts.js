// back/migrations/list/0062_news_article_drafts.js
// Migration 0062: Store server-side drafts for news articles
// Allows writers and admins to automatically draft news articles while writing,
// resume them later across sessions or devices, and manage drafts in Admin / News panels.

module.exports = {
  name: '0062_news_article_drafts',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS \`news_article_drafts\` (
        \`id\` INT UNSIGNED NOT NULL AUTO_INCREMENT,
        \`user_id\` INT(10) UNSIGNED NOT NULL,
        \`title\` VARCHAR(255) NOT NULL DEFAULT '',
        \`subtitle\` VARCHAR(255) NULL DEFAULT NULL,
        \`body\` MEDIUMTEXT NOT NULL,
        \`theme\` VARCHAR(100) NOT NULL DEFAULT 'ERT',
        \`journalist_name\` VARCHAR(100) NULL DEFAULT NULL,
        \`discord_prefix\` VARCHAR(255) NULL DEFAULT NULL,
        \`is_custom_prefix\` TINYINT(1) NOT NULL DEFAULT 0,
        \`is_private\` TINYINT(1) NOT NULL DEFAULT 0,
        \`media_url\` VARCHAR(2048) NULL DEFAULT NULL,
        \`created_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        \`updated_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (\`id\`),
        KEY \`idx_news_drafts_user\` (\`user_id\`, \`updated_at\`),
        CONSTRAINT \`fk_news_drafts_user\` FOREIGN KEY (\`user_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
