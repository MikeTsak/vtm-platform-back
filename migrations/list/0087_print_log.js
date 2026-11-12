// back/migrations/list/0087_print_log.js
//
// Migration 0087: what the admin print tool (routes/printTool.js) has already
// printed, so the next run offers only what's new. One row per item, the
// latest print wins. kind: 'rumor' | 'news' | 'decree' | 'boon' (news and
// decrees share news_entries ids, so the kind is part of the key).
module.exports = {
  name: '0087_print_log',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS \`print_log\` (
        \`kind\` VARCHAR(16) NOT NULL,
        \`item_id\` INT(10) UNSIGNED NOT NULL,
        \`printed_at\` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        \`printed_by\` INT(10) UNSIGNED NULL DEFAULT NULL,
        PRIMARY KEY (\`kind\`, \`item_id\`),
        CONSTRAINT \`fk_print_log_user\` FOREIGN KEY (\`printed_by\`) REFERENCES \`users\` (\`id\`) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`);
  },
};
