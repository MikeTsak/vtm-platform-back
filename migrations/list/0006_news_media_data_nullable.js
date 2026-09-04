// Some deployments' `news_media` table predates this migration system and
// still has `data` defined NOT NULL. POST /api/news/upload intentionally
// stores data: NULL whenever the external image CDN upload succeeds (only
// falling back to storing the raw bytes in MySQL when the CDN call fails) —
// so a NOT NULL `data` column makes every successful CDN upload fail with
// "Column 'data' cannot be null", while it works fine wherever the column
// was already nullable (e.g. a fresh database built from
// 0001_baseline, where it's `longblob DEFAULT NULL`).
module.exports = {
  name: '0006_news_media_data_nullable',
  async up(pool) {
    await pool.query('ALTER TABLE news_media MODIFY COLUMN data LONGBLOB NULL');
  },
};
