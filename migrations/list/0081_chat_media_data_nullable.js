// back/migrations/list/0081_chat_media_data_nullable.js
// Migration 0081: a chat image on the image host keeps no bytes in the row
// (services/chatMedia.js, 2026-11-04: data NULL, data_url set). Production's
// chat_media predates the baseline and had `data longblob NOT NULL`, so every
// such write failed: chat uploads answered 500 and the offload job re-uploaded
// the same images each run. The baseline already says NULL; this brings older
// databases in line. chat_media is not system-versioned.
module.exports = {
  name: '0081_chat_media_data_nullable',
  async up(pool) {
    const [[col]] = await pool.query(
      `SELECT IS_NULLABLE AS nullable FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'chat_media' AND COLUMN_NAME = 'data'`
    );
    if (!col || col.nullable === 'YES') return;
    await pool.query('ALTER TABLE `chat_media` MODIFY `data` LONGBLOB NULL DEFAULT NULL');
  },
};
