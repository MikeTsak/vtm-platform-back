// back/migrations/list/0072_runtime_status.js
// Migration 0072: process liveness off the versioned app_settings table.
//
// discordWorker wrote discord_bot_last_heartbeat AND discord_bot_name into
// app_settings every 15 s. app_settings is SYSTEM VERSIONED (0051) and MariaDB
// writes a history row even for an UPDATE that changes nothing, so that was
// ~11.5k history rows a day — 267k of the table's 270k rows, for 33 settings.
//
// runtime_status is deliberately NOT versioned: it holds throwaway liveness
// state (bot heartbeat, active bot instance) that has no history worth keeping.
//
// Then the junk history is purged while keeping every real setting's history.
// DELETE HISTORY is not transactional (a ROLLBACK does not undo it), so the
// rows to keep are copied out first and the purge only starts once inserting
// history is known to be permitted. Idempotent: safe to re-run.

const MOVED_KEYS = ['discord_bot_last_heartbeat', 'discord_bot_name', 'discord_bot_active_instance'];

module.exports = {
  name: '0072_runtime_status',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS runtime_status (
        status_key   VARCHAR(64)  NOT NULL PRIMARY KEY,
        status_value VARCHAR(255) NULL,
        updated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    const ph = MOVED_KEYS.map(() => '?').join(',');
    await pool.query(`DELETE FROM app_settings WHERE setting_key IN (${ph})`, MOVED_KEYS);

    // Same connection throughout: the session variable and the temp table are per connection.
    const conn = await pool.getConnection();
    try {
      try {
        await conn.query('SET SESSION system_versioning_insert_history = 1');
      } catch (e) {
        // No permission to write history rows back: keep the junk rather than lose real history.
        console.warn('[0072] skipped app_settings history purge:', e.message);
        return;
      }
      // A real table, not TEMPORARY: if the re-insert below fails, the kept history
      // survives the connection and can be restored by hand. Dropped only on success.
      const [[leftover]] = await conn.query("SHOW TABLES LIKE '_0072_app_settings_history'");
      if (leftover) throw new Error('_0072_app_settings_history exists from a failed run: restore it into app_settings by hand, then drop it');
      await conn.query(
        `CREATE TABLE _0072_app_settings_history AS
           SELECT setting_key, setting_value, updated_at, ROW_START AS rs, ROW_END AS re
             FROM app_settings FOR SYSTEM_TIME ALL
            WHERE ROW_END < NOW(6) AND setting_key NOT IN (${ph})`,
        MOVED_KEYS
      );
      const [[{ n: keep }]] = await conn.query('SELECT COUNT(*) AS n FROM _0072_app_settings_history');
      await conn.query('DELETE HISTORY FROM app_settings');
      await conn.query(
        `INSERT INTO app_settings (setting_key, setting_value, updated_at, ROW_START, ROW_END)
         SELECT setting_key, setting_value, updated_at, rs, re FROM _0072_app_settings_history`
      );
      await conn.query('DROP TABLE _0072_app_settings_history');
      console.log(`[0072] app_settings history purged; kept ${keep} real history rows`);
    } finally {
      conn.release();
    }
  },
};
