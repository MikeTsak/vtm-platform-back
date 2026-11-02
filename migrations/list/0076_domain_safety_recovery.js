// back/migrations/list/0076_domain_safety_recovery.js
// Migration 0076: domain Safety no longer decays on its own (services/feedingCycleEnd.js).
//   domain_claims.safety_recovered_at  start of the division's 3-month recovery clock:
//       when the row was made, or its last +1. A failed hunt restarts the clock too,
//       read from the feedings table (so undoing that hunt undoes the restart).
//       Existing rows start from when the Feeding system went live.
//
// One-time repair of what the old automatic decay did, from the version history
// (0051), which starts on 2026-10-09; anything earlier cannot be seen:
//   - every Safety point a cycle-end decay run took is given back (max 10);
//   - a run that repeated an already processed cycle (2026-11-02, after a failed
//     latch read) also regrew Herd a second time: that point is taken back.
// A decay run is found by its latch write (feeding_last_decay_cycle_index): the
// division updates came just before it, the Herd regen just after.
//
// domain_claims is system-versioned (0051): ALTER needs KEEP, as in 0057.
const { log } = require('../../logger');
const { parseSheet } = require('../../utils/sheet');

async function versioned(conn, table) {
  const [rows] = await conn.query(
    `SELECT 1 FROM information_schema.TABLES
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND TABLE_TYPE = 'SYSTEM VERSIONED'`,
    [table]
  );
  return rows.length > 0;
}

module.exports = {
  name: '0076_domain_safety_recovery',
  async up(pool) {
    const conn = await pool.getConnection();
    try {
      const [cols] = await conn.query(
        `SELECT 1 FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'domain_claims' AND COLUMN_NAME = 'safety_recovered_at' LIMIT 1`
      );
      if (!cols.length) {
        await conn.query('SET SESSION system_versioning_alter_history = KEEP');
        await conn.query('ALTER TABLE `domain_claims` ADD COLUMN `safety_recovered_at` DATETIME NULL DEFAULT CURRENT_TIMESTAMP');
      }

      // The repair runs in one transaction, so a failure (and the retry on the next boot) never applies it twice.
      await conn.beginTransaction();
      await conn.query(`UPDATE domain_claims
                           SET safety_recovered_at = COALESCE((SELECT MIN(created_at) FROM feedings), NOW())`);

      const canSee = (await versioned(conn, 'app_settings')) && (await versioned(conn, 'domain_claims'))
        && (await versioned(conn, 'characters'));
      let safetyFixed = 0;
      let herdFixed = 0;
      if (canSee) {
        const [lost] = await conn.query(`
          SELECT n.division, COUNT(*) AS points
            FROM app_settings FOR SYSTEM_TIME ALL s
            JOIN domain_claims FOR SYSTEM_TIME ALL n
              ON n.row_start BETWEEN s.row_start - INTERVAL 10 SECOND AND s.row_start
            JOIN domain_claims FOR SYSTEM_TIME ALL o
              ON o.division = n.division AND o.row_end = n.row_start
           WHERE s.setting_key = 'feeding_last_decay_cycle_index'
             AND o.safety_rating = n.safety_rating + 1
           GROUP BY n.division`);
        for (const r of lost) {
          await conn.query(
            'UPDATE domain_claims SET safety_rating = LEAST(10, safety_rating + ?) WHERE division = ? AND safety_rating IS NOT NULL',
            [Number(r.points), r.division]
          );
        }
        safetyFixed = lost.length;

        // Herd points from runs that repeated a cycle (latch value unchanged).
        const [extra] = await conn.query(`
          SELECT DISTINCT cn.id
            FROM app_settings FOR SYSTEM_TIME ALL s
            JOIN app_settings FOR SYSTEM_TIME ALL sp
              ON sp.setting_key = s.setting_key AND sp.row_end = s.row_start AND sp.setting_value = s.setting_value
            JOIN characters FOR SYSTEM_TIME ALL cn
              ON cn.row_start BETWEEN s.row_start AND s.row_start + INTERVAL 60 SECOND
            JOIN characters FOR SYSTEM_TIME ALL co
              ON co.id = cn.id AND co.row_end = cn.row_start
           WHERE s.setting_key = 'feeding_last_decay_cycle_index'
             AND CAST(JSON_VALUE(cn.sheet, '$.herd_current') AS SIGNED) = CAST(JSON_VALUE(co.sheet, '$.herd_current') AS SIGNED) + 1`);
        for (const { id } of extra) {
          const [[c]] = await conn.query('SELECT sheet FROM characters WHERE id = ? FOR UPDATE', [id]);
          const sheet = c ? parseSheet(c.sheet) : null;
          if (!sheet || !(Number(sheet.herd_current) > 0)) continue;
          sheet.herd_current = Number(sheet.herd_current) - 1;
          await conn.query('UPDATE characters SET sheet = ? WHERE id = ?', [JSON.stringify(sheet), id]);
          herdFixed += 1;
        }
      }
      await conn.commit();
      log.info?.(`0076: Safety given back to ${safetyFixed} division(s), extra Herd point taken back from ${herdFixed} character(s)${canSee ? '' : ' (no version history: repair skipped)'}.`);
    } catch (e) {
      await conn.rollback().catch(() => {});
      throw e;
    } finally {
      conn.release();
    }
  },
};
