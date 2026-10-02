// One table for every dice roll. Live-session rolls used to live in
// live_session_rolls AND be copied into dice_rolls (note "[Session: …]"), with
// the dice chosen by the browser. From now on the server rolls everything into
// dice_rolls (services/rolls.js) and the session feed reads rows with a
// session_id.
//
// Moves every live_session_rolls row across (keeping its time, type, name and
// visibility), then deletes the old "[Session: …]" copies so nothing is
// counted twice. live_session_rolls itself is left in place, unused, as a
// fallback; it can be dropped once this has been in production a while.
const { computeV5Outcome } = require('../../services/dice');

module.exports = {
  name: '0043_unify_dice_rolls',
  async up(pool) {
    // Column by column: older databases (production among them) predate
    // is_hidden, so nothing here may assume the baseline's exact layout.
    const [existing] = await pool.query('SHOW COLUMNS FROM dice_rolls');
    const have = new Set(existing.map(c => c.Field));
    const columns = [
      ['session_id', 'INT(10) UNSIGNED NULL DEFAULT NULL'],
      ['roll_type', 'VARCHAR(50) NULL DEFAULT NULL'],
      ['character_name', 'VARCHAR(255) NULL DEFAULT NULL'],
      ['is_hidden', 'TINYINT(1) NOT NULL DEFAULT 0'],
      ['rerolled', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ];
    for (const [name, type] of columns) {
      if (!have.has(name)) await pool.query(`ALTER TABLE dice_rolls ADD COLUMN ${name} ${type}`);
    }
    const [keys] = await pool.query("SHOW INDEX FROM dice_rolls WHERE Key_name = 'idx_dice_rolls_session'");
    if (!keys.length) await pool.query('ALTER TABLE dice_rolls ADD KEY idx_dice_rolls_session (session_id, created_at)');

    // Already moved (or a fresh install with session rolls made by the new code).
    const [[done]] = await pool.query('SELECT COUNT(*) AS n FROM dice_rolls WHERE session_id IS NOT NULL');
    if (done.n > 0) return;
    const [legacy] = await pool.query("SHOW TABLES LIKE 'live_session_rolls'");
    if (!legacy.length) return;

    const [rows] = await pool.query(`
      SELECT r.*, COALESCE(c.user_id, s.admin_id) AS owner_id
      FROM live_session_rolls r
      LEFT JOIN characters c ON c.id = r.character_id
      LEFT JOIN live_sessions s ON s.id = r.session_id
      ORDER BY r.id`);

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      for (const r of rows) {
        let res = r.results;
        if (typeof res === 'string') { try { res = JSON.parse(res); } catch { res = null; } }
        res = res || {};
        const normal = (res.normal || []).map(Number);
        const hunger = (res.hunger || []).map(Number);
        const rouse = (res.rouse || []).map(Number);
        const o = rouse.length
          ? { successes: rouse.some(d => d >= 6) ? 1 : 0, crit_pairs: 0, messy_crit: false, bestial_failure: false }
          : computeV5Outcome({ normal, hunger, difficulty: res.difficulty || 0 });
        await conn.query(
          `INSERT INTO dice_rolls
             (user_id, character_id, session_id, roll_type, character_name, pool, hunger, sides, results_json,
              successes, crit_pairs, messy_crit, bestial_failure, note, is_hidden, created_at)
           VALUES (?,?,?,?,?,?,?,10,?,?,?,?,?,?,?,?)`,
          [r.owner_id || 0, r.character_id, r.session_id, r.roll_type || 'custom', r.character_name,
            Number(r.pool) || normal.length + hunger.length + rouse.length, Number(r.hunger) || hunger.length,
            JSON.stringify({ normal, hunger, ...(rouse.length ? { rouse } : {}), difficulty: res.difficulty || null }),
            Number(r.successes ?? o.successes) || 0, o.crit_pairs, o.messy_crit ? 1 : 0, o.bestial_failure ? 1 : 0,
            r.note ? String(r.note).slice(0, 255) : null, r.is_hidden ? 1 : 0, r.created_at]
        );
      }
      // The old mirrored copies of those same rolls.
      await conn.query("DELETE FROM dice_rolls WHERE session_id IS NULL AND note LIKE '[Session: %'");
      await conn.commit();
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  },
};
