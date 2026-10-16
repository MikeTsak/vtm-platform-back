// utils/sheetLock.js
//
// Read-modify-write of a character's sheet under a row lock, so two writers
// (feeding, ST tracker, rouse, willpower reset) can't overwrite each other's
// change with a stale copy. Same pattern as routes/mechanics.js.
const { parseSheet } = require('./sheet');

/**
 * Locks the character row, parses its sheet, runs `fn(sheet, row, conn)` and
 * saves the (mutated) sheet in the same transaction. Use `conn` for any other
 * query in `fn`: a second pool connection touching rows that reference this
 * character would wait on the lock. `fn` returns { error, code? } to roll back.
 * Throws (after rolling back) if the stored sheet is not valid JSON.
 * @returns {Promise<object>} fn's result, or { notFound: true } if the row is gone
 */
async function withSheetLock(pool, characterId, fn) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[row]] = await conn.query('SELECT id, user_id, name, sheet FROM characters WHERE id=? FOR UPDATE', [characterId]);
    if (!row) { await conn.rollback(); return { notFound: true }; }
    // parseSheet reads garbage as {}: saving that back would wipe the sheet.
    if (typeof row.sheet === 'string' && row.sheet.trim()) JSON.parse(row.sheet);
    const sheet = parseSheet(row.sheet);
    const before = JSON.stringify(sheet);
    const result = await fn(sheet, row, conn);
    if (result?.error) { await conn.rollback(); return result; }
    // Skip a no-op write: the table is system-versioned, every UPDATE adds a history row.
    const after = JSON.stringify(sheet);
    if (after !== before) await conn.query('UPDATE characters SET sheet=? WHERE id=?', [after, characterId]);
    await conn.commit();
    return result || {};
  } catch (err) {
    await conn.rollback().catch(() => {});
    throw err;
  } finally {
    conn.release();
  }
}

module.exports = { withSheetLock };
