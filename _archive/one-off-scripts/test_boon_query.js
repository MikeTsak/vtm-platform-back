const pool = require('./db');

async function run() {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM boons WHERE recorded_by = 34 AND DATE(created_at) = '2026-09-19'`
    );
    console.log("Found boons:", rows.length);
    console.log(rows);
  } catch (err) {
    console.error(err);
  } finally {
    pool.end();
  }
}

run();
