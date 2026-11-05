// db.js backstop: a caller that waits too long for a connection fails instead of
// hanging the process, and its query never runs once a connection frees up.
const pool = require('../db');

describe('pool acquire timeout', () => {
  beforeAll(() => { process.env.DB_ACQUIRE_TIMEOUT_MS = '300'; });
  afterAll(() => { delete process.env.DB_ACQUIRE_TIMEOUT_MS; });

  it('every connection held + one more asked for: fails fast, the pool recovers, the abandoned write never runs', async () => {
    const held = [];
    for (let i = 0; i < pool.poolStats().limit; i++) held.push(await pool.getConnection());
    try {
      await expect(pool.query("INSERT INTO app_settings (setting_key, setting_value) VALUES ('acquire_timeout_probe', 'x')"))
        .rejects.toMatchObject({ code: 'POOL_ACQUIRE_TIMEOUT' });
      await expect(pool.getConnection()).rejects.toMatchObject({ code: 'POOL_ACQUIRE_TIMEOUT' });
    } finally {
      held.forEach((c) => c.release());
    }
    await new Promise((r) => setTimeout(r, 50)); // late hand-offs go back to the pool
    const [[row]] = await pool.query("SELECT COUNT(*) AS n FROM app_settings WHERE setting_key = 'acquire_timeout_probe'");
    expect(Number(row.n)).toBe(0);
    expect(pool.poolStats().queued).toBe(0);
  });
});
