// back/migrations/list/0074_job_status.js
// Migration 0074: job_status, the latest outcome of each background job
// (jobs/index.js runJob), read by the admin Background Jobs panel.
// One row per job, overwritten on every run. Deliberately NOT system-versioned:
// some jobs run every minute.

module.exports = {
  name: '0074_job_status',
  async up(pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS job_status (
        job_name         VARCHAR(64)  NOT NULL PRIMARY KEY,
        last_run_at      DATETIME     NULL,
        last_duration_ms INT UNSIGNED NULL,
        last_note        VARCHAR(255) NULL,
        last_ok_at       DATETIME     NULL,
        last_error       TEXT         NULL,
        last_error_at    DATETIME     NULL,
        runs             INT UNSIGNED NOT NULL DEFAULT 0,
        failures         INT UNSIGNED NOT NULL DEFAULT 0
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
  },
};
