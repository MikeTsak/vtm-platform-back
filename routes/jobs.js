// routes/jobs.js
//
// Admin Background Jobs panel: every job in jobs/index.js with its schedule and
// latest outcome (job_status), the newest backups on disk, and a run-now button.
// Run-now is safe for every job: each is latched or harmless to repeat, and
// runJob takes the same cross-process lock as the scheduler.

const { JOBS, findJob, runJob } = require('../jobs');

module.exports = async function (fastify, opts) {
  const { pool, authRequired, requireAdmin } = opts;
  const adminOnly = [authRequired, requireAdmin];

  fastify.get('/api/admin/jobs', { preHandler: adminOnly }, async (req, reply) => {
    // Ages come from the DB clock, the same clock that wrote last_run_at.
    const [rows] = await pool.query(
      `SELECT job_name, last_run_at, last_duration_ms, last_note, last_ok_at, last_error, last_error_at, runs, failures,
              TIMESTAMPDIFF(MINUTE, last_run_at, NOW()) AS age_min
         FROM job_status`
    );
    const byName = new Map(rows.map((r) => [r.job_name, r]));

    const jobs = JOBS.map((j) => {
      const s = byName.get(j.name) || null;
      const enabled = j.enabled !== false;
      let health = 'ok';
      if (!enabled) health = 'disabled';
      else if (!s) health = 'never';
      else if (s.age_min > j.maxGapMin) health = 'overdue';
      else if (s.last_error_at && (!s.last_ok_at || s.last_error_at >= s.last_ok_at)) health = 'failing';
      return {
        name: j.name, label: j.label, schedule: j.cron || 'while comms are open', maxGapMin: j.maxGapMin,
        enabled, health, status: s,
      };
    });

    let backups = [];
    try {
      const { listBackups } = require('../scripts/backup-db');
      backups = (await listBackups()).slice(0, 5).map((b) => ({ file: b.file, size: b.size, mtime: b.mtime, full: !b.file.includes('-nomedia') }));
    } catch { /* no backup dir yet */ }

    const [[starts]] = await pool.query("SELECT setting_value AS v FROM app_settings WHERE setting_key = 'daily_server_starts'");
    reply.header('Cache-Control', 'no-store');
    reply.send({
      jobs,
      backups,
      server: {
        pid: process.pid,
        uptime_sec: Math.floor(process.uptime()),
        boots_today: Number(starts?.v || 0),
      },
    });
  });

  fastify.post('/api/admin/jobs/:name/run', { preHandler: adminOnly }, async (req, reply) => {
    const job = findJob(req.params.name);
    if (!job) return reply.status(404).send({ error: 'Unknown job' });
    if (job.enabled === false) return reply.status(400).send({ error: 'This job is disabled on the server' });
    const res = await runJob(job, { io: fastify.io });
    if (!res.ran) return reply.status(409).send({ error: 'Already running in another server process. Try again in a moment.' });
    return reply.send(res);
  });
};
