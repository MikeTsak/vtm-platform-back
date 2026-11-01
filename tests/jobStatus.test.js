// tests/jobStatus.test.js — runJob records every outcome in job_status (what the
// admin Background Jobs panel reads), and the panel endpoint is admin-only.
// Uses synthetic jobs: the real ones message real players.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser, extractSessionCookie } = require('./setup/helpers');
const { runJob, JOBS } = require('../jobs');

let pool, app, player, admin;

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  player = await registerUser(app);
  admin = await registerUser(app);
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = extractSessionCookie(login);
  await pool.query('DELETE FROM job_status');
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

const row = async (name) => (await pool.query('SELECT * FROM job_status WHERE job_name = ?', [name]))[0][0];

describe('runJob', () => {
  it('records a successful run with its note', async () => {
    const res = await runJob({ name: 't-ok', label: 'ok', run: async () => 'did 3 things' });
    expect(res).toMatchObject({ ran: true, ok: true, note: 'did 3 things' });
    const r = await row('t-ok');
    expect(r).toMatchObject({ runs: 1, failures: 0, last_note: 'did 3 things', last_error: null });
    expect(r.last_ok_at).toBeTruthy();
  });

  it('records a failure without throwing, then clears the error on the next success', async () => {
    let fail = true;
    const job = { name: 't-flaky', label: 'flaky', run: async () => { if (fail) throw new Error('boom'); return 'fine'; } };
    expect(await runJob(job)).toMatchObject({ ran: true, ok: false });
    let r = await row('t-flaky');
    expect(r.failures).toBe(1);
    expect(r.last_error).toContain('boom');
    expect(r.last_ok_at).toBeNull();

    fail = false;
    await runJob(job);
    r = await row('t-flaky');
    expect(r).toMatchObject({ runs: 2, failures: 1, last_note: 'fine' });
    expect(r.last_ok_at).toBeTruthy();
    expect(r.last_error).toContain('boom'); // kept for the panel, but older than last_ok_at
  });

  it('skips (and records nothing) while another caller holds the job', async () => {
    let release;
    const job = { name: 't-slow', label: 'slow', run: () => new Promise((r) => { release = r; }) };
    const first = runJob(job);
    await new Promise((r) => setTimeout(r, 100));
    expect(await runJob(job)).toEqual({ ran: false });
    release('done');
    await first;
    expect((await row('t-slow')).runs).toBe(1);
  });
});

describe('GET /api/admin/jobs', () => {
  it('is admin-only', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/admin/jobs', headers: { cookie: player.cookie } });
    expect(res.statusCode).toBe(403);
  });

  it('lists every scheduled job with a health verdict', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/admin/jobs', headers: { cookie: admin.cookie } });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.jobs.map((j) => j.name)).toEqual(JOBS.map((j) => j.name));
    for (const j of body.jobs) expect(['ok', 'never', 'overdue', 'failing', 'disabled']).toContain(j.health);
  });

  it('refuses to run an unknown job', async () => {
    const res = await app.inject({ method: 'POST', url: '/api/admin/jobs/nope/run', headers: { cookie: admin.cookie } });
    expect(res.statusCode).toBe(404);
  });
});
