// tests/liveSessionPrivacy.test.js — players see the table, not the Storyteller's
// data: no other player's sheet, no ST notes/NPCs, nothing at all if not seated.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser, extractSessionCookie } = require('./setup/helpers');
const { closeStaleSessions } = require('../services/liveSession');

let pool;
let app;

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

async function player(name) {
  const p = await registerUser(app);
  const [r] = await pool.query('INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?, ?, ?, 0, ?)',
    [p.user.id, name, 'Brujah', JSON.stringify({ hunger: 4, willpower: { superficial: 2, aggravated: 0 } })]);
  return { ...p, id: r.insertId };
}

async function storyteller() {
  const a = await registerUser(app);
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [a.user.id]);
  const res = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: a.email, password: a.password } });
  return { ...a, cookie: extractSessionCookie(res) };
}

const get = (who, url) => app.inject({ method: 'GET', url, headers: { cookie: who.cookie } });

describe('live session privacy', () => {
  it('players only get the public part of the session and roster', async () => {
    const st = await storyteller();
    const alice = await player('Alice');
    const bob = await player('Bob');
    const outsider = await player('Carol');
    const metadata = {
      scene: 'The Elysium', ambient: 'calm', clocks: [], initiative: [],
      notes: { [alice.id]: 'secretly a spy' }, npcs: [{ name: 'Hidden Prince' }],
      activeEffects: { [alice.id]: [{ id: 'a', mod: 1 }], [bob.id]: [{ id: 'b', mod: 2 }] },
      rollRequests: [{ id: 'x', targetId: alice.id }, { id: 'y', targetId: bob.id }],
    };
    const code = `P${Date.now().toString(36).slice(-7)}`;
    const [s] = await pool.query('INSERT INTO live_sessions (session_code, name, admin_id, status, metadata) VALUES (?, ?, ?, ?, ?)',
      [code, 'Night', st.user.id, 'active', JSON.stringify(metadata)]);
    for (const p of [alice, bob]) {
      await pool.query('INSERT INTO live_session_participants (session_id, user_id, character_id) VALUES (?, ?, ?)', [s.insertId, p.user.id, p.id]);
    }

    const sess = JSON.parse((await get(alice, `/api/live-session/${code}`)).body).session;
    expect(sess.metadata.scene).toBe('The Elysium');
    expect(sess.metadata.notes).toBeUndefined();
    expect(sess.metadata.npcs).toBeUndefined();
    expect(Object.keys(sess.metadata.activeEffects)).toEqual([String(alice.id)]);
    expect(sess.metadata.rollRequests.map(r => r.id)).toEqual(['x']);

    const roster = JSON.parse((await get(alice, `/api/live-session/${code}/players`)).body).players;
    expect(roster).toHaveLength(2);
    roster.forEach(p => { expect(p.sheet).toBeUndefined(); expect(p.user_name).toBeUndefined(); });

    // The Storyteller still gets everything.
    const full = JSON.parse((await get(st, `/api/live-session/${code}`)).body).session;
    expect(full.metadata.notes).toBeDefined();
    const stRoster = JSON.parse((await get(st, `/api/live-session/${code}/players`)).body).players;
    expect(stRoster[0].sheet).toBeDefined();

    // Not seated at the table: nothing.
    for (const path of ['', '/players', '/rolls', '/broadcast']) {
      expect((await get(outsider, `/api/live-session/${code}${path}`)).statusCode).toBe(403);
    }
  });

  it('an ended session is staff-only: players just learn it ended', async () => {
    const st = await storyteller();
    const alice = await player('Alice');
    const code = `E${Date.now().toString(36).slice(-7)}`;
    const [s] = await pool.query('INSERT INTO live_sessions (session_code, name, admin_id, status, metadata) VALUES (?, ?, ?, ?, ?)',
      [code, 'Old night', st.user.id, 'active', JSON.stringify({ scene: 'Secret scene' })]);
    await pool.query('INSERT INTO live_session_participants (session_id, user_id, character_id) VALUES (?, ?, ?)', [s.insertId, alice.user.id, alice.id]);

    const end = await app.inject({ method: 'POST', url: `/api/live-session/${code}/end`, headers: { cookie: st.cookie } });
    expect(end.statusCode).toBe(200);

    expect(JSON.parse((await get(alice, `/api/live-session/${code}`)).body).session).toEqual({ id: s.insertId, session_code: code, status: 'ended' });
    for (const path of ['/players', '/rolls', '/broadcast']) {
      expect((await get(alice, `/api/live-session/${code}${path}`)).statusCode).toBe(403);
      expect((await get(st, `/api/live-session/${code}${path}`)).statusCode).toBe(200);
    }
    expect(JSON.parse((await get(st, `/api/live-session/${code}`)).body).session.metadata.scene).toBe('Secret scene');
    const join = await app.inject({ method: 'POST', url: `/api/live-session/${code}/join`, headers: { cookie: alice.cookie }, payload: {} });
    expect(join.statusCode).toBe(400);
  });

  it('a session left open for over 24 hours is closed automatically', async () => {
    const st = await storyteller();
    const mk = async (code, hoursAgo) => (await pool.query(
      "INSERT INTO live_sessions (session_code, name, admin_id, status, created_at) VALUES (?, ?, ?, 'active', NOW() - INTERVAL ? HOUR)",
      [code, 'Night', st.user.id, hoursAgo]))[0].insertId;
    const stale = await mk(`S${Date.now().toString(36).slice(-7)}`, 25);
    const fresh = await mk(`F${Date.now().toString(36).slice(-7)}`, 2);
    await closeStaleSessions(null);
    const [[a]] = await pool.query('SELECT status, ended_at FROM live_sessions WHERE id=?', [stale]);
    const [[b]] = await pool.query('SELECT status FROM live_sessions WHERE id=?', [fresh]);
    expect(a.status).toBe('ended');
    expect(a.ended_at).not.toBeNull();
    expect(b.status).toBe('active');
  });

  it('a session flagged keepOpen survives the 24 hour auto-close', async () => {
    const st = await storyteller();
    const [r] = await pool.query(
      "INSERT INTO live_sessions (session_code, name, admin_id, status, metadata, created_at) VALUES (?, ?, ?, 'active', ?, NOW() - INTERVAL 30 HOUR)",
      [`K${Date.now().toString(36).slice(-7)}`, 'Marathon', st.user.id, JSON.stringify({ keepOpen: true })]);
    await closeStaleSessions(null);
    const [[row]] = await pool.query('SELECT status FROM live_sessions WHERE id=?', [r.insertId]);
    expect(row.status).toBe('active');
  });

  it('players can find the running session by name and code only, and the ST can remove a player', async () => {
    const st = await storyteller();
    const alice = await player('Alice');
    const code = `A${Date.now().toString(36).slice(-7)}`;
    const [s] = await pool.query("INSERT INTO live_sessions (session_code, name, admin_id, status, metadata) VALUES (?, ?, ?, 'active', '{}')", [code, 'Tonight', st.user.id]);

    const found = JSON.parse((await get(alice, '/api/live-session/active')).body).sessions.find(x => x.session_code === code);
    expect(Object.keys(found).sort()).toEqual(['admin_name', 'name', 'session_code']);

    await pool.query('INSERT INTO live_session_participants (session_id, user_id, character_id) VALUES (?, ?, ?)', [s.insertId, alice.user.id, alice.id]);
    const del = (who) => app.inject({ method: 'DELETE', url: `/api/live-session/${code}/participants/${alice.user.id}`, headers: { cookie: who.cookie } });
    expect((await del(alice)).statusCode).toBe(403);           // players can't remove anyone
    expect((await get(alice, `/api/live-session/${code}`)).statusCode).toBe(200);
    expect((await del(st)).statusCode).toBe(200);
    expect((await get(alice, `/api/live-session/${code}`)).statusCode).toBe(403);
  });
});
