// tests/courtActions.test.js — Court Actions (routes/courtActions.js, routes/elysium.js):
// office decides power (not just the courtuser role), a Sheriff's Blood Hunt waits
// for the Prince, the is_bloodhunted flag follows the ledger, the Hierarchy offers
// to fix court-user roles, and a barred guest never learns where Elysium meets.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool;
let app;
let prince, sheriff, keeper, player, admin;
let targetId, playerCharId;

async function courtUser(name, title) {
  const u = await registerUser(app, { displayName: name });
  await pool.query("UPDATE users SET role='courtuser' WHERE id=?", [u.user.id]);
  await pool.query('INSERT INTO characters (user_id, name, clan, xp, camarilla_titles) VALUES (?,?,?,0,?)', [u.user.id, name, 'Ventrue', JSON.stringify([title])]);
  // Role is read from the session; log in again so the cookie carries courtuser.
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: u.email, password: u.password } });
  u.cookie = login.cookies.map(c => `${c.name}=${c.value}`).join('; ');
  return u;
}

const call = (user, method, url, payload) => app.inject({ method, url, payload, headers: { cookie: user.cookie } });

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  for (const t of ['blood_hunts', 'court_wanted', 'elysium_invitation_versions', 'elysium_invitation_reads', 'elysium_invitations', 'events']) await pool.query(`DELETE FROM ${t}`);
  app = buildTestApp(pool);
  await app.ready();

  prince = await courtUser('Prince Anna', 'Prince');
  sheriff = await courtUser('Sheriff Bo', 'Sheriff');
  keeper = await courtUser('Keeper Cy', 'Keeper');
  player = await registerUser(app, { displayName: 'Player' });
  const [c] = await pool.query('INSERT INTO characters (user_id, name, clan, xp) VALUES (?,?,?,0)', [player.user.id, 'Dora', 'Toreador']);
  playerCharId = c.insertId;
  const [t] = await pool.query("INSERT INTO npcs (name, clan) VALUES ('Villain', 'Banu Haqim')");
  targetId = t.insertId;
  admin = await registerUser(app, { displayName: 'Admin' });
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = login.cookies.map(ck => `${ck.name}=${ck.value}`).join('; ');
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

const flag = async () => (await pool.query('SELECT is_bloodhunted FROM npcs WHERE id=?', [targetId]))[0][0].is_bloodhunted;

describe('Blood Hunts', () => {
  it('a plain player and the Keeper cannot call one', async () => {
    const body = { target_type: 'npc', target_id: targetId, reason: 'Diablerie' };
    expect((await call(player, 'POST', '/api/court-actions/blood-hunts', body)).statusCode).toBe(403);
    expect((await call(keeper, 'POST', '/api/court-actions/blood-hunts', body)).statusCode).toBe(403);
  });

  it('the Sheriff only proposes; the Prince ratifies, which sets the flag; lifting clears it', async () => {
    const res = await call(sheriff, 'POST', '/api/court-actions/blood-hunts', { target_type: 'npc', target_id: targetId, reason: 'Diablerie' });
    expect(res.statusCode).toBe(201);
    const { hunt } = JSON.parse(res.body);
    expect(hunt.status).toBe('proposed');
    expect(await flag()).toBe(0);

    expect((await call(sheriff, 'POST', `/api/court-actions/blood-hunts/${hunt.id}/ratify`)).statusCode).toBe(403);
    expect((await call(prince, 'POST', `/api/court-actions/blood-hunts/${hunt.id}/ratify`)).statusCode).toBe(200);
    expect(await flag()).toBe(1);

    // Players see the active hunt, not the court's history.
    const pub = JSON.parse((await call(player, 'GET', '/api/court-actions/blood-hunts')).body);
    expect(pub.hunts.map(h => h.status)).toEqual(['active']);

    expect((await call(sheriff, 'POST', `/api/court-actions/blood-hunts/${hunt.id}/lift`)).statusCode).toBe(200);
    expect(await flag()).toBe(0);
  });

  it('an expired hunt ends and clears the flag', async () => {
    const res = await call(prince, 'POST', '/api/court-actions/blood-hunts', { target_type: 'npc', target_id: targetId, reason: 'Again' });
    const { hunt } = JSON.parse(res.body);
    expect(hunt.status).toBe('active');
    expect(await flag()).toBe(1);
    await pool.query('UPDATE blood_hunts SET expires_at = NOW() - INTERVAL 1 MINUTE WHERE id=?', [hunt.id]);
    await call(player, 'GET', '/api/court-actions/blood-hunts');
    expect(await flag()).toBe(0);
  });
});

describe('Dangerous domains', () => {
  it('ranks assessed divisions worst first for security offices only', async () => {
    for (const t of ['domain_problems', 'domain_claims']) await pool.query(`DELETE FROM ${t}`);
    await pool.query("INSERT INTO domain_claims (division, owner_name, color, owner_npc_id, safety_rating) VALUES (1, 'x', '#000', ?, 9), (2, NULL, '#888', NULL, 3), (3, NULL, '#888', NULL, 3), (4, NULL, '#888', NULL, NULL)", [targetId]);
    await pool.query("INSERT INTO domain_problems (domain_id, problem_text) VALUES (3, 'SI van spotted')");

    expect((await call(keeper, 'GET', '/api/court-actions/dangerous-domains')).statusCode).toBe(403);
    expect((await call(player, 'GET', '/api/court-actions/dangerous-domains')).statusCode).toBe(403);
    const res = await call(sheriff, 'GET', '/api/court-actions/dangerous-domains');
    expect(res.statusCode).toBe(200);
    const { domains } = JSON.parse(res.body);
    expect(domains.map(d => d.division)).toEqual([3, 2, 1]); // unassessed 4 left out; incidents break the tie
    expect(domains[0].incidents[0].text).toBe('SI van spotted');
    expect(domains[2].owner_name).toBe('Villain');
  });
});

describe('Court access sync', () => {
  it('suggests promoting a title holder and demoting an office-less court user', async () => {
    await pool.query("UPDATE characters SET camarilla_titles=? WHERE id=?", [JSON.stringify(['Scourge']), playerCharId]);
    await pool.query("UPDATE characters SET is_ex=1 WHERE user_id=?", [keeper.user.id]);
    const { mismatches } = JSON.parse((await call(admin, 'GET', '/api/admin/camarilla/court-access')).body);
    const byId = Object.fromEntries(mismatches.map(m => [m.user_id, m.suggested_role]));
    expect(byId[player.user.id]).toBe('courtuser');
    expect(byId[keeper.user.id]).toBe('user');
    expect(byId[prince.user.id]).toBeUndefined();
    await pool.query("UPDATE characters SET camarilla_titles=NULL WHERE id=?", [playerCharId]);
    await pool.query("UPDATE characters SET is_ex=0 WHERE user_id=?", [keeper.user.id]);
  });
});

describe('Elysium invitation', () => {
  let eventId;
  beforeAll(async () => {
    const [e] = await pool.query("INSERT INTO events (title, date, is_elysium) VALUES ('Modern Day Event', NOW() + INTERVAL 5 DAY, 1)");
    eventId = e.insertId;
  });

  it('only the Keeper writes it; guests see it once published; barred guests never see the venue', async () => {
    const draft = { name: 'Feast of Thorns', location: 'The Zappeion', body: 'Come, {name}.', barred: [], design: { cardPreset: 'velvet-rose', cardImage: 'javascript:alert(1)' } };
    expect((await call(prince, 'PUT', `/api/court-actions/elysium/${eventId}`, draft)).statusCode).toBe(403);
    const saved = await call(keeper, 'PUT', `/api/court-actions/elysium/${eventId}`, draft);
    expect(saved.statusCode).toBe(200);
    expect(JSON.parse(saved.body).invitation.design.cardImage).toBeUndefined(); // unsafe URL dropped

    let cur = JSON.parse((await call(player, 'GET', '/api/elysium/current')).body);
    expect(cur.status).toBe('pending');
    expect(cur.invitation).toBeNull();
    expect(cur.event.name).toBeNull(); // the Keeper's draft title is not announced yet

    await call(keeper, 'POST', `/api/court-actions/elysium/${eventId}/publish`, { publish: true });
    cur = JSON.parse((await call(player, 'GET', '/api/elysium/current')).body);
    expect(cur.status).toBe('invited');
    expect(cur.invitation.location).toBe('The Zappeion');
    expect(cur.read).toBe(false);
    await call(player, 'POST', `/api/elysium/${eventId}/read`);
    expect(JSON.parse((await call(player, 'GET', '/api/elysium/current')).body).read).toBe(true);

    await call(keeper, 'PUT', `/api/court-actions/elysium/${eventId}`, { ...draft, barred: [playerCharId] });
    cur = JSON.parse((await call(player, 'GET', '/api/elysium/current')).body);
    expect(cur.status).toBe('barred');
    expect(cur.invitation.location).toBeUndefined();
  });

  it('keeps every version, who made it, and every opening, for the admin only', async () => {
    // Re-send must not erase who already read it; it only re-arms the pop-up.
    await call(keeper, 'POST', `/api/court-actions/elysium/${eventId}/publish`, { publish: true, reannounce: true });
    await call(keeper, 'PUT', `/api/court-actions/elysium/${eventId}`, { name: 'Feast of Thorns', location: 'The Zappeion', body: 'Come, {name}.', barred: [] });
    let cur = JSON.parse((await call(player, 'GET', '/api/elysium/current')).body);
    expect(cur.read).toBe(false);
    await call(player, 'POST', `/api/elysium/${eventId}/read`);
    await call(player, 'POST', `/api/elysium/${eventId}/read`);

    expect((await call(keeper, 'GET', `/api/admin/elysium/invitations/${eventId}`)).statusCode).toBe(403);
    const res = await call(admin, 'GET', `/api/admin/elysium/invitations/${eventId}`);
    expect(res.statusCode).toBe(200);
    const h = JSON.parse(res.body);
    expect(h.versions.map(v => v.action)).toEqual(['save', 'publish', 'edit', 'reannounce', 'edit']);
    expect(h.versions.every(v => v.actor_office === 'Keeper')).toBe(true);
    expect(h.versions[1].published).toBe(true);
    const r = h.reads.find(x => x.user_id === player.user.id);
    expect(r.open_count).toBe(3);
    expect(r.seen_as).toBe('invited');
    expect(r.first_version_id).toBe(h.versions[1].id);

    const list = JSON.parse((await call(admin, 'GET', '/api/admin/elysium/invitations')).body).invitations;
    expect(list.find(i => i.id === eventId).version_count).toBe(5);
  });

  it('stores the card language, and drops anything but el / en', async () => {
    const draft = { name: 'Feast of Thorns', location: 'The Zappeion', body: 'Come.', barred: [] };
    let res = await call(keeper, 'PUT', `/api/court-actions/elysium/${eventId}`, { ...draft, design: { lang: 'el' } });
    expect(JSON.parse(res.body).invitation.design.lang).toBe('el');
    res = await call(keeper, 'PUT', `/api/court-actions/elysium/${eventId}`, { ...draft, design: { lang: 'fr' } });
    expect(JSON.parse(res.body).invitation.design.lang).toBeUndefined();
    const cur = JSON.parse((await call(player, 'GET', '/api/elysium/current')).body);
    expect(cur.invitation.design.lang).toBeUndefined(); // card then defaults to English
  });

  it('autosaves drafts quietly, never onto a published invitation, and image export is locked down', async () => {
    const [e2] = await pool.query("INSERT INTO events (title, date, is_elysium) VALUES ('Modern Day Event', NOW() + INTERVAL 40 DAY, 1)");
    const id2 = e2.insertId;
    const versions = async () => (await pool.query('SELECT COUNT(*) AS n FROM elysium_invitation_versions WHERE event_id=?', [id2]))[0][0].n;
    const draft = { name: 'Later', location: 'Somewhere', body: 'Hi', barred: [], autosave: true };

    // Admin may work on any Elysium; the Keeper only on the coming one.
    expect((await call(admin, 'PUT', `/api/court-actions/elysium/${id2}`, draft)).statusCode).toBe(200);
    expect(await versions()).toBe(0);
    expect((await call(admin, 'PUT', `/api/court-actions/elysium/${id2}`, { ...draft, autosave: false })).statusCode).toBe(200);
    expect(await versions()).toBe(1);

    await call(admin, 'POST', `/api/court-actions/elysium/${id2}/publish`, { publish: true });
    expect((await call(admin, 'PUT', `/api/court-actions/elysium/${id2}`, draft)).statusCode).toBe(409);

    // The image proxy: Keeper/admin only, and only the portal's own image host.
    const img = (u, who) => call(who, 'GET', `/api/elysium/image?u=${encodeURIComponent(u)}`);
    expect((await img('https://img.miketsak.gr/uploads/x.webp', player)).statusCode).toBe(403);
    expect((await img('http://169.254.169.254/latest/meta-data', keeper)).statusCode).toBe(400);
    expect((await img('https://evil.example/img.png', keeper)).statusCode).toBe(400);
    expect((await img('https://img.miketsak.gr@evil.example/x.png', keeper)).statusCode).toBe(400);
  });
});
