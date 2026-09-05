// tests/coteries.test.js — integration tests for routes/coteries.js against
// the real Fastify app and the isolated test database.
//
// The XP cases here are regression tests for two live exploits in the routes
// this file replaced: any coterie member could POST an arbitrary delta to
// /xp and mint themselves an unlimited bank, and could set `coterie_xp`
// directly through PUT. Both are now admin-only and both write a ledger row.
const { buildTestApp } = require('./setup/testApp');
const { setupTestDatabase, getTestPool } = require('./setup/testDb');
const { registerUser, extractSessionCookie } = require('./setup/helpers');

let app;
let pool;
let members;   // three ordinary players, each with a character
let admin;
let outsider;  // authenticated, but not in the coterie

async function makeCharacter(userId, name, { xp = 0, clan = 'Brujah' } = {}) {
  const [r] = await pool.query(
    'INSERT INTO characters (user_id, name, clan, xp) VALUES (?,?,?,?)',
    [userId, name, clan, xp]
  );
  return r.insertId;
}

/** Registers a user, gives them a character, and returns both. */
async function makePlayer(name, opts) {
  const u = await registerUser(app, { displayName: name });
  const characterId = await makeCharacter(u.user.id, name, opts);
  return { ...u, characterId };
}

const legalPayload = (over = {}) => ({
  name: 'The Night Wardens',
  concept: 'Keeps the docks quiet',
  type: null,
  domain_id: 7,
  // pool = 3 members x 1 = 3, spend = chasse 2 + lien 1 = 3
  traits: { chasse: 2, lien: 1, portillon: 0 },
  backgrounds: [],
  merits: [],
  flaws: [],
  points_per_member: 1,
  bonus_points: 0,
  members: members.map((m) => ({ user_id: m.user.id })),
  ...over,
});

const post = (url, cookie, payload) =>
  app.inject({ method: 'POST', url, headers: { cookie }, payload });
const get = (url, cookie) => app.inject({ method: 'GET', url, headers: { cookie } });
const put = (url, cookie, payload) =>
  app.inject({ method: 'PUT', url, headers: { cookie }, payload });

beforeAll(async () => {
  await setupTestDatabase();
  pool = getTestPool();
  app = buildTestApp(pool);
  await app.ready();

  members = [
    await makePlayer('Wren', { xp: 20, clan: 'Nosferatu' }),
    await makePlayer('Sable', { xp: 5, clan: 'Gangrel' }),
    await makePlayer('Idris', { xp: 0, clan: 'Toreador' }),
  ];
  outsider = await makePlayer('Outsider');

  admin = await registerUser(app, { displayName: 'Storyteller' });
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  // Re-login so the session cookie actually carries role=admin.
  const login = await app.inject({
    method: 'POST',
    url: '/api/auth/login',
    payload: { email: admin.email, password: admin.password },
  });
  admin.cookie = extractSessionCookie(login);
});

afterAll(async () => { if (app) await app.close(); });

/* ================================================================== */

describe('POST /api/coteries', () => {
  it('creates a coterie the caller belongs to', async () => {
    const res = await post('/api/coteries', members[0].cookie, legalPayload());
    expect(res.statusCode).toBe(201);
    const { coterie } = JSON.parse(res.body);
    expect(coterie.name).toBe('The Night Wardens');
    expect(coterie.traits).toEqual({ chasse: 2, lien: 1, portillon: 0 });
    // The mechanics the sheet renders are computed server-side.
    expect(coterie.mechanics.huntingDifficulty).toBe(5);
    expect(coterie.mechanics.lienBonusDice).toBe(1);
  });

  it('rejects a coterie the caller is not part of', async () => {
    const res = await post('/api/coteries', outsider.cookie, legalPayload());
    expect(res.statusCode).toBe(403);
  });

  it('rejects fewer than three members', async () => {
    const res = await post('/api/coteries', members[0].cookie, legalPayload({
      members: members.slice(0, 2).map((m) => ({ user_id: m.user.id })),
      traits: { chasse: 1, lien: 0, portillon: 0 },
    }));
    expect(res.statusCode).toBe(400);
  });

  it('rejects a member who has no character sheet', async () => {
    const sheetless = await registerUser(app, { displayName: 'Sheetless' });
    const res = await post('/api/coteries', members[0].cookie, legalPayload({
      members: [...members.map((m) => ({ user_id: m.user.id })), { user_id: sheetless.user.id }],
    }));
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).missing_user_ids).toContain(sheetless.user.id);
  });

  // The client's arithmetic is a display convenience; the server re-runs it.
  it('rejects overspending the coterie pool even if the client says otherwise', async () => {
    const res = await post('/api/coteries', members[0].cookie, legalPayload({
      traits: { chasse: 5, lien: 5, portillon: 5 }, // 15 dots from a pool of 3
    }));
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/overspending/i);
  });

  it('rejects Domain traits with no Domain claimed', async () => {
    const res = await post('/api/coteries', members[0].cookie, legalPayload({
      domain_id: null,
      traits: { chasse: 2, lien: 1, portillon: 0 },
    }));
    expect(res.statusCode).toBe(400);
  });

  it('silently drops Backgrounds a coterie cannot hold in common', async () => {
    const res = await post('/api/coteries', members[0].cookie, legalPayload({
      name: 'Filtered',
      traits: { chasse: 1, lien: 0, portillon: 0 },
      backgrounds: [{ key: 'haven', dots: 1 }, { key: 'auspex', dots: 3 }],
    }));
    expect(res.statusCode).toBe(201);
    const { coterie } = JSON.parse(res.body);
    expect(coterie.backgrounds.map((b) => b.key)).toEqual(['haven']);
  });

  it('ignores a starting XP grant from a non-admin', async () => {
    const res = await post('/api/coteries', members[0].cookie, legalPayload({
      name: 'No Free Lunch', coterie_xp: 500,
    }));
    expect(res.statusCode).toBe(201);
    expect(JSON.parse(res.body).coterie.coterie_xp).toBe(0);
  });
});

/* ================================================================== */

describe('coterie XP', () => {
  let coterieId;

  beforeEach(async () => {
    const res = await post('/api/coteries', members[0].cookie, legalPayload({
      name: `XP Test ${Date.now()}${Math.random()}`,
    }));
    coterieId = JSON.parse(res.body).coterie.id;
  });

  it('lets a Storyteller award XP and records it in the ledger', async () => {
    const res = await post(`/api/coteries/${coterieId}/xp`, admin.cookie, { delta: 12, note: 'Good scene' });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).coterie_xp).toBe(12);

    const detail = JSON.parse((await get(`/api/coteries/${coterieId}`, admin.cookie)).body);
    const award = detail.xp_log.find((r) => r.kind === 'award' && r.bank_delta === 12);
    expect(award).toBeTruthy();
    expect(award.note).toBe('Good scene');
  });

  // Regression: previously any member could mint themselves unlimited XP.
  it('refuses an XP award from an ordinary member', async () => {
    const res = await post(`/api/coteries/${coterieId}/xp`, members[0].cookie, { delta: 999 });
    expect(res.statusCode).toBe(403);

    const detail = JSON.parse((await get(`/api/coteries/${coterieId}`, members[0].cookie)).body);
    expect(detail.coterie.coterie_xp).toBe(0);
  });

  // Regression: coterie_xp used to be writable through the ordinary update.
  it('ignores coterie_xp sent through PUT by a member', async () => {
    const res = await put(`/api/coteries/${coterieId}`, members[0].cookie, { coterie_xp: 999 });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).coterie.coterie_xp).toBe(0);
  });

  it('never lets the bank go negative', async () => {
    await post(`/api/coteries/${coterieId}/xp`, admin.cookie, { delta: 5 });
    const res = await post(`/api/coteries/${coterieId}/xp`, admin.cookie, { delta: -50 });
    expect(JSON.parse(res.body).coterie_xp).toBe(0);
  });
});

/* ================================================================== */

describe('POST /api/coteries/:id/purchase', () => {
  let coterieId;

  beforeEach(async () => {
    const res = await post('/api/coteries', members[0].cookie, legalPayload({
      name: `Buy Test ${Date.now()}${Math.random()}`,
    }));
    coterieId = JSON.parse(res.body).coterie.id;
    await pool.query('UPDATE characters SET xp=? WHERE user_id=?', [20, members[0].user.id]);
  });

  it('raises a Domain trait for 3 XP per dot from the bank', async () => {
    await post(`/api/coteries/${coterieId}/xp`, admin.cookie, { delta: 30 });

    // Lien 1 -> 3 is two dots = 6 XP.
    const res = await post(`/api/coteries/${coterieId}/purchase`, members[0].cookie, {
      target: { kind: 'domain', key: 'lien' },
      to_dots: 3,
      from_bank: 6,
      from_personal: 0,
    });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.spent).toEqual({ cost: 6, from_bank: 6, from_personal: 0 });
    expect(body.coterie.traits.lien).toBe(3);
    expect(body.coterie.coterie_xp).toBe(24);
    expect(body.coterie.mechanics.lienBonusDice).toBe(3);
  });

  it('splits the cost between the bank and the buyer’s own character XP', async () => {
    await post(`/api/coteries/${coterieId}/xp`, admin.cookie, { delta: 4 });

    // Portillon 0 -> 2 = 6 XP: 4 from the bank, 2 topped up personally.
    const res = await post(`/api/coteries/${coterieId}/purchase`, members[0].cookie, {
      target: { kind: 'domain', key: 'portillon' },
      to_dots: 2,
      from_bank: 4,
      from_personal: 2,
    });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).coterie.coterie_xp).toBe(0);

    const [[ch]] = await pool.query('SELECT xp FROM characters WHERE user_id=?', [members[0].user.id]);
    expect(ch.xp).toBe(18);
  });

  it('refuses when the funding does not add up to the cost', async () => {
    await post(`/api/coteries/${coterieId}/xp`, admin.cookie, { delta: 50 });
    const res = await post(`/api/coteries/${coterieId}/purchase`, members[0].cookie, {
      target: { kind: 'domain', key: 'lien' },
      to_dots: 3,
      from_bank: 1, // real cost is 6
      from_personal: 0,
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/must total the cost of 6/i);
  });

  it('refuses to draw more than the bank holds', async () => {
    const res = await post(`/api/coteries/${coterieId}/purchase`, members[0].cookie, {
      target: { kind: 'domain', key: 'lien' },
      to_dots: 2, from_bank: 3, from_personal: 0,
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/bank holds 0/i);
  });

  it('refuses to draw more personal XP than the buyer has', async () => {
    await pool.query('UPDATE characters SET xp=1 WHERE user_id=?', [members[2].user.id]);
    const res = await post(`/api/coteries/${coterieId}/purchase`, members[2].cookie, {
      target: { kind: 'domain', key: 'lien' },
      to_dots: 2, from_bank: 0, from_personal: 3,
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/not enough personal xp/i);
  });

  it('buys a coterie Merit and records who paid', async () => {
    await post(`/api/coteries/${coterieId}/xp`, admin.cookie, { delta: 30 });
    const res = await post(`/api/coteries/${coterieId}/purchase`, members[0].cookie, {
      target: { kind: 'merit', key: 'bolt_holes' },
      to_dots: 2, from_bank: 6, from_personal: 0,
    });
    expect(res.statusCode).toBe(200);
    const merits = JSON.parse(res.body).coterie.merits;
    expect(merits).toEqual([expect.objectContaining({ key: 'bolt_holes', dots: 2, name: 'Bolt Holes' })]);

    const detail = JSON.parse((await get(`/api/coteries/${coterieId}`, members[0].cookie)).body);
    const spend = detail.xp_log.find((r) => r.target_key === 'bolt_holes');
    expect(spend).toMatchObject({ kind: 'spend', bank_delta: -6, from_dots: 0, to_dots: 2 });
  });

  // A Lien Merit on a coterie with no Lien would be unusable, so the purchase
  // is rejected rather than silently stored.
  it('refuses a Domain Merit whose anchoring trait the coterie lacks', async () => {
    await post(`/api/coteries/${coterieId}/xp`, admin.cookie, { delta: 30 });
    const res = await post(`/api/coteries/${coterieId}/purchase`, members[0].cookie, {
      target: { kind: 'merit', key: 'transit' }, // Portillon Merit; coterie has Portillon 0
      to_dots: 2, from_bank: 6, from_personal: 0,
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/portillon/i);
  });

  it('refuses to "buy" a rating at or below the current one', async () => {
    await post(`/api/coteries/${coterieId}/xp`, admin.cookie, { delta: 30 });
    const res = await post(`/api/coteries/${coterieId}/purchase`, members[0].cookie, {
      target: { kind: 'domain', key: 'chasse' }, // already 2
      to_dots: 2, from_bank: 0, from_personal: 0,
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/new dots only/i);
  });

  it('refuses an unknown target', async () => {
    const res = await post(`/api/coteries/${coterieId}/purchase`, members[0].cookie, {
      target: { kind: 'merit', key: 'not_a_real_merit' },
      to_dots: 1, from_bank: 0, from_personal: 3,
    });
    expect(res.statusCode).toBe(400);
  });

  it('refuses a purchase from someone outside the coterie', async () => {
    await post(`/api/coteries/${coterieId}/xp`, admin.cookie, { delta: 30 });
    const res = await post(`/api/coteries/${coterieId}/purchase`, outsider.cookie, {
      target: { kind: 'domain', key: 'lien' },
      to_dots: 2, from_bank: 3, from_personal: 0,
    });
    expect(res.statusCode).toBe(403);
  });

  // Advancement legitimately takes a coterie past its creation pool.
  it('allows advancement to exceed the original creation pool', async () => {
    await post(`/api/coteries/${coterieId}/xp`, admin.cookie, { delta: 60 });
    const res = await post(`/api/coteries/${coterieId}/purchase`, members[0].cookie, {
      target: { kind: 'domain', key: 'chasse' },
      to_dots: 5, from_bank: 9, from_personal: 0,
    });
    expect(res.statusCode).toBe(200);
    const { coterie } = JSON.parse(res.body);
    expect(coterie.traits.chasse).toBe(5);
    expect(coterie.mechanics.huntingDifficulty).toBe(2);
    expect(coterie.budget.remaining).toBeLessThan(0); // over the creation pool, by design
  });
});

/* ================================================================== */

describe('reads and authorization', () => {
  let coterieId;

  beforeAll(async () => {
    const res = await post('/api/coteries', members[0].cookie, legalPayload({ name: 'Read Test' }));
    coterieId = JSON.parse(res.body).coterie.id;
  });

  it('hides a coterie sheet from non-members', async () => {
    const res = await get(`/api/coteries/${coterieId}`, outsider.cookie);
    expect(res.statusCode).toBe(403);
  });

  it('lets an admin read any coterie', async () => {
    const res = await get(`/api/coteries/${coterieId}`, admin.cookie);
    expect(res.statusCode).toBe(200);
  });

  it('requires authentication', async () => {
    const res = await app.inject({ method: 'GET', url: `/api/coteries/${coterieId}` });
    expect(res.statusCode).toBe(401);
  });

  it('lists only the coteries a player belongs to', async () => {
    const res = await get('/api/coteries', outsider.cookie);
    expect(JSON.parse(res.body).coteries).toEqual([]);
  });

  // The registry is deliberately public to logged-in players, and returns
  // members as rows rather than a GROUP_CONCAT string that silently
  // truncated at 1024 bytes on large rosters.
  it('shows every coterie in the public registry with a full roster', async () => {
    const res = await get('/api/coteries/all', outsider.cookie);
    expect(res.statusCode).toBe(200);
    const found = JSON.parse(res.body).coteries.find((c) => c.id === coterieId);
    expect(found.member_count).toBe(3);
    expect(found.members.map((m) => m.name).sort()).toEqual(['Idris', 'Sable', 'Wren']);
  });

  it('only an admin may delete', async () => {
    const denied = await app.inject({
      method: 'DELETE', url: `/api/coteries/${coterieId}`, headers: { cookie: members[0].cookie },
    });
    expect(denied.statusCode).toBe(403);

    const ok = await app.inject({
      method: 'DELETE', url: `/api/coteries/${coterieId}`, headers: { cookie: admin.cookie },
    });
    expect(ok.statusCode).toBe(200);
  });
});

/* ================================================================== */

describe('membership', () => {
  it('requires the caller to keep themselves in the coterie', async () => {
    const created = await post('/api/coteries', members[0].cookie, legalPayload({ name: 'Membership' }));
    const id = JSON.parse(created.body).coterie.id;

    const res = await post(`/api/coteries/${id}/members/set`, members[0].cookie, {
      members: [
        { user_id: members[1].user.id },
        { user_id: members[2].user.id },
        { user_id: outsider.user.id },
      ],
    });
    expect(res.statusCode).toBe(403);
  });

  it('stores the character behind each member rather than just the account', async () => {
    const created = await post('/api/coteries', members[0].cookie, legalPayload({ name: 'Characters' }));
    const id = JSON.parse(created.body).coterie.id;

    const detail = JSON.parse((await get(`/api/coteries/${id}`, members[0].cookie)).body);
    for (const m of detail.members) {
      expect(m.character_id).toBeTruthy();
      expect(m.character_name).toBeTruthy();
    }
  });
});
