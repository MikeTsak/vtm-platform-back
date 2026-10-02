// tests/coterieRetainers.test.js — sheets for a coterie's shared Retainers
// Background: the dots are the budget (tiers split freely), any member may
// build, a ghoul's domitor must be a member, and a personal retainer can be
// moved in.
const { buildTestApp } = require('./setup/testApp');
const { setupTestDatabase, getTestPool } = require('./setup/testDb');
const { registerUser } = require('./setup/helpers');

let app, pool, members, outsider, coterieId;

const req = (method, url, who, payload) => app.inject({ method, url, headers: { cookie: who.cookie }, payload });

// Tier 1: two attributes at 2, three skills at 2, five at 1.
const T1 = {
  attributes: { Strength: 2, Wits: 2 },
  skills: { Brawl: 2, Drive: 2, Streetwise: 2, Stealth: 1, Larceny: 1, Insight: 1, Awareness: 1, Firearms: 1 },
};
// Tier 2: two attributes at 3, three at 2; skills 3x3, 4x2, 5x1.
const T2 = {
  attributes: { Strength: 3, Wits: 3, Dexterity: 2, Stamina: 2, Resolve: 2 },
  skills: {
    Brawl: 3, Drive: 3, Streetwise: 3, Stealth: 2, Larceny: 2, Insight: 2, Awareness: 2,
    Firearms: 1, Melee: 1, Athletics: 1, Intimidation: 1, Persuasion: 1,
  },
};

async function makePlayer(name, clan) {
  const u = await registerUser(app, { displayName: name });
  const [r] = await pool.query('INSERT INTO characters (user_id, name, clan, xp) VALUES (?,?,?,0)', [u.user.id, name, clan]);
  return { ...u, characterId: r.insertId };
}

beforeAll(async () => {
  await setupTestDatabase();
  pool = getTestPool();
  app = buildTestApp(pool);
  await app.ready();
  members = [await makePlayer('Ana', 'Ventrue'), await makePlayer('Bo', 'Brujah'), await makePlayer('Cy', 'Tremere')];
  outsider = await makePlayer('Dee', 'Gangrel');

  const res = await req('POST', '/api/coteries', members[0], {
    name: 'Retainer Test Coterie', domain_id: 7,
    traits: { chasse: 2, lien: 1, portillon: 0 }, backgrounds: [], merits: [], flaws: [],
    points_per_member: 1, bonus_points: 0, members: members.map((m) => ({ user_id: m.user.id })),
  });
  coterieId = JSON.parse(res.body).coterie.id;
  // Retainers ••• bought before sheets existed: dots with no retainer rows.
  await pool.query('UPDATE coteries SET backgrounds_json=? WHERE id=?', [
    JSON.stringify([{ key: 'retainers', name: 'Retainers', dots: 3, note: null }]), coterieId,
  ]);
});
afterAll(async () => { if (app) await app.close(); });

describe('coterie retainers', () => {
  it('shows legacy dots as unassigned budget', async () => {
    const res = await req('GET', `/api/characters/${members[1].characterId}/coterie-retainers`, members[1]);
    const c = JSON.parse(res.body).find((x) => x.id === coterieId);
    expect(c.dots).toBe(3);
    expect(c.retainers).toEqual([]);
  });

  it('lets any member build within the dots, and refuses past them', async () => {
    const ok = await req('POST', `/api/coteries/${coterieId}/retainers`, members[1], { name: 'Driver', tier: 2, sheet: T2 });
    expect(ok.statusCode).toBe(200);
    const over = await req('POST', `/api/coteries/${coterieId}/retainers`, members[2], { name: 'Muscle', tier: 2, sheet: T2 });
    expect(over.statusCode).toBe(400);
    expect(JSON.parse(over.body).error).toMatch(/1 unassigned/);
  });

  it('refuses outsiders', async () => {
    const res = await req('POST', `/api/coteries/${coterieId}/retainers`, outsider, { name: 'Spy', tier: 1, sheet: T1 });
    expect(res.statusCode).toBe(403);
  });

  it('requires a member domitor for a ghoul', async () => {
    const sheet = { ...T1, isGhoul: true, disciplines: { Dominate: 1 } };
    const bad = await req('POST', `/api/coteries/${coterieId}/retainers`, members[0],
      { name: 'Ghoul', tier: 1, sheet, domitor_character_id: outsider.characterId });
    expect(bad.statusCode).toBe(400);
    const good = await req('POST', `/api/coteries/${coterieId}/retainers`, members[0],
      { name: 'Ghoul', tier: 1, sheet, domitor_character_id: members[0].characterId });
    expect(good.statusCode).toBe(200);
    expect(JSON.parse(good.body).domitor_character_id).toBe(members[0].characterId);
  });

  it('upgrades only when the dots allow, giving back the old tier first', async () => {
    const [[driver]] = await pool.query("SELECT id FROM retainers WHERE coterie_id=? AND name='Driver'", [coterieId]);
    // 3 dots: Driver T2 + Ghoul T1. Driver -> T2 again (same tier) is fine; there is no room for T3.
    const same = await req('PUT', `/api/coteries/${coterieId}/retainers/${driver.id}`, members[2], { tier: 2, sheet: T2 });
    expect(same.statusCode).toBe(200);
    const up = await req('PUT', `/api/coteries/${coterieId}/retainers/${driver.id}`, members[2], { tier: 3, sheet: T2 });
    expect(up.statusCode).toBe(400);
  });

  it('moves a personal retainer in once dots are freed', async () => {
    const [[ghoul]] = await pool.query("SELECT id FROM retainers WHERE coterie_id=? AND name='Ghoul'", [coterieId]);
    expect((await req('DELETE', `/api/coteries/${coterieId}/retainers/${ghoul.id}`, members[1])).statusCode).toBe(200);

    const [p] = await pool.query('INSERT INTO retainers (character_id, name, tier, sheet) VALUES (?,?,?,?)',
      [members[2].characterId, 'Old Friend', 1, JSON.stringify(T1)]);
    // Someone else's personal retainer can't be taken.
    const steal = await req('POST', `/api/coteries/${coterieId}/retainers/transfer`, members[1], { retainer_id: p.insertId });
    expect(steal.statusCode).toBe(404);
    const mine = await req('POST', `/api/coteries/${coterieId}/retainers/transfer`, members[2], { retainer_id: p.insertId });
    expect(mine.statusCode).toBe(200);
    const [[row]] = await pool.query('SELECT character_id, coterie_id FROM retainers WHERE id=?', [p.insertId]);
    expect(row).toEqual({ character_id: null, coterie_id: coterieId });
  });
});
