// tests/sessionGhouls.test.js — the Storyteller brings a player's ghoul into a
// live session; only that player rolls for it (no Hunger dice), its Health and
// Willpower move only through the tracker routes, and a power above level 1
// costs it 1 Aggravated instead of a Rouse Check.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser, extractSessionCookie } = require('./setup/helpers');
const { parseSheet } = require('../utils/sheet');

let pool, app, st, ana, bo, code, sessionId, ghoulId, strayId;

const req = (who, method, url, payload) => app.inject({ method, url, headers: { cookie: who.cookie }, payload });
const GHOUL = {
  isGhoul: true,
  attributes: { Strength: 2, Wits: 2, Stamina: 1 },
  skills: { Brawl: 2, Drive: 2, Streetwise: 2, Stealth: 1, Larceny: 1, Insight: 1, Awareness: 1, Firearms: 1 },
  disciplines: { Potence: 1 }, powers: [{ discipline: 'Potence', name: 'Lethal Body' }],
};

async function player(name) {
  const p = await registerUser(app);
  const [r] = await pool.query('INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?, ?, ?, 0, ?)',
    [p.user.id, name, 'Brujah', JSON.stringify({ hunger: 3, disciplines: { Potence: 1 } })]);
  return { ...p, id: r.insertId };
}

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  const a = await registerUser(app);
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [a.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: a.email, password: a.password } });
  st = { ...a, cookie: extractSessionCookie(login) };
  ana = await player('Ana');
  bo = await player('Bo');

  const [g] = await pool.query('INSERT INTO retainers (character_id, name, tier, sheet) VALUES (?,?,?,?)', [ana.id, 'Igor', 1, JSON.stringify(GHOUL)]);
  ghoulId = g.insertId;
  const [x] = await pool.query('INSERT INTO retainers (character_id, name, tier, sheet) VALUES (?,?,?,?)', [ana.id, 'Stray', 1, JSON.stringify(GHOUL)]);
  strayId = x.insertId;

  code = `G${Date.now().toString(36).slice(-7)}`;
  const [s] = await pool.query('INSERT INTO live_sessions (session_code, name, admin_id, status, metadata) VALUES (?,?,?,?,?)',
    [code, 'Night', st.user.id, 'active', JSON.stringify({ ghouls: [ghoulId] })]);
  sessionId = s.insertId;
  for (const p of [ana, bo]) {
    await pool.query('INSERT INTO live_session_participants (session_id, user_id, character_id) VALUES (?,?,?)', [sessionId, p.user.id, p.id]);
  }
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

describe('ghouls at the table', () => {
  it('shows the ghoul only to the player who plays it, and its candidates to the Storyteller', async () => {
    const mine = JSON.parse((await req(ana, 'GET', `/api/live-session/${code}/ghouls`)).body);
    expect(mine.ghouls.map((g) => g.id)).toEqual([ghoulId]);
    expect(mine.ghouls[0].trackers).toMatchObject({ maxHealth: 4, maxWillpower: 2 });
    expect(JSON.parse((await req(bo, 'GET', `/api/live-session/${code}/ghouls`)).body).ghouls).toEqual([]);
    const stView = JSON.parse((await req(st, 'GET', `/api/live-session/${code}/ghouls`)).body);
    expect(stView.candidates.map((c) => c.id)).toEqual([strayId]);
  });

  it('rolls plain dice for the ghoul, only for its player and only once brought in', async () => {
    const roll = (who, retainerId, extra = {}) => req(who, 'POST', '/api/dice/roll',
      { mode: 'ghoul', sessionId: code, retainerId, traits: ['Strength', 'Brawl'], ...extra });
    const ok = await roll(ana, ghoulId);
    expect(ok.statusCode).toBe(200);
    const r = JSON.parse(ok.body).roll;
    expect(r.character_name).toBe('Igor');
    expect(r.results.hunger).toEqual([]);
    expect(r.results.normal).toHaveLength(4);
    expect(r.results.retainer_id).toBe(ghoulId);
    expect((await roll(bo, ghoulId)).statusCode).toBe(403);
    expect((await roll(ana, strayId)).statusCode).toBe(403);
    const power = await roll(ana, ghoulId, { traits: undefined, powerName: 'Lethal Body' });
    expect(power.statusCode).toBe(400); // Lethal Body has no dice pool
  });

  it('moves Health only through the Storyteller and the overreach cost, never through a sheet save', async () => {
    const t = await req(st, 'PATCH', `/api/ghouls/${ghoulId}/trackers`, { damage: { amount: 3, type: 'superficial' }, wpSupDelta: 1 });
    expect(JSON.parse(t.body).trackers).toMatchObject({ health: { superficial: 3, aggravated: 0 }, willpower: { superficial: 1 } });

    const over = await req(ana, 'POST', `/api/live-session/${code}/ghouls/${ghoulId}/overreach`, { power: 'Prowess' });
    expect(JSON.parse(over.body).trackers.health).toEqual({ superficial: 3, aggravated: 1 });

    // A sheet save (here the Storyteller's editor) keeps the stored damage.
    await req(st, 'PUT', `/api/retainers/${ghoulId}`, { name: 'Igor', tier: 1, xp: 0, sheet: { ...GHOUL, health: { superficial: 0, aggravated: 0 } } });
    const [[row]] = await pool.query('SELECT sheet FROM retainers WHERE id=?', [ghoulId]);
    expect(parseSheet(row.sheet).health).toEqual({ superficial: 3, aggravated: 1 });
    expect((await req(bo, 'POST', `/api/live-session/${code}/ghouls/${ghoulId}/overreach`, {})).statusCode).toBe(403);
  });

  it('charges a Willpower reroll to the ghoul, not the vampire', async () => {
    const r = JSON.parse((await req(ana, 'POST', '/api/dice/roll', { mode: 'ghoul', sessionId: code, retainerId: ghoulId, traits: ['Wits', 'Drive'] })).body).roll;
    const re = await req(ana, 'POST', `/api/dice/rolls/${r.id}/reroll`, { indices: [0] });
    expect(re.statusCode).toBe(200);
    const [[g]] = await pool.query('SELECT sheet FROM retainers WHERE id=?', [ghoulId]);
    expect(parseSheet(g.sheet).willpower.superficial).toBe(2);
    const [[c]] = await pool.query('SELECT sheet FROM characters WHERE id=?', [ana.id]);
    expect(parseSheet(c.sheet).willpower).toBeUndefined();
  });
});

describe('choosing the Discipline of a ghoul that has none', () => {
  it("accepts only the owner's highest-rated Discipline with a level 1 power they own", async () => {
    const { disciplines, powers, ...bare } = GHOUL;
    const [g] = await pool.query('INSERT INTO retainers (character_id, name, tier, sheet) VALUES (?,?,?,?)', [ana.id, 'Reset', 1, JSON.stringify(bare)]);
    const pick = (disc, power) => req(ana, 'PUT', `/api/retainers/${g.insertId}/upgrade`,
      { name: 'Reset', tier: 1, sheet: { ...bare, disciplines: { [disc]: 1 }, powers: [{ discipline: disc, name: power }] } });
    expect((await pick('Potence', 'Lethal Body')).statusCode).toBe(400); // Ana doesn't own it yet
    await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify({ disciplines: { Potence: 1 }, disciplinePowers: { Potence: [{ id: 'lethal_body', name: 'Lethal Body', level: 1 }] } }), ana.id]);
    expect((await pick('Celerity', "Cat's Grace")).statusCode).toBe(400); // not her Discipline
    expect((await pick('Potence', 'Lethal Body')).statusCode).toBe(200);
  });
});
