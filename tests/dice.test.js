// tests/dice.test.js — every roll is thrown by the server and stored in the one
// dice_rolls table (routes/dice.js, services/rolls.js). Each case is something
// the browser used to decide: the dice faces, the pool size, re-answering a
// Storyteller request, rerolling twice, clearing frenzy.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser, extractSessionCookie } = require('./setup/helpers');

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

async function player(sheet = {}, clan = 'Brujah') {
  const p = await registerUser(app);
  const [r] = await pool.query('INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?, ?, ?, 0, ?)',
    [p.user.id, `Roller ${p.user.id}`, clan, JSON.stringify(sheet)]);
  return { ...p, id: r.insertId };
}

async function storyteller() {
  const a = await registerUser(app);
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [a.user.id]);
  const res = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: a.email, password: a.password } });
  return { ...a, cookie: extractSessionCookie(res) };
}

let codeSeq = 0;
async function session(adminId, metadata = {}, status = 'active') {
  // live_sessions isn't reset between runs, so keep codes unique per run.
  const code = `T${Date.now().toString(36).slice(-6)}${++codeSeq}`.slice(0, 10);
  const [r] = await pool.query('INSERT INTO live_sessions (session_code, name, admin_id, status, metadata) VALUES (?, ?, ?, ?, ?)',
    [code, 'Test night', adminId, status, JSON.stringify(metadata)]);
  return { id: r.insertId, code };
}

const seat = (s, p) => pool.query('INSERT INTO live_session_participants (session_id, user_id, character_id) VALUES (?, ?, ?)', [s.id, p.user.id, p.id]);
const roll = (who, payload) => app.inject({ method: 'POST', url: '/api/dice/roll', headers: { cookie: who.cookie }, payload });
const body = (res) => JSON.parse(res.body);
async function sheetOf(id) {
  const [[row]] = await pool.query('SELECT sheet FROM characters WHERE id=?', [id]);
  return typeof row.sheet === 'string' ? JSON.parse(row.sheet) : row.sheet;
}

const sturdy = { attributes: { Strength: 3, Stamina: 2, Composure: 2, Resolve: 2, Wits: 2 }, skills: { Brawl: { dots: 2, specialties: [] } }, hunger: 2 };

describe('server-thrown dice', () => {
  it('a free roll ignores dice sent by the client and is stored once', async () => {
    const p = await player();
    const res = await roll(p, { mode: 'free', pool: 6, hunger: 2, results: { normal: [10, 10, 10, 10], hunger: [] } });
    expect(res.statusCode).toBe(200);
    const r = body(res).roll;
    expect(r.results.normal).toHaveLength(4);
    expect(r.results.hunger).toHaveLength(2);
    [...r.results.normal, ...r.results.hunger].forEach(d => expect(d).toBeGreaterThanOrEqual(1));
    const [[row]] = await pool.query('SELECT roll_type, character_id FROM dice_rolls WHERE id=?', [r.id]);
    expect(row).toEqual({ roll_type: 'free', character_id: p.id });
  });

  it('the old "here are my dice" endpoint is gone', async () => {
    const p = await player();
    const res = await app.inject({ method: 'POST', url: '/api/dice/rolls', headers: { cookie: p.cookie }, payload: { results: { normal: [10], hunger: [] } } });
    expect(res.statusCode).toBe(404);
  });

  it('a trait roll is built from the stored sheet, not the request', async () => {
    const p = await player(sturdy);
    const r = body(await roll(p, { mode: 'traits', traits: ['Strength', 'Brawl'], pool: 30, specialty: true, situational: { mod: 50, reason: 'pleading' } })).roll;
    // 3 + 2, no specialty on Brawl, situational capped at +10 → 15; Hunger 2 from the sheet
    expect(r.pool).toBe(15);
    expect(r.results.hunger).toHaveLength(2);
    expect(r.note).toMatch(/Strength \+ Brawl/);
  });

  it('impairment applies, and ignoring it charges a Willpower with the roll', async () => {
    const p = await player({ ...sturdy, health: { superficial: 5, aggravated: 0 } }); // Stamina 2 + 3 = 5: full
    expect(body(await roll(p, { mode: 'traits', traits: ['Strength', 'Brawl'] })).roll.pool).toBe(3);
    expect(body(await roll(p, { mode: 'traits', traits: ['Strength', 'Brawl'], ignoreImpairment: true })).roll.pool).toBe(5);
    expect((await sheetOf(p.id)).willpower.superficial).toBe(1);
  });

  it('a Storyteller request is rolled exactly as asked, and only once', async () => {
    const st = await storyteller();
    const p = await player(sturdy);
    const s = await session(st.user.id, { rollRequests: [{ id: 'rr-123456789', targetId: String(p.id), trait1: 'Wits', trait2: 'Brawl', difficulty: 3, specialty: 'Ambush' }] });
    await seat(s, p);
    const first = await roll(p, { mode: 'request', requestId: 'rr-123456789', sessionId: s.code, traits: ['Strength', 'Brawl'] });
    expect(first.statusCode).toBe(200);
    const r = body(first).roll;
    expect(r.pool).toBe(5);                 // Wits 2 + Brawl 2 + the Storyteller's specialty
    expect(r.difficulty).toBe(3);
    expect(r.session_id).toBe(s.id);
    expect((await roll(p, { mode: 'request', requestId: 'rr-123456789', sessionId: s.code })).statusCode).toBe(404);
    const other = await player(sturdy);
    await seat(s, other);
    expect((await roll(other, { mode: 'request', requestId: 'rr-123456789', sessionId: s.code })).statusCode).toBe(404);
  });

  it('a discipline roll uses the owned power\'s own pool', async () => {
    const p = await player({ ...sturdy, attributes: { ...sturdy.attributes, Charisma: 3 }, disciplines: { Dominate: 2 }, disciplinePowers: { Dominate: [{ id: 'compel', level: 1 }] } }, 'Ventrue');
    const r = body(await roll(p, { mode: 'power', discipline: 'Dominate', powerId: 'compel' })).roll;
    expect(r.pool).toBe(5);                 // Charisma 3 + Dominate 2
    expect((await roll(p, { mode: 'power', discipline: 'Dominate', powerId: 'mesmerize' })).statusCode).toBe(400);
  });

  it('frenzy can only be cleared by winning the server roll', async () => {
    const calm = await player(sturdy);
    expect((await roll(calm, { mode: 'frenzy' })).statusCode).toBe(400);
    const p = await player({ ...sturdy, attributes: { Composure: 5, Resolve: 5 }, humanity: 9, frenzyState: 'fury' });
    const r = body(await roll(p, { mode: 'frenzy' })).roll;
    expect(r.pool).toBe(11);                // Willpower 10 + Humanity 9 / 3, minus the Brujah Bane (2) against fury
    expect((await sheetOf(p.id)).frenzyState ?? null).toBe(r.successes > 0 ? null : 'fury');
  });

  it('a Willpower reroll spends one Willpower, rerolls up to three dice, once', async () => {
    const p = await player(sturdy);
    const r = body(await roll(p, { mode: 'traits', traits: ['Strength', 'Brawl'] })).roll;
    const reroll = (who, indices) => app.inject({ method: 'POST', url: `/api/dice/rolls/${r.id}/reroll`, headers: { cookie: who.cookie }, payload: { indices } });
    expect((await reroll(p, [0, 1, 2, 0])).statusCode).toBe(200);
    expect((await sheetOf(p.id)).willpower.superficial).toBe(1);
    expect((await reroll(p, [0])).statusCode).toBe(400);  // already rerolled
    const other = await player(sturdy);
    const theirs = body(await roll(other, { mode: 'traits', traits: ['Strength', 'Brawl'] })).roll;
    expect((await app.inject({ method: 'POST', url: `/api/dice/rolls/${theirs.id}/reroll`, headers: { cookie: p.cookie }, payload: { indices: [0] } })).statusCode).toBe(404);
  });

  it('a Hunger 10 can be rerolled only when it makes the roll a Messy Critical', async () => {
    const p = await player(sturdy);
    // Fixed dice: a regular 10 + a Hunger 10 (Messy Critical), and a plain roll with a Hunger 10 but no pair.
    const stored = async (normal, hunger, messy) => (await pool.query(
      `INSERT INTO dice_rolls (user_id, character_id, roll_type, pool, hunger, sides, results_json, successes, crit_pairs, messy_crit, bestial_failure)
       VALUES (?, ?, 'pool_roll', ?, ?, 10, ?, 0, ?, ?, 0)`,
      [p.user.id, p.id, normal.length + hunger.length, hunger.length, JSON.stringify({ normal, hunger }), messy ? 1 : 0, messy ? 1 : 0]))[0].insertId;
    const reroll = (id, payload) => app.inject({ method: 'POST', url: `/api/dice/rolls/${id}/reroll`, headers: { cookie: p.cookie }, payload });

    const plain = await stored([3, 4], [10, 2], false);
    expect((await reroll(plain, { hungerIndices: [0] })).statusCode).toBe(400);   // no Messy Critical
    const messy = await stored([10, 4], [10, 2], true);
    expect((await reroll(messy, { hungerIndices: [1] })).statusCode).toBe(400);   // the Hunger 2 stays
    expect((await reroll(messy, { indices: [0, 1, 0], hungerIndices: [0, 0] })).statusCode).toBe(200);
    const [[row]] = await pool.query("SELECT results_json FROM dice_rolls WHERE character_id=? AND roll_type='willpower_reroll' ORDER BY id DESC LIMIT 1", [p.id]);
    const res = typeof row.results_json === 'string' ? JSON.parse(row.results_json) : row.results_json;
    expect(res.hunger[1]).toBe(2);                                                 // untouched
  });

  it('only the Storyteller posts free rolls to a session; ended sessions take no rolls', async () => {
    const st = await storyteller();
    const p = await player(sturdy);
    const s = await session(st.user.id);
    expect((await roll(p, { mode: 'free', pool: 3, sessionId: s.code })).statusCode).toBe(403);
    const npc = body(await roll(st, { mode: 'free', pool: 4, hunger: 1, sessionId: s.code, rollType: 'admin_roll', characterName: 'Sheriff' })).roll;
    expect([npc.session_id, npc.character_name, npc.pool]).toEqual([s.id, 'Sheriff', 4]);
    const ended = await session(st.user.id, {}, 'ended');
    expect((await roll(p, { mode: 'traits', traits: ['Strength', 'Brawl'], sessionId: ended.code })).statusCode).toBe(400);
  });

  it('a player who has not joined a session cannot roll into it', async () => {
    const st = await storyteller();
    const p = await player(sturdy);
    const s = await session(st.user.id);
    expect((await roll(p, { mode: 'traits', traits: ['Strength', 'Brawl'], sessionId: s.code })).statusCode).toBe(403);
    // Rouse Checks don't leak into it either: they are logged outside the session.
    await app.inject({ method: 'POST', url: `/api/characters/${p.id}/rouse`, headers: { cookie: p.cookie }, payload: { sessionId: s.code, source: 'blush_of_life' } });
    const [[row]] = await pool.query('SELECT session_id FROM dice_rolls WHERE character_id=? ORDER BY id DESC LIMIT 1', [p.id]);
    expect(row.session_id).toBeNull();
    await seat(s, p);
    expect((await roll(p, { mode: 'traits', traits: ['Strength', 'Brawl'], sessionId: s.code })).statusCode).toBe(200);
  });

  it('Rouse Checks made in a session land in the same table', async () => {
    const st = await storyteller();
    const p = await player(sturdy);
    const s = await session(st.user.id);
    await seat(s, p);
    const res = await app.inject({ method: 'POST', url: `/api/characters/${p.id}/rouse`, headers: { cookie: p.cookie }, payload: { sessionId: s.code, source: 'blush_of_life' } });
    expect(res.statusCode).toBe(200);
    const [[row]] = await pool.query('SELECT roll_type, session_id FROM dice_rolls WHERE character_id=? ORDER BY id DESC LIMIT 1', [p.id]);
    expect(row).toEqual({ roll_type: 'blush_of_life', session_id: s.id });
  });
});

describe('frenzy pool', () => {
  it('is unspent Willpower plus a third of Humanity, rounded down', () => {
    const { frenzyPool } = require('../services/rolls');
    const sheet = { attributes: { Composure: 3, Resolve: 3 }, humanity: 8, willpower: { superficial: 2, aggravated: 0 } };
    expect(frenzyPool(sheet, 'Ventrue').pool).toBe(4 + 2);   // 6 Willpower - 2 spent = 4, + floor(8/3) = 2
    expect(frenzyPool({ ...sheet, willpower: { superficial: 0, aggravated: 0 } }, 'Ventrue').pool).toBe(6 + 2);
  });
});

describe('migration 0043: live_session_rolls merged into dice_rolls', () => {
  it('adds the missing columns, moves the old session rolls across and drops their duplicate copies', async () => {
    const migration = require('../migrations/list/0043_unify_dice_rolls');
    const st = await storyteller();
    const p = await player(sturdy);
    const s = await session(st.user.id);
    await pool.query('DELETE FROM dice_rolls');
    await pool.query('DELETE FROM live_session_rolls'); // not reset between test runs
    // Production's dice_rolls predates is_hidden and the new columns: start from that layout.
    await pool.query('ALTER TABLE dice_rolls DROP KEY idx_dice_rolls_session, DROP COLUMN session_id, DROP COLUMN roll_type, DROP COLUMN character_name, DROP COLUMN is_hidden, DROP COLUMN rerolled');
    await pool.query(
      'INSERT INTO live_session_rolls (session_id, character_id, character_name, roll_type, pool, hunger, results, successes, note, is_hidden) VALUES (?,?,?,?,?,?,?,?,?,?), (?,?,?,?,?,?,?,?,?,?)',
      [s.id, p.id, 'Old roll', 'pool_roll', 3, 1, JSON.stringify({ normal: [10, 10], hunger: [10] }), 4, 'old', 0,
        s.id, null, 'NPC', 'admin_roll', 2, 0, JSON.stringify({ normal: [1, 2], hunger: [] }), 0, 'npc', 1]);
    // The old code's mirrored copy, and an unrelated standalone roll that must stay.
    await pool.query("INSERT INTO dice_rolls (user_id, character_id, pool, hunger, results_json, successes, crit_pairs, note) VALUES (?, ?, 3, 1, '{}', 4, 1, '[Session: X] old'), (?, ?, 2, 0, '{}', 0, 0, 'standalone')",
      [p.user.id, p.id, p.user.id, p.id]);

    await migration.up(pool);

    const [rows] = await pool.query('SELECT user_id, session_id, roll_type, character_name, messy_crit, is_hidden, note FROM dice_rolls ORDER BY id');
    expect(rows).toEqual([
      { user_id: p.user.id, session_id: null, roll_type: null, character_name: null, messy_crit: 0, is_hidden: 0, note: 'standalone' },
      { user_id: p.user.id, session_id: s.id, roll_type: 'pool_roll', character_name: 'Old roll', messy_crit: 1, is_hidden: 0, note: 'old' },
      { user_id: st.user.id, session_id: s.id, roll_type: 'admin_roll', character_name: 'NPC', messy_crit: 0, is_hidden: 1, note: 'npc' },
    ]);
    await migration.up(pool); // running again changes nothing
    const [[{ n }]] = await pool.query('SELECT COUNT(*) AS n FROM dice_rolls');
    expect(n).toBe(3);
  });
});
