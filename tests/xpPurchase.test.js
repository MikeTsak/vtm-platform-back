// tests/xpPurchase.test.js — the server decides what an XP purchase changes
// and costs (utils/xpPurchase.js), and what a player may edit for free
// (utils/playerSheetEdit.js). Each case is a request the old routes accepted
// at face value.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser, extractSessionCookie } = require('./setup/helpers');
const { allowedDots } = require('../utils/xpPurchase');

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

async function player({ clan = 'Brujah', xp = 100, sheet = {} } = {}) {
  const p = await registerUser(app);
  const [r] = await pool.query('INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?, ?, ?, ?, ?)',
    [p.user.id, 'Test Character', clan, xp, JSON.stringify(sheet)]);
  return { ...p, id: r.insertId };
}

async function admin() {
  const a = await registerUser(app);
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [a.user.id]);
  const res = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: a.email, password: a.password } });
  return { ...a, cookie: extractSessionCookie(res) };
}

const spend = (p, payload) => app.inject({ method: 'POST', url: '/api/characters/xp/spend', headers: { cookie: p.cookie }, payload });

async function stored(id) {
  const [[row]] = await pool.query('SELECT xp, clan, name, sheet FROM characters WHERE id=?', [id]);
  return { ...row, sheet: typeof row.sheet === 'string' ? JSON.parse(row.sheet) : row.sheet };
}

describe('XP purchases are applied by the server', () => {
  it('buys exactly one dot at the stored level; the rest of a sent sheet is ignored', async () => {
    const p = await player({ sheet: { attributes: { Strength: 2, Dexterity: 1 } } });
    const res = await spend(p, {
      type: 'attribute', target: 'Strength', newLevel: 3,
      patchSheet: { attributes: { Strength: 5, Dexterity: 5 }, disciplines: { Potence: 5 } },
    });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).spent).toBe(15);
    const s = await stored(p.id);
    expect(s.xp).toBe(85);
    expect(s.sheet.attributes).toEqual({ Strength: 3, Dexterity: 1 });
    expect(s.sheet.disciplines).toBeUndefined();
  });

  it('a free flaw cannot carry a rewritten sheet', async () => {
    const p = await player({ sheet: { attributes: { Strength: 1 }, advantages: { merits: [], flaws: [] } } });
    const flawId = 'linguistics__illiterate';
    const res = await spend(p, {
      type: 'flaw', target: flawId, dots: 2,
      patchSheet: { attributes: { Strength: 5 }, advantages: { merits: [{ id: 'looks__stunning', dots: 4 }], flaws: [{ id: flawId, name: 'Illiterate', dots: 2 }] } },
    });
    expect(res.statusCode).toBe(200);
    const s = await stored(p.id);
    expect(s.sheet.attributes.Strength).toBe(1);
    expect(s.sheet.advantages.merits).toEqual([]);
    expect(s.sheet.advantages.flaws.map(f => f.id)).toEqual([flawId]);
  });

  it('a stale or inflated level is refused instead of charged', async () => {
    const p = await player({ sheet: { attributes: { Strength: 1 } } });
    expect((await spend(p, { type: 'attribute', target: 'Strength', newLevel: 5 })).statusCode).toBe(409);
    expect((await stored(p.id)).xp).toBe(100);
  });

  it('out-of-clan is decided by the server: claiming "clan" neither skips the unlock nor the price', async () => {
    const p = await player({ clan: 'Brujah', xp: 100 });
    expect((await spend(p, { type: 'discipline', disciplineKind: 'clan', target: 'Dominate', powerId: 'cloud_memory' })).statusCode).toBe(403);
    await pool.query('INSERT INTO discipline_access (character_id, discipline, max_level) VALUES (?, ?, ?)', [p.id, 'Dominate', 1]);
    const ok = await spend(p, { type: 'discipline', disciplineKind: 'clan', target: 'Dominate', powerId: 'cloud_memory' });
    expect(ok.statusCode).toBe(200);
    expect(JSON.parse(ok.body).spent).toBe(7); // out-of-clan rate, not the claimed in-clan 5
  });

  it('a discipline dot needs one valid new power', async () => {
    const p = await player({ clan: 'Brujah', sheet: { disciplines: { Potence: 1 }, disciplinePowers: { Potence: [{ id: 'lethal_body', level: 1 }] } } });
    const buy = (powerId) => spend(p, { type: 'discipline', disciplineKind: 'clan', target: 'Potence', powerId });
    expect((await buy(undefined)).statusCode).toBe(400);
    expect((await buy('lethal_body')).statusCode).toBe(400);       // already owned
    expect((await buy('earth_shock')).statusCode).toBe(400);       // a level-5 power at 2 dots
    expect((await buy('prowess')).statusCode).toBe(200);
    const s = await stored(p.id);
    expect(s.sheet.disciplines.Potence).toBe(2);
    expect(s.sheet.disciplinePowers.Potence.map(x => x.id)).toEqual(['lethal_body', 'prowess']);
    expect(s.xp).toBe(90); // in-clan, 2 x 5
  });

  it('rituals are priced and gated by their real level', async () => {
    const p = await player({ clan: 'Tremere', sheet: { disciplines: { 'Blood Sorcery': 1 } } });
    const ok = await spend(p, { type: 'ritual', target: 'astromancy', ritualLevel: 5 });
    expect(ok.statusCode).toBe(200);
    expect(JSON.parse(ok.body).spent).toBe(3); // level 1, whatever the client claimed
    expect((await spend(p, { type: 'ritual', target: 'astromancy' })).statusCode).toBe(400); // already known
  });

  it('merits: only the bought merit changes, priced by the dots actually added', async () => {
    const p = await player({ sheet: { advantages: { merits: [{ id: 'looks__beautiful', name: 'Beautiful', dots: 2 }], flaws: [] } } });
    const res = await spend(p, {
      type: 'advantage', target: 'linguistics__linguistics', dots: 1,
      patchSheet: { advantages: { merits: [{ id: 'looks__beautiful', name: 'Beautiful', dots: 4 }, { id: 'linguistics__linguistics', name: 'Linguistics', dots: 1, notes: 'French' }] } },
    });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).spent).toBe(3);
    const s = await stored(p.id);
    expect(s.sheet.advantages.merits).toEqual([
      { id: 'looks__beautiful', name: 'Beautiful', dots: 2 },
      { id: 'linguistics__linguistics', name: 'Linguistics', dots: 1, notes: 'French' },
    ]);
    // A rating the merit doesn't come in is refused.
    expect((await spend(p, {
      type: 'advantage', target: 'looks__beautiful',
      patchSheet: { advantages: { merits: [{ id: 'looks__beautiful', dots: 3 }] } },
    })).statusCode).toBe(400);
  });

  it('two purchases racing for the last XP: exactly one is charged', async () => {
    const p = await player({ xp: 10, sheet: { attributes: { Strength: 1, Dexterity: 1 } } });
    const [a, b] = await Promise.all([
      spend(p, { type: 'attribute', target: 'Strength' }),
      spend(p, { type: 'attribute', target: 'Dexterity' }),
    ]);
    expect([a.statusCode, b.statusCode].sort()).toEqual([200, 400]);
    expect((await stored(p.id)).xp).toBe(0);
  });

  it('a Storyteller buys on a player\'s behalf without the unlock gate', async () => {
    const st = await admin();
    const p = await player({ clan: 'Brujah', xp: 20 });
    const res = await app.inject({
      method: 'POST', url: `/api/admin/characters/${p.id}/xp/spend`, headers: { cookie: st.cookie },
      payload: { type: 'discipline', target: 'Dominate', powerId: 'cloud_memory' },
    });
    expect(res.statusCode).toBe(200);
    expect((await stored(p.id)).xp).toBe(13);
  });
});

describe('a player saving their own sheet', () => {
  it('keeps narrative edits, drops dots, trackers, clan and name', async () => {
    const p = await player({ clan: 'Brujah', sheet: { attributes: { Strength: 1 }, hunger: 1, advantages: { merits: [{ id: 'looks__beautiful', dots: 2 }] } } });
    const res = await app.inject({
      method: 'PUT', url: '/api/characters/me', headers: { cookie: p.cookie },
      payload: {
        name: 'Renamed', clan: 'Ventrue',
        sheet: {
          ambition: 'Rule Athens', hunger: 3, attributes: { Strength: 5 },
          advantages: { merits: [{ id: 'looks__beautiful', dots: 2, notes: 'Striking eyes' }] },
        },
      },
    });
    expect(res.statusCode).toBe(200);
    const s = await stored(p.id);
    expect(s.clan).toBe('Brujah');
    expect(s.name).toBe('Test Character');
    expect(s.sheet.ambition).toBe('Rule Athens');
    expect(s.sheet.hunger).toBe(1); // Hunger only moves through server rolls or a Storyteller
    expect(s.sheet.attributes.Strength).toBe(1);
    expect(s.sheet.advantages.merits).toEqual([{ id: 'looks__beautiful', dots: 2, notes: 'Striking eyes' }]);
  });

  it('cannot rebuild without a Storyteller-granted re-roll, and the grant is single-use', async () => {
    const p = await player();
    const rebuild = () => app.inject({
      method: 'POST', url: '/api/characters/rebuild', headers: { cookie: p.cookie },
      payload: { name: 'New', clan: 'Brujah', sheet: { attributes: { Strength: 3 }, allow_reset: true } },
    });
    expect((await rebuild()).statusCode).toBe(403);
    await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify({ allow_reset: true }), p.id]);
    expect((await rebuild()).statusCode).toBe(200);
    expect((await stored(p.id)).sheet.allow_reset).toBeUndefined();
    expect((await rebuild()).statusCode).toBe(403);
  });
});

describe('live-session trackers', () => {
  const post = (p, url, payload = {}) => app.inject({ method: 'POST', url: `/api/characters/${p.id}/${url}`, headers: { cookie: p.cookie }, payload });

  it('a player cannot write Hunger, Health or Willpower by saving the sheet', async () => {
    const p = await player({ sheet: { hunger: 4, health: { superficial: 3, aggravated: 1 }, willpower: { superficial: 2, aggravated: 0 } } });
    await app.inject({
      method: 'PUT', url: '/api/characters/me', headers: { cookie: p.cookie },
      payload: { sheet: { hunger: 0, health: { superficial: 0, aggravated: 0 }, willpower: { superficial: 0, aggravated: 0 }, compulsion: 'Paranoia' } },
    });
    const s = (await stored(p.id)).sheet;
    expect(s.hunger).toBe(4);
    expect(s.health).toEqual({ superficial: 3, aggravated: 1 });
    expect(s.willpower).toEqual({ superficial: 2, aggravated: 0 });
    expect(s.compulsion).toBe('Paranoia');
  });

  it('the Rouse reroll die is decided by the server from an owned power', async () => {
    const p = await player({ sheet: { blood_potency: 2, hunger: 1, disciplinePowers: { Potence: [{ id: 'lethal_body', level: 1 }] } } });
    const plain = JSON.parse((await post(p, 'rouse', { advantage: true })).body);
    expect(plain.advantage).toBe(false);                    // the old client flag is ignored
    expect(plain.die2).toBeNull();
    const notOwned = JSON.parse((await post(p, 'rouse', { discipline: 'Potence', powerId: 'prowess' })).body);
    expect(notOwned.advantage).toBe(false);
    const owned = JSON.parse((await post(p, 'rouse', { discipline: 'Potence', powerId: 'lethal_body' })).body);
    expect(owned.advantage).toBe(true);                      // BP 2 rerolls level-1 powers
    expect(owned.die2).not.toBeNull();
  });

  it('mending heals by the Blood Potency amount, after a server Rouse Check', async () => {
    const p = await player({ sheet: { blood_potency: 3, hunger: 0, health: { superficial: 5, aggravated: 2 } } });
    const sup = JSON.parse((await post(p, 'mend', { type: 'superficial' })).body);
    expect(sup.healed).toBe(2);                              // BP 3 mends 2
    expect(sup.rolls).toHaveLength(1);
    const agg = JSON.parse((await post(p, 'mend', { type: 'aggravated' })).body);
    expect(agg.healed).toBe(1);
    expect(agg.rolls).toHaveLength(3);
    const s = (await stored(p.id)).sheet;
    expect(s.health).toEqual({ superficial: 3, aggravated: 1 });
    expect(s.hunger).toBe(sup.rolls.concat(agg.rolls).filter(r => !r.success).length);
  });

  it('nobody else can roll on your character, and the old heal-by-negative-damage route is gone', async () => {
    const p = await player();
    const other = await player();
    expect((await post({ ...other, id: p.id }, 'rouse')).statusCode).toBe(403);
    expect((await post(p, 'apply-damage', { amount: -10, type: 'superficial' })).statusCode).toBe(404);
  });
});

describe('duplicate merits', () => {
  it('a second Contacts is allowed, a second Beautiful is not', async () => {
    const p = await player({ sheet: { advantages: { merits: [
      { id: 'backgrounds_contacts__contacts', name: 'Contacts', dots: 1 },
      { id: 'looks__beautiful', name: 'Beautiful', dots: 2 },
    ] } } });
    const add = (id, name, dots) => spend(p, {
      type: 'advantage', target: id, dots,
      patchSheet: { advantages: { merits: [...(p.merits ||= [
        { id: 'backgrounds_contacts__contacts', name: 'Contacts', dots: 1 },
        { id: 'looks__beautiful', name: 'Beautiful', dots: 2 },
      ]), { id, name, dots }] } },
    });
    expect((await add('looks__beautiful', 'Beautiful', 2)).statusCode).toBe(400);
    expect((await add('backgrounds_contacts__contacts', 'Contacts', 1)).statusCode).toBe(200);
    const merits = (await stored(p.id)).sheet.advantages.merits;
    expect(merits.filter(m => m.id === 'backgrounds_contacts__contacts')).toHaveLength(2);
    expect(merits.filter(m => m.id === 'looks__beautiful')).toHaveLength(1);
  });
});

describe('retainers are paid for by the route that creates them', () => {
  const weakMortal = {
    attributes: { Strength: 2, Wits: 2 },
    skills: { Brawl: 2, Drive: 2, Stealth: 2, Athletics: 1, Firearms: 1, Larceny: 1, Melee: 1, Survival: 1 },
  };

  it('charges 3 XP per tier, refuses without the XP, and ignores a client-set retainer XP', async () => {
    const p = await player({ xp: 4 });
    const create = (tier) => app.inject({
      method: 'POST', url: `/api/characters/${p.id}/retainers`, headers: { cookie: p.cookie },
      payload: { name: 'Hired Help', tier, sheet: weakMortal, xp: 500 },
    });
    const first = await create(1);
    expect(first.statusCode, first.body).toBe(200);
    expect(JSON.parse(first.body).xp).toBe(0);
    expect((await stored(p.id)).xp).toBe(1);

    expect((await create(1)).statusCode).toBe(400); // 3 XP needed, 1 left
    const [[{ n }]] = await pool.query('SELECT COUNT(*) AS n FROM retainers WHERE character_id=?', [p.id]);
    expect(n).toBe(1);
  });
});

describe('merit rating parser', () => {
  it('reads the catalog display strings', () => {
    expect(allowedDots('••')).toEqual([2]);
    expect(allowedDots('• - •••')).toEqual([1, 2, 3]);
    expect(allowedDots('•• or ••••')).toEqual([2, 4]);
    expect(allowedDots('• +')).toEqual([1, 2, 3, 4, 5]);
  });
});
