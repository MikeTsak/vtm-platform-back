// tests/spamPurchase.test.js — a player hammering a buy button. 30 identical
// requests fire at once WITHOUT an idempotency key (the worst case: an old tab,
// a script, a flaky network retrying), and exactly one may take effect. The
// guarantee comes from the server itself: each purchase locks the character
// row and is checked against the stored sheet, so the 2nd..30th copy finds the
// thing already bought.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

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

const N = 30;

async function player(sheet, { clan = 'Brujah', xp = 500 } = {}) {
  const p = await registerUser(app);
  const [r] = await pool.query('INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?, ?, ?, ?, ?)',
    [p.user.id, 'Spammer', clan, xp, JSON.stringify(sheet)]);
  return { ...p, id: r.insertId };
}

async function hammer(p, method, url, payload) {
  const res = await Promise.all(Array.from({ length: N }, () =>
    app.inject({ method, url, headers: { cookie: p.cookie }, payload })));
  return res.map(r => r.statusCode);
}

async function state(id) {
  const [[row]] = await pool.query('SELECT xp, sheet FROM characters WHERE id=?', [id]);
  const [[{ logs }]] = await pool.query('SELECT COUNT(*) AS logs FROM xp_log WHERE character_id=?', [id]);
  return { xp: row.xp, sheet: typeof row.sheet === 'string' ? JSON.parse(row.sheet) : row.sheet, logs };
}

const ok = (codes) => codes.filter(c => c === 200).length;
const spend = (p, payload) => hammer(p, 'POST', '/api/characters/xp/spend', payload);

describe(`${N} identical purchases at once are charged once`, () => {
  it('attribute dot', async () => {
    const p = await player({ attributes: { Strength: 1 } });
    expect(ok(await spend(p, { type: 'attribute', target: 'Strength', newLevel: 2 }))).toBe(1);
    const s = await state(p.id);
    expect([s.xp, s.sheet.attributes.Strength, s.logs]).toEqual([490, 2, 1]);
  });

  it('skill dot', async () => {
    const p = await player({ skills: {} });
    expect(ok(await spend(p, { type: 'skill', target: 'Brawl', newLevel: 1 }))).toBe(1);
    const s = await state(p.id);
    expect([s.xp, s.sheet.skills.Brawl.dots, s.logs]).toEqual([497, 1, 1]);
  });

  it('specialty', async () => {
    const p = await player({ skills: { Brawl: { dots: 1, specialties: [] } } });
    expect(ok(await spend(p, { type: 'specialty', target: 'Brawl', specialty: 'Grappling' }))).toBe(1);
    const s = await state(p.id);
    expect([s.xp, s.sheet.skills.Brawl.specialties, s.logs]).toEqual([497, ['Grappling'], 1]);
  });

  it('discipline dot with its power', async () => {
    const p = await player({ disciplines: {}, disciplinePowers: {} });
    expect(ok(await spend(p, { type: 'discipline', target: 'Potence', newLevel: 1, powerId: 'lethal_body' }))).toBe(1);
    const s = await state(p.id);
    expect([s.xp, s.sheet.disciplines.Potence, s.sheet.disciplinePowers.Potence.length]).toEqual([495, 1, 1]);
  });

  it('free power pick (cannot fill more than the open dots)', async () => {
    const p = await player({ disciplines: { Potence: 2 }, disciplinePowers: { Potence: [{ id: 'lethal_body', level: 1 }] } });
    expect(ok(await spend(p, { type: 'discipline', disciplineKind: 'select', target: 'Potence', powerId: 'prowess' }))).toBe(1);
    expect((await state(p.id)).sheet.disciplinePowers.Potence.map(x => x.id)).toEqual(['lethal_body', 'prowess']);
  });

  it('ritual', async () => {
    const p = await player({ disciplines: { 'Blood Sorcery': 1 } }, { clan: 'Tremere' });
    expect(ok(await spend(p, { type: 'ritual', target: 'astromancy' }))).toBe(1);
    const s = await state(p.id);
    expect([s.xp, s.sheet.rituals.blood_sorcery.length]).toEqual([497, 1]);
  });

  it('blood potency', async () => {
    const p = await player({ blood_potency: 1 });
    expect(ok(await spend(p, { type: 'blood_potency', target: 'Blood Potency', newLevel: 2 }))).toBe(1);
    expect((await state(p.id)).xp).toBe(480);
  });

  it('merit upgrade', async () => {
    const merits = [{ id: 'looks__beautiful', name: 'Beautiful', dots: 2 }];
    const p = await player({ advantages: { merits } });
    // Contacts 0 -> 2 as a brand-new entry
    const patch = { advantages: { merits: [...merits, { id: 'backgrounds_contacts__contacts', name: 'Contacts', dots: 2 }] } };
    expect(ok(await spend(p, { type: 'advantage', target: 'backgrounds_contacts__contacts', dots: 2, patchSheet: patch }))).toBe(1);
    const s = await state(p.id);
    expect([s.xp, s.sheet.advantages.merits.length]).toEqual([494, 2]);
  });

  it('a second Contacts instance (repeatable merit) is still added only once', async () => {
    const merits = [{ id: 'backgrounds_contacts__contacts', name: 'Contacts', dots: 1, instance: 1 }];
    const p = await player({ advantages: { merits } });
    const patch = { advantages: { merits: [...merits, { id: 'backgrounds_contacts__contacts', name: 'Contacts', dots: 1, instance: 2 }] } };
    expect(ok(await spend(p, { type: 'advantage', target: 'backgrounds_contacts__contacts', dots: 1, patchSheet: patch }))).toBe(1);
    const s = await state(p.id);
    expect([s.xp, s.sheet.advantages.merits.length]).toEqual([497, 2]);
  });

  it('flaw', async () => {
    const p = await player({ advantages: { merits: [], flaws: [] } });
    const patch = { advantages: { flaws: [{ id: 'linguistics__illiterate', name: 'Illiterate', dots: 2 }] } };
    expect(ok(await spend(p, { type: 'flaw', target: 'linguistics__illiterate', dots: 2, patchSheet: patch }))).toBe(1);
    expect((await state(p.id)).sheet.advantages.flaws).toHaveLength(1);
  });

  it('retainer recruit and upgrade', async () => {
    const p = await player({});
    const sheet = {
      attributes: { Strength: 2, Wits: 2 },
      skills: { Brawl: 2, Drive: 2, Stealth: 2, Athletics: 1, Firearms: 1, Larceny: 1, Melee: 1, Survival: 1 },
    };
    expect(ok(await hammer(p, 'POST', `/api/characters/${p.id}/retainers`, { name: 'Ghoul', tier: 1, sheet }))).toBe(1);
    const [rows] = await pool.query('SELECT id FROM retainers WHERE character_id=?', [p.id]);
    expect(rows).toHaveLength(1);
    expect((await state(p.id)).xp).toBe(497);

    // Upgrading to tier 2 charges once; the repeats are already at tier 2 (no extra tiers to pay for).
    const tier2 = {
      attributes: { Strength: 3, Wits: 3, Dexterity: 2, Stamina: 2, Resolve: 2 },
      skills: { Brawl: 3, Drive: 3, Stealth: 3, Athletics: 2, Firearms: 2, Larceny: 2, Melee: 2, Survival: 1, Awareness: 1, Insight: 1, Occult: 1, Science: 1 },
    };
    const codes = await hammer(p, 'PUT', `/api/retainers/${rows[0].id}/upgrade`, { name: 'Ghoul', tier: 2, sheet: tier2 });
    expect(codes.every(c => c === 200)).toBe(true);
    expect((await state(p.id)).xp).toBe(494);                 // 3 XP, once
  });
});

describe('with the client\'s idempotency key the repeats are replays, not refusals', () => {
  it('returns the first response to every duplicate', async () => {
    const p = await player({ attributes: { Strength: 1 } });
    const res = await Promise.all(Array.from({ length: N }, () => app.inject({
      method: 'POST', url: '/api/characters/xp/spend',
      headers: { cookie: p.cookie, 'idempotency-key': `spam-${p.id}` },
      payload: { type: 'attribute', target: 'Strength', newLevel: 2 },
    })));
    expect(res.every(r => r.statusCode === 200)).toBe(true);
    expect(res.filter(r => r.headers['x-idempotent-replay'] === 'true')).toHaveLength(N - 1);
    expect((await state(p.id)).xp).toBe(490);
  });
});
