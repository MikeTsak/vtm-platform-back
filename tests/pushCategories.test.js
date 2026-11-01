// tests/pushCategories.test.js — notification categories: a category the player
// never set follows its parent (so splitting chat/system changed nobody's
// choices), and the settings endpoint stores only known categories as booleans.
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');
const { effectiveSettings } = require('../services/push');

describe('effectiveSettings', () => {
  it('lets unset categories follow their parent', () => {
    const s = effectiveSettings({ chat: true, system: false });
    expect(s).toMatchObject({ chat: true, mail: true, notes: true, system: false, downtimes: false, court: false, character: false });
  });

  it('uses a category\'s own value once set', () => {
    expect(effectiveSettings({ chat: true, mail: false }).mail).toBe(false);
    expect(effectiveSettings({ system: false, court: true }).court).toBe(true);
  });

  it('treats missing or unparseable settings as all off', () => {
    expect(Object.values(effectiveSettings(null)).some(Boolean)).toBe(false);
    expect(Object.values(effectiveSettings('{nope')).some(Boolean)).toBe(false);
  });
});

describe('/api/push/settings', () => {
  let pool, app, player;
  beforeAll(async () => {
    pool = await setupTestDatabase();
    await truncateAll();
    app = buildTestApp(pool);
    await app.ready();
    player = await registerUser(app);
  });
  afterAll(async () => {
    await app.close();
    await teardownTestDatabase();
  });

  const put = (settings) => app.inject({ method: 'PUT', url: '/api/push/settings', headers: { cookie: player.cookie }, payload: { settings } });

  it('stores only known categories with boolean values', async () => {
    const res = await put({ court: true, chat: 'yes', bogus: true, 0: '{' });
    expect(res.statusCode).toBe(200);
    const [[row]] = await pool.query('SELECT push_settings FROM users WHERE id = ?', [player.user.id]);
    const stored = typeof row.push_settings === 'string' ? JSON.parse(row.push_settings) : row.push_settings;
    expect(stored).toEqual({ court: true });
  });

  it('rejects a request with nothing usable', async () => {
    expect((await put({ bogus: true })).statusCode).toBe(400);
  });

  it('returns every category, effective', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/push/settings', headers: { cookie: player.cookie } });
    expect(JSON.parse(res.body)).toEqual({ chat: false, mail: false, notes: false, downtimes: false, court: true, character: false, system: false });
  });
});
