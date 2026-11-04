// tests/chatMedia.test.js — chat images live on the image host (services/chatMedia.js):
// older ones stored in the database move there a batch at a time, voice
// messages stay, and serving one is a redirect behind the same access check.
// The image host is faked: tests/setup/env.js blocks real uploads.
const { setupTestDatabase, teardownTestDatabase, truncateAll, getTestPool } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');
const { imageClient } = require('../services/media');
const { offloadChatImages } = require('../services/chatMedia');

let pool, app, owner, stranger;
const blocked = imageClient.uploadImage; // the env.js guard
const uploads = [];
const fakeHost = (failFor = new Set()) => {
  imageClient.uploadImage = async (buffer, filename) => {
    if (failFor.has(filename)) return { success: false, error: 'host said no' };
    uploads.push(filename);
    return { success: true, url: `https://img.test/uploads/${filename}` };
  };
};
const media = async (mime, data, dataUrl = null) => (await pool.query(
  'INSERT INTO chat_media (uploader_id, filename, mime, size, data, data_url) VALUES (?, ?, ?, ?, ?, ?)',
  [owner.user.id, 'x', mime, data ? data.length : 0, data, dataUrl]))[0].insertId;
const row = async (id) => (await pool.query('SELECT data, data_url FROM chat_media WHERE id=?', [id]))[0][0];

beforeAll(async () => {
  await setupTestDatabase();
  pool = getTestPool();
  await truncateAll();
  await pool.query('DELETE FROM chat_media');
  app = buildTestApp(pool);
  await app.ready();
  owner = await registerUser(app);
  stranger = await registerUser(app);
});
afterAll(async () => {
  imageClient.uploadImage = blocked;
  await app.close();
  await teardownTestDatabase();
});

it('the test setup blocks uploads to the real image host', async () => {
  await expect(blocked(Buffer.from('x'), 'x.webp')).rejects.toThrow(/never upload/);
});

describe('moving chat images to the image host', () => {
  it('moves stored images, keeps voice messages, and skips what is already there', async () => {
    fakeHost();
    const img = await media('image/webp', Buffer.from('RIFF....WEBPfake'));
    const legacy = await media('image/png', Buffer.from('https://img.test/uploads/old.png'));
    const voice = await media('audio/webm', Buffer.from('voice'));
    const done = await media('image/webp', null, 'https://img.test/uploads/done.webp');

    expect(await offloadChatImages()).toMatchObject({ moved: 2, failed: 0, left: 0 });
    expect(await row(img)).toEqual({ data: null, data_url: `https://img.test/uploads/chat_${img}.webp` });
    expect(await row(legacy)).toEqual({ data: null, data_url: 'https://img.test/uploads/old.png' }); // no re-upload
    expect((await row(voice)).data.toString()).toBe('voice');
    expect((await row(done)).data_url).toBe('https://img.test/uploads/done.webp');
    expect(uploads).toEqual([`chat_${img}.webp`]);

    expect(await offloadChatImages()).toMatchObject({ moved: 0, left: 0 }); // nothing left: harmless
  });

  it('leaves an image whose upload failed in place, for the next run', async () => {
    const stuck = await media('image/jpeg', Buffer.from('jpeg bytes'));
    fakeHost(new Set([`chat_${stuck}.jpg`]));
    expect(await offloadChatImages()).toMatchObject({ moved: 0, failed: 1, left: 1 });
    expect((await row(stuck)).data.toString()).toBe('jpeg bytes');
    fakeHost();
    expect(await offloadChatImages()).toMatchObject({ moved: 1, left: 0 });
  });
});

describe('GET /api/chat/media/:id', () => {
  it('redirects to the image host, but only for someone allowed to see it', async () => {
    const id = await media('image/webp', null, 'https://img.test/uploads/seen.webp');
    const get = (who) => app.inject({ method: 'GET', url: `/api/chat/media/${id}`, headers: { cookie: who.cookie } });
    const res = await get(owner);
    expect([res.statusCode, res.headers.location]).toEqual([302, 'https://img.test/uploads/seen.webp']);
    expect((await get(stranger)).statusCode).toBe(404);
  });

  it('still serves a voice message from the database', async () => {
    const id = await media('audio/webm', Buffer.from('voice 2'));
    const res = await app.inject({ method: 'GET', url: `/api/chat/media/${id}`, headers: { cookie: owner.cookie } });
    expect([res.statusCode, res.body]).toEqual([200, 'voice 2']);
  });
});
