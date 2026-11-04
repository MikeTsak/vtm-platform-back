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
let lastUploaded = null; // the bytes the host last received
const fakeHost = (failFor = new Set()) => {
  imageClient.uploadImage = async (buffer, filename) => {
    if (failFor.has(filename)) return { success: false, error: 'host said no' };
    uploads.push(filename);
    lastUploaded = buffer;
    return { success: true, url: `https://img.test/uploads/${filename}` };
  };
};
const sharp = require('sharp');
// POST /api/chat/upload as the owner, one file as multipart.
const uploadFile = (file, filename, type) => {
  const boundary = '----erebus-test';
  const payload = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: ${type}\r\n\r\n`),
    file, Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
  return app.inject({ method: 'POST', url: '/api/chat/upload', payload,
    headers: { cookie: owner.cookie, 'content-type': `multipart/form-data; boundary=${boundary}` } });
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

// Production's chat_media predates the baseline: `data longblob NOT NULL`. A
// chat image on the image host stores no bytes, so every upload answered 500
// and the offload job re-uploaded the same images each run (2026-11-04).
describe("production's older chat_media (data NOT NULL), then migration 0081", () => {
  const migration = require('../migrations/list/0081_chat_media_data_nullable');
  const realDelete = imageClient.deleteImage;
  const deleted = [];
  const upload = async () => uploadFile(
    await sharp({ create: { width: 4, height: 4, channels: 3, background: '#a00' } }).png().toBuffer(), 'photo.png', 'image/png');

  beforeAll(async () => {
    await pool.query('DELETE FROM chat_media');
    await pool.query('ALTER TABLE `chat_media` MODIFY `data` LONGBLOB NOT NULL');
    imageClient.deleteImage = async (filename) => { deleted.push(filename); return { success: true }; };
    fakeHost();
  });
  afterAll(async () => {
    await migration.up(pool); // leave the shared test database as the baseline has it
    imageClient.deleteImage = realDelete;
  });

  it('reproduces the 500, and the offload takes back what it could not record', async () => {
    expect((await upload()).statusCode).toBe(500);
    const id = await media('image/webp', Buffer.from('bytes'));
    expect(await offloadChatImages()).toMatchObject({ moved: 0, failed: 1 });
    expect(deleted).toEqual([`chat_${id}.webp`]); // no copy left behind to pile up
    expect((await row(id)).data.toString()).toBe('bytes');
  });

  it('after the migration: uploads go to the image host and the offload catches up', async () => {
    await migration.up(pool);
    const res = await upload();
    expect(res.statusCode).toBe(200);
    const [[saved]] = await pool.query('SELECT data, data_url FROM chat_media WHERE id=?', [JSON.parse(res.body).id]);
    expect(saved).toEqual({ data: null, data_url: expect.stringMatching(/^https:\/\/img\.test\/uploads\/photo\.webp$/) });
    expect(await offloadChatImages()).toMatchObject({ moved: 1, failed: 0, left: 0 });
    await migration.up(pool); // already nullable: harmless
  });
});

// GIFs used to arrive as a still picture: sharp reads only the first frame
// unless told otherwise. They become animated WebP (the image host keeps
// WebP as it is: checked against img.miketsak.gr on 2026-11-04).
describe('animated GIFs', () => {
  const twoFrameGif = async () => {
    const frame = (bg) => sharp({ create: { width: 64, height: 64, channels: 3, background: bg } }).png().toBuffer();
    return sharp([await frame('#a00000'), await frame('#0000a0')], { join: { animated: true } }).gif().toBuffer();
  };

  it('stay animated: every frame reaches the image host, as WebP', async () => {
    fakeHost();
    const res = await uploadFile(await twoFrameGif(), 'dance.gif', 'image/gif');
    expect(res.statusCode).toBe(200);
    const meta = await sharp(lastUploaded, { animated: true }).metadata();
    expect([meta.format, meta.pages]).toEqual(['webp', 2]);
  });

  it('a file that is not really an image is refused, not a server error', async () => {
    const res = await uploadFile(Buffer.from('not an image at all'), 'fake.gif', 'image/gif');
    expect(res.statusCode).toBe(400);
  });
});
